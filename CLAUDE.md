# Net-Watcher Memory Optimization Agent

## Role & Objective

You are a specialized memory optimization agent for the **net-watcher** network threat detection system. Your goal is to reduce peak RSS memory from ~4.5 GB to under 1 GB for the `net-watcher-test-only` dataset **without degrading detection accuracy or processing throughput**.

## Source Files (Python only — read nothing else unless you created it)

| File | Purpose |
|------|---------|
| `src/run.py` | Entry point: wires queues, threads, offline/online modes |
| `src/flow_reconstruction.py` | Reads packets → reconstructs flows → emits terminated flows |
| `src/flow_features.py` | Extracts numeric features from raw flow dicts |
| `src/flow_analysis.py` | TensorFlow classifier: reads feature flows → emits detection events |
| `src/enums.py` | Direction, Protocol, FlowTerminationReason enums |
| `src/logging_utils.py` | Logging helpers |
| `profile_memory.py` | RSS profiler: spawns detector subprocess, samples memory every 0.5 s |
| `memory_profile/memory_samples.csv` | Last profiling run raw data (if exists) |
| `memory_profile/memory_usage.png` | Last profiling run graph (if exists) |

## Pipeline Architecture (Critical Context)

```
RawPcapReader ──► packet_queue (30 k max)
                      │
                 packet_processor thread
                      │ [active_flows / finalizing_flows dicts]
                      ▼
              terminated_flows queue (10 k max)
                      │
          terminated_flows_processor thread
                      │  calculate_features()
                      ▼
          reconstructed_flows / network_flows queue (UNBOUNDED in detector mode)
                      │
              analyze_flows thread
                      │  TF model.predict()
                      ▼
                  event log file
```

## Diagnosed Memory Hotspots (ranked by impact)

### #1 — Scapy packet objects in `active_flows` / `finalizing_flows` (CRITICAL ~3–4 GB)

**Location:** `flow_reconstruction.py` — `initiate_new_flow()` and `process_tcp/universal()`

Each flow stores **full Scapy packet objects** in `flow["packets"]`. A Scapy `Ether(pkt_data)` object occupies ~2–5 KB even after `preprocess()` strips the Raw payload. With a large pcap creating thousands of simultaneous TCP flows each holding tens of packets, this easily reaches gigabytes.

**What `calculate_features()` actually needs per packet:**
- `packet.time` → `float`
- `packet.payload_bytes` → `int` (already set by `preprocess()`)
- `packet.direction` → `Direction` enum
- TCP only: `packet[TCP].flags` → flags byte
- TCP only: `packet[TCP].window` → `int`
- TCP SYN only: `packet[TCP].options` → list (for WScale only)
- First packet only: `src_ip`, `dst_ip`, `sport`, `dport`, `protocol`

**Fix:** Replace Scapy objects with a `__slots__` dataclass immediately after `preprocess()`. This achieves a 10–40× per-packet reduction.

```python
# flow_reconstruction.py — add near top
from dataclasses import dataclass
from typing import Optional

@dataclass(slots=True)
class PacketRecord:
    time: float
    payload_bytes: int
    direction: int          # Direction.value — avoid enum overhead
    tcp_flags: int          # 0 for UDP
    tcp_window: int         # 0 for UDP
    tcp_wscale: int         # 2**WScale option value; 1 if absent (SYN only)
    # Metadata (only needed from first packet — store once on flow dict, not per packet)

def scapy_to_record(packet) -> PacketRecord:
    tcp_flags = 0
    tcp_window = 0
    tcp_wscale = 1
    if TCP in packet:
        tcp = packet[TCP]
        tcp_flags = int(tcp.flags)
        tcp_window = tcp.window
        if tcp.flags.S and tcp.options:
            for opt in tcp.options:
                if opt[0] == 'WScale':
                    tcp_wscale = 2 ** opt[1]
                    break
    return PacketRecord(
        time=float(packet.time),
        payload_bytes=packet.payload_bytes,
        direction=packet.direction.value,
        tcp_flags=tcp_flags,
        tcp_window=tcp_window,
        tcp_wscale=tcp_wscale,
    )
```

`calculate_features()` and `calculate_tcp_window_features()` in `flow_features.py` must be updated to access `record.time`, `record.payload_bytes`, `record.tcp_flags`, etc. instead of `packet.time`, `packet[TCP].flags`, etc. The first-packet metadata (src_ip, dst_ip, sport, dport, protocol) must be stored separately on the flow dict at `initiate_new_flow()` time.

**Pros:** Highest single impact. 10–40× per-packet memory reduction. No algorithmic change.
**Cons:** Requires coordinated changes in `flow_reconstruction.py` and `flow_features.py`. Risk: any packet field accessed downstream that isn't captured will raise `AttributeError`. Mitigation: run full test suite after applying.

---

### #2 — Unbounded `network_flows` / `reconstructed_flows` queue in detector mode (~variable, can be large)

**Location:** `run.py` — `detection_offline()` and `detection_online()`

```python
network_flows = queue.Queue()   # no maxsize — unbounded!
```

If the TF classifier is slower than flow reconstruction (common with large pcap), all reconstructed flow feature dicts accumulate here indefinitely.

**Fix:** Set `maxsize=2000` (or similar). The existing `enqueue_nowait()` mechanism already handles full queues gracefully (logs + discards). For offline mode, blocking `put()` is preferable to discarding:

```python
network_flows = queue.Queue(maxsize=2000)
# In terminated_flows_processor, change enqueue_nowait → blocking put with timeout
self.reconstructed_flows.put(flow, timeout=30)
```

**Pros:** Trivial one-line change. Eliminates a whole class of memory blow-up.
**Cons:** Blocking put slows reconstruction when classifier is the bottleneck. Acceptable for offline mode; use `enqueue_nowait` for online/real-time mode to preserve low latency.

---

### #3 — TensorFlow pre-allocates all available CPU/GPU memory (~0.5–2 GB wasted)

**Location:** `run.py` — before `import tensorflow as tf`

**Fix:**
```python
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
# Add these before importing tensorflow:
os.environ['TF_FORCE_GPU_ALLOW_GROWTH'] = 'true'

import tensorflow as tf
gpus = tf.config.list_physical_devices('GPU')
for gpu in gpus:
    tf.config.experimental.set_memory_growth(gpu, True)
```

**Pros:** Immediate reduction in baseline memory; no code structure change.
**Cons:** Slight inference latency variance on GPU (not applicable for CPU-only systems).

---

### #4 — GC pressure from many short-lived Scapy objects

**Location:** `run.py` — after model and scaler are loaded in `_analyze_flows()`

Python's cyclic GC is triggered frequently by Scapy's complex object graph. Freezing stable objects (model, scaler, enums) reduces GC scanning overhead.

```python
import gc
# After model and scaler loaded:
gc.collect()
gc.freeze()   # Exempt all already-allocated objects from future GC cycles
gc.set_threshold(10000, 10, 10)  # Reduce GC frequency (default: 700, 10, 10)
```

**Pros:** Reduces CPU overhead 3–8%; slightly reduces peak memory from GC timing effects.
**Cons:** If stable objects have circular refs (unlikely for TF model), those won't be collected.

---

### #5 — `flows_batch` in `_analyze_flows()` holds full flow dicts

**Location:** `flow_analysis.py` — `_analyze_flows()`

`flows_batch` retains entire flow dicts (including `payload_bytes_seq`, `interarrival_time_s_seq` lists) while waiting to fill a batch of 64. These lists can be large.

**Fix:** After extracting `features` via `flow_to_np_and_meta()`, strip the sequence fields from the flow before appending to `flows_batch`:
```python
features, meta = flow_to_np_and_meta(flow)
# Free large sequence lists immediately
flow.pop('payload_bytes_seq', None)
flow.pop('interarrival_time_s_seq', None)
flow.pop('fwd_window_size_seq', None)
flow.pop('bwd_window_size_seq', None)
flows_batch.append(flow)
```

**Pros:** Minimal code change; no logic impact (sequences not used in classification).
**Cons:** Sequences lost before logging — only matters if you later want to log raw sequences.

---

## Profiling Workflow

### 1. Baseline measurement
```
venv/Scripts/python profile_memory.py
```
Records RSS every 0.5 s. Results in `memory_profile/memory_samples.csv` and `memory_profile/memory_usage.png`.

### 2. Hotspot identification (tracemalloc)
Use the `/mem-analyze` skill to inject tracemalloc into the subprocess and capture top allocations at peak memory.

### 3. Apply optimization
Use the `/mem-optimize` skill for guided code changes. Always apply one optimization at a time and re-run `profile_memory.py` to quantify impact.

### 4. Performance verification
After any change, verify:
- Peak RSS reduced vs. baseline
- Processing throughput unchanged: check `Execution completed in X seconds` log line
- No new `discarded` warnings in logs (would indicate backpressure degrading data quality)
- Detection accuracy unchanged: compare event log line counts before/after

## Key Constraints

1. **Do not change feature names or numeric values** — the trained TF model depends on exact feature layout from `flow_numeric_features` in `flow_features.py`.
2. **Do not change the 5-tuple flow key** `(src_ip, dst_ip, sport, dport, protocol)`.
3. **Packet discarding is allowed but only as last resort** — prefer backpressure over dropping.
4. **Only edit `.py` files** in `src/` plus `profile_memory.py`. Do not touch `venv/`, `artifacts/`, or `pcap/`.

## Optimization Priority

| # | Change | Est. RSS reduction | Code risk | Lines changed |
|---|--------|--------------------|-----------|---------------|
| 1 | Scapy → PacketRecord slots dataclass | 60–80% | Medium | ~50 |
| 2 | Bound network_flows queue | 5–20% | Low | 1 |
| 3 | TF memory growth flag | 5–15% | Low | 3 |
| 4 | GC freeze after model load | 2–5% | Low | 4 |
| 5 | Strip seq fields in analyze_flows | 2–5% | Low | 5 |

Apply in order. Re-profile after each step.

---

## Testing Infrastructure

Tests live in `tests/` and use **pytest** (dev-only, not in `requirements.txt`).

### Running tests
```bash
# All tests
venv/Scripts/python -m pytest tests/ -v

# Single scenario
venv/Scripts/python -m pytest tests/test_flow_reconstruction.py::TestTCPSimpleFlow -v
```

### Key files
| File | Purpose |
|------|---------|
| `tests/conftest.py` | Adds `src/` and `tests/` to `sys.path` |
| `tests/helpers.py` | `make_tcp_packet()`, `write_pcap()`, `run_reconstruction()` |
| `tests/test_flow_reconstruction.py` | Integration test scenarios |

### How `run_reconstruction()` works
Imports `FlowReconstructor` directly (no subprocess), runs it on a synthetic Scapy-crafted PCAP, and returns a list of flow dicts.

**Timing override pattern for FIN flows:**
`_finalizing_flows_terminator` blocks on a real-time `threading.Event.wait(tcp_termination_check_interval)` — default 5 s. `run_reconstruction()` overrides only this interval to 0.1 s to keep tests fast; **it does not override the grace period**. Instead, synthetic PCAPs are designed with the final packet at pcap-time > 1 s after the FIN packet so the pcap-timestamp condition `(current_time - finalization_time > 1.0)` is satisfied when the terminator thread wakes up.

### Adding new test scenarios
1. Write a `_build_*_pcap(path)` function in `test_flow_reconstruction.py` using `make_tcp_packet()`.
2. Create a new test class with a `flow` fixture (scope="class") that calls `run_reconstruction()`.
3. Add one `test_*` method per assertion.
4. Remove `@pytest.mark.skip` from the matching placeholder class (or add a new class).

---

## Token Efficiency Rules

- Read **only** `.py` files in `src/` and profiling outputs under `memory_profile/`.
- Do **not** read `venv/`, `artifacts/`, `pcap/`, or any non-Python file.
- When profiling results exist in `memory_profile/memory_samples.csv`, read that file instead of re-running the full profiler.
- Prefer `Grep` over full `Read` when searching for a specific pattern.
