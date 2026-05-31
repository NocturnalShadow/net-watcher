# Net-Watcher Memory Optimization Agent

## Role & Objective

You are a specialized memory optimization agent for the **net-watcher** network threat detection system. The original goal was to reduce peak RSS from ~5 GB to under 1 GB on the `icsx-ctu-extended` test dataset (`pcap/icsx-ctu-extended/test/`) without degrading detection accuracy or processing throughput.

## Current Status (as of commit `6cf5eb5` on `memory-optimization` branch)

**Optimizations applied:**
- **#1 PacketRecord slots dataclass** — `flow["packets"]` now holds lightweight records (~100 B/record vs ~2–5 KB/Scapy pkt); 5-tuple metadata stored once on the flow dict.
- **#2 Bounded `network_flows` queue** — `--flow-queue-max-size` CLI arg (default 2000); offline modes use blocking `put()` (backpressure), online keeps `enqueue_nowait` (discard).

**Results on full dataset:**
- `main` baseline `7e875d9`: 5,020.8 MB peak / 1,804.4 MB avg / 4,307 s
- After `6cf5eb5` (#1 + #2): **927.8 MB peak / 840.5 MB avg / 3,100 s** — sub-1 GB target met.
- Runtime improved ~28 % (less GC churn on Scapy object graphs).

**Still unbounded / not yet guaranteed safe for arbitrary input:**
- `active_flows` and `finalizing_flows` dicts — count is constrained only by flow lifecycle (timeouts / FIN / RST), not by a hard cap. A pathological pcap could still grow these without bound. See Hotspot #2B below.
- `packet_queue` and `terminated_flows` queues use `enqueue_nowait` in all modes — in offline this silently drops packets/flows under load rather than propagating backpressure upstream. See Hotspot #2C below.

## Profiler output naming

`profile_memory.py` suffixes output files with the short commit hash (e.g. `memory_samples_6cf5eb5.csv`, `memory_usage_6cf5eb5.png`) so successive runs don't overwrite baselines. This lives on `memory-optimization`; on `main` the files are unsuffixed.

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

### #1 — Scapy packet objects in `active_flows` / `finalizing_flows` — **DONE (commit `6cf5eb5`)**

Each flow stored full Scapy packet objects in `flow["packets"]` (~2–5 KB per packet). With thousands of simultaneous TCP flows × tens of packets, this dominated peak RSS.

**Implemented:** `PacketRecord` `__slots__` dataclass in `flow_reconstruction.py` carrying only the fields downstream needs (`time`, `payload_bytes`, `direction`, `tcp_flags`, `tcp_window`, `tcp_wscale`). `_to_record(packet, direction)` converts Scapy packets at append-time. 5-tuple metadata (`src_ip`, `dst_ip`, `sport`, `dport`, `protocol`) is stored once on the flow dict in `initiate_new_flow`. `flow_features.py` reads metadata from the flow dict and iterates `PacketRecord` fields; TCP flag counting uses `enums.TCPFlag` bitmasks instead of Scapy's `FlagValue`.

Delivered ~5× reduction in peak RSS alone. All 186 reconstruction tests still pass.

---

### #2 — Unbounded `network_flows` / `reconstructed_flows` queue in detector mode — **DONE (commit on `memory-optimization` branch)**

**Implemented:** new CLI arg `--flow-queue-max-size` (default 2000) sets the cap in `run.py`. `FlowReconstructor` accepts `backpressure=True`; in `_terminated_flows_processor`, offline modes use blocking `put()`, online keeps `enqueue_nowait` (drop for real-time latency). Offline modes (`detection_offline`, `flow_reconstruction_offline`) pass `backpressure=True`.

Note: this optimization was originally *applied before* #1 and caused a regression (peak RSS doubled) because bounded output forced upstream accumulation in `terminated_flows` queue items that still held raw Scapy packets. With #1 in place, upstream items are cheap and the bound is a net win.

---

### #2B — `active_flows` / `finalizing_flows` dicts have no hard cap (NEW, PENDING)

**Location:** `flow_reconstruction.py` — `initiate_new_flow()` adds to `self.active_flows` with no size limit.

Current count is implicitly bounded by flow termination (idle/activity timeouts, FIN/RST). A pathological pcap (e.g. SYN-flood-like pattern with many short-lived half-open connections arriving faster than the timeout thread terminates them) could still grow these dicts arbitrarily, especially since each entry now carries up to `max_packets` PacketRecords.

**Possible fixes:**
- Hard cap on `len(active_flows) + len(finalizing_flows)`; when reached, evict oldest active flow (terminate by `"overflow"`) — but this *drops data*, acceptable only if we document the limit.
- Propagate backpressure upstream instead: when the dict count is high, delay consuming from `packet_queue` so the pcap reader stalls. Cleaner for offline.

**Priority:** Not observed as a peak-RSS driver on the current test dataset, but necessary for a true "predictable upper bound on any input" guarantee.

---

### #2C — `packet_queue` and `terminated_flows` still drop in offline mode (NEW, PENDING)

**Location:** `flow_reconstruction.py` — `online()` packet_handler, `offline()` for-loop, and `terminate_flow()` use `enqueue_nowait` which silently discards when full. The `backpressure` flag introduced for #2 only applies to `reconstructed_flows`.

For offline correctness the two upstream queues should also block when full, so the `RawPcapReader` stalls instead of losing data.

**Fix sketch:** extend the `backpressure` flag to gate `enqueue_nowait` → blocking `put` for `packet_queue` and `terminated_flows` in offline mode too. Online mode keeps drop-on-full for real-time latency.

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
Records RSS every 0.5 s. On `memory-optimization` branch results are suffixed with the short commit hash (e.g. `memory_samples_6cf5eb5.csv`, `memory_usage_6cf5eb5.png`). On `main` the files are unsuffixed.

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

| # | Change | Est. RSS reduction | Status |
|---|--------|--------------------|--------|
| 1 | Scapy → PacketRecord slots dataclass | **−81% peak RSS (measured)** | Done `6cf5eb5` |
| 2 | Bound `network_flows` queue with offline backpressure | small on its own; load-bearing for #2B/C | Done |
| 2B | Cap `active_flows` / `finalizing_flows` dicts or propagate backpressure | correctness, not peak | Pending |
| 2C | Extend backpressure to `packet_queue` and `terminated_flows` | correctness, not peak | Pending |
| 3 | TF memory growth flag | 5–15% | Pending |
| 4 | GC freeze after model load | 2–5% | Pending |
| 5 | Strip seq fields in `analyze_flows` | 2–5% | Pending |

## Lessons Learned

- **Sequencing matters: #2 before #1 was a regression.** Bounding the post-feature-calc `network_flows` queue while upstream queues still held heavy Scapy packet objects just moved the backpressure to heavier items (`terminated_flows` at 10 k × ~3 KB/pkt × dozens of pkts/flow). Peak RSS *doubled*. After #1 landed, items at every stage are cheap and #2's bound became a net win.
- **Bound memory by *byte-equivalent*, not item count.** A 2 k queue of lightweight flow-feature dicts ≪ a 10 k queue of flow dicts each containing a list of Scapy packets. Queue `maxsize` is meaningful only once item size is known and stable.
- **Analyzer-slower-than-reconstructor was suspected, not measured.** Before extending backpressure or tuning queue sizes further, instrument `_analyze_flows` with `perf_counter` around `model.predict()` and batch-fill waits to confirm where time goes.

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
