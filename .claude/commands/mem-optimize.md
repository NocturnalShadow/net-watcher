# /mem-optimize [N] — Apply a Specific Memory Optimization

Apply one of the ranked optimizations from `CLAUDE.md` to the source code. Always apply optimizations one at a time so the impact of each can be measured with `/mem-profile`.

**Usage:** `/mem-optimize 1` (apply optimization #1), `/mem-optimize 2` (apply #2), etc.

If no number is provided, list available optimizations and prompt the user to choose.

---

## Optimization #1 — Replace Scapy packets with `PacketRecord` slots dataclass

**Target files:** `src/flow_reconstruction.py`, `src/flow_features.py`

**Steps:**

1. Read `src/flow_reconstruction.py` and `src/flow_features.py` in full.

2. Add the `PacketRecord` dataclass near the top of `src/flow_reconstruction.py` (after imports):
   ```python
   from dataclasses import dataclass

   @dataclass(slots=True)
   class PacketRecord:
       time: float
       payload_bytes: int
       direction: int    # Direction enum value (int), not the enum itself
       tcp_flags: int    # int(packet[TCP].flags); 0 for non-TCP
       tcp_window: int   # packet[TCP].window; 0 for non-TCP
       tcp_wscale: int   # 2**WScale option; 1 if no WScale option present
   ```

3. Add a conversion function `_to_record(packet) -> PacketRecord` after the dataclass — extract all needed fields from the Scapy packet and return a `PacketRecord`. The first-packet metadata (src_ip, dst_ip, sport, dport, protocol, time) must be stored on the **flow dict** at `initiate_new_flow()` time, not per-packet.

4. In `preprocess()`, at the very end (before `return True`), call `packet._record = _to_record(packet)` — this lets existing code that checks `TCP in packet` still work for the routing logic in `_packet_processor`, while the record is ready for storage.

5. In `initiate_new_flow()`:
   - Store first-packet metadata on the flow dict: `flow["src_ip"]`, `flow["dst_ip"]`, `flow["sport"]`, `flow["dport"]`, `flow["protocol"]`, `flow["first_time"]`.
   - Store `[packet._record]` as `flow["packets"]` instead of `[packet]`.

6. In `process_tcp()` and `process_universal()`, when appending to `flow["packets"]`, append `packet._record` instead of `packet`.

7. Update `flow_features.py`:
   - `first_packet_time(flow)`: return `flow["packets"][0].time`
   - `last_packet_time(flow)`: return `flow["packets"][-1].time`
   - `calculate_features()`: use `flow["src_ip"]`, `flow["dst_ip"]`, etc. (now on flow dict). Access per-packet fields as `record.time`, `record.payload_bytes`, `record.direction` (compare to `Direction.FORWARD.value` etc.).
   - `calculate_tcp_window_features()`: access `record.tcp_flags`, `record.tcp_window`, `record.tcp_wscale`. Replace `packet[TCP].flags.S`, `.A`, `.F`, `.R` with bitflag checks: `record.tcp_flags & 0x02` (SYN), `& 0x10` (ACK), `& 0x01` (FIN), `& 0x04` (RST).

8. **Verify**: The `Direction` enum values are `UNKNOWN=0, FORWARD=1, BACKWARD=2`. Comparisons like `packet.direction = Direction.FORWARD` must become `record.direction = Direction.FORWARD.value` or use integer constants.

9. After applying, run:
   ```bash
   venv/Scripts/python -c "from flow_reconstruction import FlowReconstructor; print('import ok')"
   venv/Scripts/python -c "from flow_features import calculate_features; print('import ok')"
   ```
   Then run `profile_memory.py` to measure the new peak RSS.

**Pros:** Expected 60–80% RSS reduction. No data loss.
**Cons:** ~50 line changes across 2 files. Must verify all packet field accesses.

---

## Optimization #2 — Bound the `network_flows` queue

**Target file:** `src/run.py`

**Steps:**

1. Read `src/run.py`.

2. In `detection_offline()` and `detection_online()`, change:
   ```python
   network_flows = queue.Queue()
   ```
   to:
   ```python
   network_flows = queue.Queue(maxsize=2000)
   ```

3. In `flow_reconstruction.py` `_terminated_flows_processor()`, the `enqueue_nowait` call for `reconstructed_flows` should block instead of discarding in offline mode. Add an optional `blocking` parameter to `enqueue_nowait` or use `put(flow, timeout=60)` directly:
   ```python
   # Replace: self.enqueue_nowait(self.reconstructed_flows, flow, "reconstructed flow")
   # With (for offline tolerance):
   try:
       self.reconstructed_flows.put(flow, timeout=60)
   except queue.Full:
       log.warning("reconstructed_flows queue full after 60s — discarding flow")
   ```
   Note: only do this if `reconstructed_flows` is an `output_queue` set by the caller. Check the queue's `maxsize` attribute to decide behavior:
   ```python
   if self.reconstructed_flows.maxsize > 0:
       self.reconstructed_flows.put(flow, timeout=60)
   else:
       self.enqueue_nowait(self.reconstructed_flows, flow, "reconstructed flow")
   ```

4. Run `profile_memory.py` and compare peak RSS.

**Pros:** 1–2 line change; prevents unbounded memory growth when TF classifier is slower than reconstruction.
**Cons:** In worst case, reconstruction blocks waiting for classifier. For offline mode this is fine (throughput > latency). For online mode, the existing `enqueue_nowait` (drop) behavior is preserved by the `maxsize` check above.

---

## Optimization #3 — TensorFlow memory growth flag

**Target file:** `src/run.py`

**Steps:**

1. Read `src/run.py`.

2. After `os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'` and before `import tensorflow as tf`, add:
   ```python
   os.environ['TF_FORCE_GPU_ALLOW_GROWTH'] = 'true'
   ```

3. After `import tensorflow as tf` and before any model loading, add:
   ```python
   gpus = tf.config.list_physical_devices('GPU')
   for gpu in gpus:
       tf.config.experimental.set_memory_growth(gpu, True)
   ```
   Place this immediately after the `print("Num GPUs Available: ...")` line.

4. Run `profile_memory.py` and compare baseline (t=0) RSS to identify reduction.

**Pros:** 3 lines; effective on GPU systems; harmless on CPU-only.
**Cons:** Negligible on CPU-only systems (no GPU to control).

---

## Optimization #4 — GC freeze after model/scaler load

**Target file:** `src/flow_analysis.py`

**Steps:**

1. Read `src/flow_analysis.py`.

2. Add `import gc` at the top.

3. After the model and scaler are fully loaded (after `scaler = pickle.load(f)` closes), add:
   ```python
   gc.collect()    # clear any garbage before freezing
   gc.freeze()     # exempt stable objects (model weights, scaler) from GC scanning
   gc.set_threshold(10000, 10, 10)  # reduce GC frequency
   ```

4. Run `profile_memory.py`. This primarily reduces CPU overhead (GC pause time) rather than peak RSS, but it prevents GC from holding memory longer than needed.

**Pros:** 4 lines; reduces GC pressure during batch inference.
**Cons:** Minor effect on RSS; main benefit is throughput stability.

---

## Optimization #5 — Strip sequence fields before batching in analyzer

**Target file:** `src/flow_analysis.py`

**Steps:**

1. Read `src/flow_analysis.py`.

2. In `_analyze_flows()`, in the while loop where flows are extracted from the queue, after `features, _ = flow_to_np_and_meta(flow)`, add:
   ```python
   # Free large sequence lists — not needed for classification or event logging
   for _seq_key in ('payload_bytes_seq', 'interarrival_time_s_seq',
                    'fwd_window_size_seq', 'bwd_window_size_seq'):
       flow.pop(_seq_key, None)
   ```

3. Run `profile_memory.py`.

**Pros:** 5 lines; reduces per-flow dict size by removing the longest lists.
**Cons:** Sequence data lost before `process_batch()`. If you ever want to log or inspect sequences in the event log, add that before these pops.

---

## After Each Optimization

Always report:
```
## Optimization #N Applied

### Changes Made
[List of specific edits with file:line references]

### Verification
- Import check: PASS/FAIL
- Profile run: pending (run /mem-profile)

### Expected Next Step
[Which optimization to apply next, or "target achieved"]
```
