# /mem-analyze — Deep Memory Hotspot Analysis with tracemalloc

Inject tracemalloc into the pipeline to pinpoint the exact code lines and object types consuming the most memory. This produces actionable data to confirm which hotspot to target first.

## Steps

1. **Create analysis script** — write `memory_profile/tracemalloc_probe.py`:

```python
"""
Tracemalloc deep analysis for net-watcher.
Runs detector on a subset of packets (first 50k) and snapshots top allocations.

Usage:
    venv/Scripts/python memory_profile/tracemalloc_probe.py
"""
import os, sys, tracemalloc, gc, queue, threading, time

sys.path.insert(0, "src")
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

PCAP_PATH = "pcap/net-watcher-test-only/"
SNAPSHOT_AFTER_PACKETS = 50_000  # take snapshot after this many packets

tracemalloc.start(25)  # keep 25 frames of traceback

from flow_reconstruction import FlowReconstructor
from flow_analysis import analyze_flows
from logging_utils import configure_app_logger
configure_app_logger(level=30)  # WARNING only

event_log = "memory_profile/tracemalloc_events.log"
network_flows = queue.Queue()

analyzer_thread = threading.Thread(
    target=analyze_flows,
    args=(network_flows, event_log, "all"),
    daemon=True,
)
analyzer_thread.start()

packet_count = [0]
snapshot_taken = [False]

def on_stats(reconstructor):
    packet_count[0] += 1
    if packet_count[0] == SNAPSHOT_AFTER_PACKETS and not snapshot_taken[0]:
        snapshot_taken[0] = True
        snapshot = tracemalloc.take_snapshot()
        stats = snapshot.statistics('lineno')
        print(f"\n=== TRACEMALLOC SNAPSHOT at {SNAPSHOT_AFTER_PACKETS} packets ===")
        print(f"Top 20 memory allocations:")
        for i, stat in enumerate(stats[:20], 1):
            print(f"  {i:2d}. {stat}")

        # Also group by file
        stats_by_file = snapshot.statistics('filename')
        print(f"\nTop 10 files by allocation:")
        for i, stat in enumerate(stats_by_file[:10], 1):
            print(f"  {i:2d}. {stat}")

        current, peak = tracemalloc.get_traced_memory()
        print(f"\ntracemalloc current: {current/1024/1024:.1f} MB, peak: {peak/1024/1024:.1f} MB")

import glob as _glob
pcap_files = _glob.glob(os.path.join(PCAP_PATH, '**', '*.pcap'), recursive=True)
if not pcap_files:
    print(f"No pcap files found in {PCAP_PATH}")
    sys.exit(1)

print(f"Analyzing: {pcap_files[0]}")
print(f"Will snapshot at {SNAPSHOT_AFTER_PACKETS} packets...")

with FlowReconstructor(output_queue=network_flows, stats_log_step=10_000,
                       collect_stats=True) as reconstructor:
    # Monkey-patch update_stats to trigger our snapshot
    _orig_update = reconstructor.update_stats
    def _patched(pkt):
        _orig_update(pkt)
        on_stats(reconstructor)
    reconstructor.update_stats = _patched
    reconstructor.offline(pcap_files[0])

network_flows.put(None)
analyzer_thread.join(timeout=30)

snapshot2 = tracemalloc.take_snapshot()
stats2 = snapshot2.statistics('lineno')
print(f"\n=== FINAL SNAPSHOT (after processing) ===")
for i, stat in enumerate(stats2[:20], 1):
    print(f"  {i:2d}. {stat}")

tracemalloc.stop()
print("\nDone. Check output above for hotspots.")
```

2. **Run the probe**:
   ```bash
   venv/Scripts/python memory_profile/tracemalloc_probe.py 2>&1 | tee memory_profile/tracemalloc_output.txt
   ```

3. **Read `memory_profile/tracemalloc_output.txt`** and identify:
   - Which source files (`src/*.py`) dominate allocations
   - The top 5 specific lines responsible for the most memory
   - Whether Scapy objects, flow dicts, or queue buffers are the dominant type

4. **Report** with this structure:
   ```
   ## Tracemalloc Analysis Results

   ### Top Allocation Sites
   | Rank | File:Line | Size | Count | Object type |
   |------|-----------|------|-------|-------------|
   | 1    | ...       | X MB | X     | ...         |

   ### Root Cause Assessment
   [Confirm or refine the hotspot ranking from CLAUDE.md]

   ### Recommended First Fix
   [Specific optimization from CLAUDE.md #N — with confidence level based on data]
   ```

## Notes
- tracemalloc measures Python-managed heap only. TF model weights and numpy arrays may show up as C-level allocations not captured here — that's expected.
- The probe processes only the first pcap file. This is sufficient to identify hotspots.
- If `SNAPSHOT_AFTER_PACKETS` is reached before the first pcap file finishes, the snapshot still captures the in-flight state.
- Do not read any files other than `.py` sources and the generated output files.
