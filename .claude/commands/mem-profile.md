# /mem-profile — Run Memory Profiler & Interpret Results

Run the memory profiler against the `net-watcher-test-only` dataset and produce an interpreted summary. Useful before and after any change that could affect memory or throughput.

## Steps

1. **Check for recent results** — read `memory_profile/memory_samples.csv` if it exists and was modified today (check via `ls -la memory_profile/` through Bash). If fresh results exist, skip re-running and jump to step 3.

2. **Run the profiler**:
   ```bash
   venv/Scripts/python profile_memory.py
   ```
   Wait for completion (can take several minutes for large pcap datasets). The script prints progress and final stats to stdout.

3. **Parse `memory_profile/memory_samples.csv`** — read the file and compute:
   - Peak RSS (MB)
   - Average RSS (MB)
   - Time to peak (seconds from start)
   - Memory growth rate (MB/s during the steepest climb phase)
   - Whether memory is released at the end (final RSS vs peak)

4. **Cross-reference with application logs** — if `memory_profile/events/` contains `.log` files, check the last few lines for any `discarded` warnings or errors.

5. **Report** with this structure:
   ```
   ## Memory Profile Results

   | Metric | Value |
   |--------|-------|
   | Peak RSS | X MB |
   | Avg RSS | X MB |
   | Time to peak | X s |
   | Growth rate (steep phase) | X MB/s |
   | Memory released at end | Yes/No (final: X MB) |

   ## Interpretation
   [Analysis of what the profile shape indicates — e.g., "Steady climb with no release
   indicates flows are accumulating in memory faster than they are GC'd"]
   ```

## Notes
- The profiler samples every 0.5 s. Spiky peaks between samples are not captured.
- RSS includes TensorFlow's pre-allocated memory (visible even at t=0 before any packets are read).
- Only read `.py` and `.csv`/`.log` files — do not inspect pcap files.
