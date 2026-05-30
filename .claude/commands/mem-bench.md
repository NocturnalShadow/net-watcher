# /mem-bench — Benchmark Memory vs. Performance Trade-off

Compare memory and throughput before and after a change to ensure no performance regression.

## Steps

1. **Check if baseline exists** — look for `memory_profile/baseline_memory_samples.csv`. If absent, the current `memory_profile/memory_samples.csv` (if it exists from a prior run) should be copied to baseline first. Prompt the user: "No baseline found. Should I use the current memory_samples.csv as baseline? (y/n)"

2. **Run profiler on current code**:
   ```bash
   venv/Scripts/python profile_memory.py
   ```
   This overwrites `memory_profile/memory_samples.csv` and prints completion time to stdout.

3. **Read both CSVs** (`memory_profile/baseline_memory_samples.csv` and `memory_profile/memory_samples.csv`) and compute the comparison table:

   | Metric | Baseline | Current | Delta | % Change |
   |--------|----------|---------|-------|----------|
   | Peak RSS (MB) | | | | |
   | Avg RSS (MB) | | | | |
   | Total runtime (s) | | | | |
   | Time to peak (s) | | | | |
   | Final RSS (MB) | | | | |

4. **Throughput proxy**: total runtime is the primary proxy for throughput (same dataset processed). If runtime increased >5%, flag as a potential regression.

5. **Check for data quality regression** — scan the most recent event log in `memory_profile/events/` for `discarded` messages. If any flows were discarded that weren't in the baseline run, flag it.

6. **Verdict**:
   - ✓ **No throughput regression**: runtime delta < +5%
   - ✓ **No data loss regression**: no new `discarded` warnings
   - ✗ Flag any criterion that fails with specific numbers

7. **Save baseline** if the user confirms the current version is the new reference:
   ```bash
   cp memory_profile/memory_samples.csv memory_profile/baseline_memory_samples.csv
   ```

## Notes
- Runtime is measured by `profile_memory.py`'s own timer (printed at end). Read stdout or check the CSV timestamp range for total duration.
- If the full profiler run takes too long, suggest running on a single small pcap file first for quick iteration.
- Do not read pcap files — only `.py`, `.csv`, and `.log` files.
