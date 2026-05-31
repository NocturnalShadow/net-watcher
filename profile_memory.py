"""
Memory usage profiler for net-watcher detector mode.
Runs the detector against pcap/icsx-ctu-extended/test/ and records RSS memory over time.

Usage:
    venv/Scripts/python profile_memory.py

Results are saved to memory_profile/ directory.
"""

import subprocess
import sys
import time
import os
import psutil
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

INPUT_PATH = "pcap/icsx-ctu-extended/test/"
OUTPUT_PATH = "memory_profile/events/"
RESULTS_DIR = "memory_profile"
SAMPLE_INTERVAL = 0.5  # seconds between memory samples


def short_commit_hash():
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def run():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(OUTPUT_PATH, exist_ok=True)
    commit = short_commit_hash()

    python = os.path.join("venv", "Scripts", "python.exe")  # Windows
    if not os.path.exists(python):
        python = os.path.join("venv", "bin", "python")  # Linux/Mac

    cmd = [
        python, "src/run.py",
        "--role", "detector",
        "--input-path", INPUT_PATH,
        "--output-path", OUTPUT_PATH,
        "--output-filter", "all",
    ]

    print(f"Running: {' '.join(cmd)}")
    print(f"Sampling memory every {SAMPLE_INTERVAL}s...")

    timestamps = []
    rss_mb = []
    start = time.perf_counter()

    # Don't capture stdout — let it print to terminal directly.
    # Piping stdout into PIPE causes the OS pipe buffer to fill up and deadlock
    # the subprocess when it produces lots of output (as the detector does).
    proc = subprocess.Popen(cmd)

    def process_tree_rss_mb(ps):
        """Sum RSS of process and all its children (TensorFlow spawns child workers)."""
        try:
            total = ps.memory_info().rss
            for child in ps.children(recursive=True):
                try:
                    total += child.memory_info().rss
                except psutil.NoSuchProcess:
                    pass
            return total / (1024 ** 2)
        except psutil.NoSuchProcess:
            return None

    try:
        ps = psutil.Process(proc.pid)
        while proc.poll() is None:
            mem = process_tree_rss_mb(ps)
            if mem is None:
                break
            elapsed = time.perf_counter() - start
            timestamps.append(elapsed)
            rss_mb.append(mem)
            time.sleep(SAMPLE_INTERVAL)
    except KeyboardInterrupt:
        proc.terminate()

    proc.wait()
    elapsed_total = time.perf_counter() - start

    print(f"\nCompleted in {elapsed_total:.1f}s")
    if rss_mb:
        print(f"Peak RSS: {max(rss_mb):.1f} MB")
        print(f"Avg RSS:  {sum(rss_mb)/len(rss_mb):.1f} MB")

    if not rss_mb:
        print("No memory samples collected.")
        return

    # Save raw data
    data_path = os.path.join(RESULTS_DIR, f"memory_samples_{commit}.csv")
    with open(data_path, "w") as f:
        f.write("time_s,rss_mb\n")
        for t, m in zip(timestamps, rss_mb):
            f.write(f"{t:.2f},{m:.2f}\n")
    print(f"Raw data saved to {data_path}")

    # Plot
    fig, ax = plt.subplots(figsize=(12, 5))
    ax.plot(timestamps, rss_mb, linewidth=1.2, color="steelblue", label="RSS memory")
    ax.axhline(max(rss_mb), linestyle="--", color="red", linewidth=0.8, label=f"Peak: {max(rss_mb):.1f} MB")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("RSS Memory (MB)")
    ax.set_title("net-watcher detector — memory usage over time\n"
                 f"Commit: {commit}  |  Input: {INPUT_PATH}  |  Duration: {elapsed_total:.1f}s  |  Peak: {max(rss_mb):.1f} MB")
    ax.legend()
    ax.yaxis.set_minor_locator(ticker.AutoMinorLocator())
    ax.grid(True, which="major", linestyle="--", alpha=0.5)
    ax.grid(True, which="minor", linestyle=":", alpha=0.3)
    ax.set_xlim(left=0)
    ax.set_ylim(bottom=0)

    graph_path = os.path.join(RESULTS_DIR, f"memory_usage_{commit}.png")
    fig.savefig(graph_path, dpi=150, bbox_inches="tight")
    print(f"Graph saved to {graph_path}")
    plt.close(fig)


if __name__ == "__main__":
    run()
