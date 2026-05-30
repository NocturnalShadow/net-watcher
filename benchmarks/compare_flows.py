"""Compare two flow-reconstruction parquet outputs for equivalence.

Used to validate that --packet-parser scapy and --packet-parser dpkt produce
identical flows. Reads every parquet under each directory, checks row counts
match, then compares the full feature tables after sorting by the 5-tuple so
emission-order differences don't cause false diffs.

Usage:
    venv/Scripts/python benchmarks/compare_flows.py <dir_a> <dir_b>
"""
import sys

import numpy as np
import pandas as pd


KEY = ["src_ip", "dst_ip", "sport", "dport", "protocol"]


def load(path):
    df = pd.read_parquet(path)
    sort_cols = [c for c in KEY if c in df.columns]
    # include a stable tiebreaker so duplicate 5-tuples order deterministically
    extra = [c for c in df.columns if c not in sort_cols]
    df = df.sort_values(sort_cols + extra, kind="stable").reset_index(drop=True)
    return df


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    a = load(sys.argv[1])
    b = load(sys.argv[2])

    print(f"A: {sys.argv[1]}  rows={len(a)} cols={len(a.columns)}")
    print(f"B: {sys.argv[2]}  rows={len(b)} cols={len(b.columns)}")

    if len(a) != len(b):
        print(f"FAIL: row count differs ({len(a)} vs {len(b)})")
        sys.exit(1)
    if list(a.columns) != list(b.columns):
        print(f"FAIL: columns differ\n  A: {list(a.columns)}\n  B: {list(b.columns)}")
        sys.exit(1)

    mismatched = []
    for col in a.columns:
        ca, cb = a[col], b[col]
        if pd.api.types.is_float_dtype(ca) and pd.api.types.is_float_dtype(cb):
            equal = np.allclose(ca.fillna(0), cb.fillna(0), rtol=1e-9, atol=1e-9)
        else:
            equal = ca.equals(cb)
        if not equal:
            mismatched.append(col)

    if mismatched:
        print(f"FAIL: {len(mismatched)} column(s) differ: {mismatched}")
        for col in mismatched[:5]:
            diff = a[col] != b[col]
            idx = diff[diff].index[:5]
            print(f"\n  column '{col}' first diffs:")
            print(pd.DataFrame({"A": a[col].iloc[idx], "B": b[col].iloc[idx]}))
        sys.exit(1)

    print(f"\nPASS: {len(a)} flows identical across all {len(a.columns)} feature columns.")


if __name__ == "__main__":
    main()
