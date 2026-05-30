"""Shared helpers for the packet-parsing micro-benchmarks.

These scripts answer one question: how much of our per-packet cost is Scapy
overhead vs. the raw work of pulling fields out of the bytes? They do NOT do
flow reconstruction -- they only read each packet and extract the same fields
our PacketRecord + 5-tuple carry, into a plain tuple.

The record is a plain tuple (not a dataclass) so every parser pays the exact
same construction cost; we're measuring parsing, not object allocation.

Record field order (keep identical across all parsers):
    (time, src_ip, dst_ip, sport, dport, protocol,
     payload_bytes, tcp_flags, tcp_window, tcp_wscale)

Mirrors src/flow_reconstruction.py:_to_record + preprocess, minus `direction`
(which is a flow-reconstruction decision, not a parsing one).
"""
import argparse
import time

# Indices into the record tuple, for readability in --verify.
T, SRC, DST, SPORT, DPORT, PROTO, PAYLEN, FLAGS, WIN, WSCALE = range(10)

PROTO_TCP = 6
PROTO_UDP = 17


def make_arg_parser(description):
    p = argparse.ArgumentParser(description=description)
    p.add_argument(
        "pcap",
        nargs="?",
        default="pcap/net-watcher-test-only/benign/benign.pcap",
        help="Path to the .pcap file (classic libpcap, Ethernet linktype).",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=500_000,
        help="Max packets per pass. Use 0 for the whole file.",
    )
    return p


class Timer:
    """Context manager that records wall-clock seconds into .elapsed."""
    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.elapsed = time.perf_counter() - self._start
        return False


def report(method, n_read, read_s, n_parsed, parse_s):
    """Print a one-method timing block. parse_s is the FULL read+parse pass."""
    parse_only = parse_s - read_s
    print(f"\n=== {method} ===")
    print(f"  read-only pass : {n_read:>10,} pkts  {read_s:7.3f} s"
          f"  ({_pps(n_read, read_s)})")
    print(f"  read+parse pass: {n_parsed:>10,} pkts  {parse_s:7.3f} s"
          f"  ({_pps(n_parsed, parse_s)})")
    print(f"  parse-only     : {' ':>10}        {parse_only:7.3f} s"
          f"  ({_pps(n_parsed, parse_only)})")


def _pps(n, secs):
    if secs <= 0 or n <= 0:
        return "n/a"
    return f"{n / secs:,.0f} pkt/s"
