"""Benchmark: read + parse packets the EXACT way net-watcher does today.

This drives the real production code path from src/flow_reconstruction.py:
  RawPcapReader -> Ether(pkt_data) -> FlowReconstructor.preprocess(packet)
  -> _to_record(packet, direction)
so the numbers reflect Scapy's true cost in the running system (no
reimplementation). Flow reconstruction itself is skipped -- we stop right
after the per-packet record is built.

Two passes over the file separate I/O from dissection:
  * read-only  : iterate RawPcapReader, pull raw bytes + timestamp, nothing else.
  * read+parse : same, but Ether() + preprocess() + _to_record() each packet.
  parse-only = (read+parse) - (read-only).

Usage:
    venv/Scripts/python benchmarks/bench_scapy.py [pcap] [--limit N]
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scapy.all import Ether, RawPcapReader  # noqa: E402
from scapy.utils import RawPcapNgReader  # noqa: E402

from flow_reconstruction import _parsed_from_scapy  # noqa: E402

import bench_common as bc  # noqa: E402


def _time_extractor(reader):
    # Classic pcap: sec/usec. pcapng: tshigh/tslow/tsresol. (matches production)
    if isinstance(reader, RawPcapNgReader):
        return lambda m: ((m.tshigh << 32) | m.tslow) / m.tsresol
    return lambda m: m.sec + m.usec / 1_000_000


def read_only(path, limit):
    reader = RawPcapReader(path)
    extract_time = _time_extractor(reader)
    n = 0
    sink = 0.0
    for pkt_data, pkt_meta in reader:
        sink += extract_time(pkt_meta)  # touch the data so it isn't optimized out
        n += 1
        if limit and n >= limit:
            break
    reader.close()
    return n


def parse_record(pkt, ts):
    """Run the production Scapy parse (_parsed_from_scapy); return comparison tuple."""
    rec = _parsed_from_scapy(pkt, ts)
    if rec is None:
        return None
    return (rec.time, rec.src_ip, rec.dst_ip, rec.sport, rec.dport,
            rec.protocol, rec.payload_bytes, rec.tcp_flags,
            rec.tcp_window, rec.tcp_wscale)


def read_and_parse(path, limit):
    reader = RawPcapReader(path)
    extract_time = _time_extractor(reader)
    n = 0
    last = None
    for pkt_data, pkt_meta in reader:
        if len(pkt_data) < 14:
            continue
        ts = extract_time(pkt_meta)
        pkt = Ether(pkt_data)
        rec = parse_record(pkt, ts)
        if rec is not None:
            last = rec  # keep a ref so the work isn't dead-code eliminated
            n += 1
        if limit and n >= limit:
            break
    reader.close()
    return n, last


def main():
    args = bc.make_arg_parser(__doc__).parse_args()
    limit = args.limit

    with bc.Timer() as t_read:
        n_read = read_only(args.pcap, limit)
    with bc.Timer() as t_parse:
        n_parsed, _ = read_and_parse(args.pcap, limit)

    bc.report("Scapy (production path: Ether + preprocess + _to_record)",
              n_read, t_read.elapsed, n_parsed, t_parse.elapsed)


if __name__ == "__main__":
    main()
