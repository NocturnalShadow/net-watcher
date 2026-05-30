"""Benchmark: Isolated parse performance with dpkt vs Scapy.

Tests four scenarios to identify where the actual cost is:
  1. Read-only (I/O baseline)
  2. Scapy: Ether() dissection only (can't run — Scapy removed)
  3. dpkt: parse_packet() dissection
  4. Hand-rolled struct parsing for reference

This measures pure parsing overhead in isolation. The full pipeline
(reconstruct + features + classify) is profiled separately via profile_memory.py.

Usage:
    venv/Scripts/python benchmarks/bench_integrated.py [pcap] [--limit N]
"""
import argparse
import os
import sys
import time
import socket
import struct

import dpkt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from packet_parsing import parse_packet, resolve_link_layer_dissector

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
VLAN_TAGS = (0x8100, 0x88A8)
PROTO_TCP = 6
PROTO_UDP = 17


def iter_pcap(path, limit=0):
    """Yield (timestamp, packet_bytes, linktype) from a classic libpcap file."""
    with open(path, "rb") as f:
        gh = f.read(24)
        magic = struct.unpack("<I", gh[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            endian, ns = "<", magic == 0xA1B23C4D
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            endian, ns = ">", magic == 0x4D3CB2A1
        else:
            raise ValueError(f"Not a classic pcap (magic=0x{magic:08x})")
        linktype = struct.unpack(endian + "I", gh[20:24])[0]

        rec_hdr = struct.Struct(endian + "IIII")
        divisor = 1_000_000_000 if ns else 1_000_000
        read = f.read
        count = 0
        while True:
            hdr = read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_sub, incl_len, _orig = rec_hdr.unpack(hdr)
            data = read(incl_len)
            if len(data) < incl_len:
                break
            count += 1
            yield ts_sec + ts_sub / divisor, data, linktype
            if limit and count >= limit:
                break


class Timer:
    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.elapsed = time.perf_counter() - self._start
        return False


def benchmark_read_only(path, limit):
    """Baseline: read raw bytes from pcap."""
    n = 0
    with Timer() as t:
        for ts, data, _ in iter_pcap(path, limit):
            n += 1
    return n, t.elapsed


def benchmark_dpkt(path, limit):
    """Parse packets with dpkt via src/packet_parsing.py:parse_packet()."""
    link_layer = None
    n = 0
    with Timer() as t:
        for ts, data, linktype in iter_pcap(path, limit):
            if link_layer is None:
                link_layer = resolve_link_layer_dissector(linktype)
            pkt = parse_packet(data, ts, link_layer)
            if pkt:
                n += 1
    return n, t.elapsed


_u16 = struct.Struct("!H")


def parse_struct_minimal(data, ts):
    """Hand-rolled struct parser for comparison."""
    try:
        n = len(data)
        if n < 14:
            return None
        ethertype = _u16.unpack_from(data, 12)[0]
        off = 14
        while ethertype in VLAN_TAGS:
            ethertype = _u16.unpack_from(data, off + 2)[0]
            off += 4
        if ethertype <= 0x05DC:
            if data[off:off + 3] != b"\xaa\xaa\x03":
                return None
            ethertype = _u16.unpack_from(data, off + 6)[0]
            off += 8

        if ethertype == ETH_IPV4:
            ver_ihl = data[off]
            ihl = (ver_ihl & 0x0F) * 4
            total_len = _u16.unpack_from(data, off + 2)[0]
            proto = data[off + 9]
            src_ip = socket.inet_ntoa(data[off + 12:off + 16])
            dst_ip = socket.inet_ntoa(data[off + 16:off + 20])
            transport_off = off + ihl
            ip_end = min(off + total_len, n)
        elif ethertype == ETH_IPV6:
            payload_len = _u16.unpack_from(data, off + 4)[0]
            proto = data[off + 6]
            src_ip = socket.inet_ntop(socket.AF_INET6, data[off + 8:off + 24])
            dst_ip = socket.inet_ntop(socket.AF_INET6, data[off + 24:off + 40])
            transport_off = off + 40
            ip_end = min(off + 40 + payload_len, n)
        else:
            return None

        if proto == PROTO_TCP:
            sport = _u16.unpack_from(data, transport_off)[0]
            dport = _u16.unpack_from(data, transport_off + 2)[0]
            thl = ((data[transport_off + 12] >> 4) & 0x0F) * 4
            flags = ((data[transport_off + 12] & 0x01) << 8) | data[transport_off + 13]
            window = _u16.unpack_from(data, transport_off + 14)[0]
            payload_bytes = max(0, ip_end - (transport_off + thl))
            wscale = 1
            if flags & 0x02:
                opt = transport_off + 20
                opt_end = transport_off + thl
                while opt < opt_end:
                    kind = data[opt]
                    if kind == 0:
                        break
                    if kind == 1:
                        opt += 1
                        continue
                    length = data[opt + 1]
                    if length < 2:
                        break
                    if kind == 3 and length == 3:
                        wscale = 2 ** data[opt + 2]
                        break
                    opt += length
            return 1  # found one
        elif proto == PROTO_UDP:
            return 1  # found one
        return None
    except (IndexError, struct.error):
        return None


def benchmark_struct(path, limit):
    """Parse packets with hand-rolled struct."""
    n = 0
    with Timer() as t:
        for ts, data, _ in iter_pcap(path, limit):
            if parse_struct_minimal(data, ts):
                n += 1
    return n, t.elapsed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "pcap",
        nargs="?",
        default="pcap/net-watcher-test-only/benign/benign.pcap",
        help="Path to the .pcap file (classic libpcap).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=500_000,
        help="Max packets. Use 0 for the whole file.",
    )
    args = parser.parse_args()

    print(f"\n{'='*80}")
    print(f"Isolated Parse Performance Benchmark")
    print(f"PCAP: {args.pcap}")
    print(f"Limit: {args.limit if args.limit else 'all'} packets")
    print(f"{'='*80}\n")

    # 1. Read-only baseline
    print("1. Read-only (I/O baseline)...")
    n_read, t_read = benchmark_read_only(args.pcap, args.limit)
    print(f"   {n_read:>10,} packets  {t_read:7.3f} s  ({n_read/t_read:,.0f} pkt/s)\n")

    # 2. struct (hand-rolled)
    print("2. Hand-rolled struct parser...")
    n_struct, t_struct = benchmark_struct(args.pcap, args.limit)
    parse_struct = t_struct - t_read
    print(f"   {n_struct:>10,} packets  {t_struct:7.3f} s  ({n_struct/t_struct:,.0f} pkt/s)")
    print(f"   Parse-only: {parse_struct:7.3f} s ({n_struct/parse_struct:,.0f} pkt/s parse)\n")

    # 3. dpkt
    print("3. dpkt parser (src/packet.py:parse_packet)...")
    n_dpkt, t_dpkt = benchmark_dpkt(args.pcap, args.limit)
    parse_dpkt = t_dpkt - t_read
    print(f"   {n_dpkt:>10,} packets  {t_dpkt:7.3f} s  ({n_dpkt/t_dpkt:,.0f} pkt/s)")
    print(f"   Parse-only: {parse_dpkt:7.3f} s ({n_dpkt/parse_dpkt:,.0f} pkt/s parse)\n")

    # Summary
    print(f"{'='*80}")
    print("Parse Performance Summary:")
    print(f"  struct:    {n_struct/parse_struct:>8,.0f} pkt/s")
    print(f"  dpkt:      {n_dpkt/parse_dpkt:>8,.0f} pkt/s")
    print(f"  Ratio (dpkt/struct): {(n_dpkt/parse_dpkt) / (n_struct/parse_struct):.2f}x")
    print(f"\nNote: Scapy baseline (~5.5k pkt/s) cannot be run here since Scapy")
    print(f"      dissection has been removed from the codebase.")
    print(f"      See profile_memory.py for full-pipeline timing.")
    print(f"{'='*80}\n")


if __name__ == "__main__":
    main()
