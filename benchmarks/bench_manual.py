"""Benchmark: read + parse packets WITHOUT Scapy, to expose Scapy's overhead.

Two non-Scapy parsers, each producing the exact same record tuple as
bench_scapy.py:
  * struct : hand-rolled struct.unpack of Ethernet / IPv4 / IPv6 / TCP / UDP.
  * dpkt   : the dpkt library's dissectors.

Each parser is timed in two passes (read-only vs read+parse) so parse-only
cost is isolated, same as bench_scapy.py.

--verify runs all three parsers (struct, dpkt, Scapy) over the first N packets
and asserts they produce identical records -- otherwise the speed comparison is
meaningless.

Only classic little-endian/​big-endian libpcap with Ethernet linktype is
supported by the struct reader (that's our dataset). IPv6 extension headers are
not walked (matches the production reader's behavior).

Usage:
    venv/Scripts/python benchmarks/bench_manual.py [pcap] [--limit N] [--verify N]
"""
import socket
import struct
import sys

import dpkt

import bench_common as bc

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
VLAN_TAGS = (0x8100, 0x88A8)


# ---------------------------------------------------------------------------
# Classic-pcap record reader (struct only; no Scapy, no dpkt)
# ---------------------------------------------------------------------------
def iter_pcap(path):
    """Yield (timestamp, packet_bytes) from a classic libpcap file."""
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
        if linktype != 1:
            raise ValueError(f"Expected Ethernet linktype 1, got {linktype}")

        rec_hdr = struct.Struct(endian + "IIII")
        divisor = 1_000_000_000 if ns else 1_000_000
        read = f.read
        while True:
            hdr = read(16)
            if len(hdr) < 16:
                return
            ts_sec, ts_sub, incl_len, _orig = rec_hdr.unpack(hdr)
            data = read(incl_len)
            if len(data) < incl_len:
                return
            yield ts_sec + ts_sub / divisor, data


# ---------------------------------------------------------------------------
# struct parser
# ---------------------------------------------------------------------------
_u16 = struct.Struct("!H")


def parse_struct(data, ts):
    """Produce the production record tuple from raw Ethernet bytes, or None."""
    try:
        n = len(data)
        if n < 14:
            return None
        ethertype = _u16.unpack_from(data, 12)[0]
        off = 14
        while ethertype in VLAN_TAGS:
            ethertype = _u16.unpack_from(data, off + 2)[0]
            off += 4
        # IEEE 802.3: field <= 1500 is a length, not an ethertype. Decode the
        # LLC/SNAP shim (aa aa 03 + 3-byte OUI) to recover the real ethertype.
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
            proto = data[off + 6]  # next header; ext headers not walked
            src_ip = socket.inet_ntop(socket.AF_INET6, data[off + 8:off + 24])
            dst_ip = socket.inet_ntop(socket.AF_INET6, data[off + 24:off + 40])
            transport_off = off + 40
            ip_end = min(off + 40 + payload_len, n)
        else:
            return None

        if proto == bc.PROTO_TCP:
            sport = _u16.unpack_from(data, transport_off)[0]
            dport = _u16.unpack_from(data, transport_off + 2)[0]
            off_x2 = data[transport_off + 12]
            thl = (off_x2 >> 4) * 4
            # 9-bit flags incl. NS, to match Scapy's int(tcp.flags)
            flags = ((off_x2 & 0x01) << 8) | data[transport_off + 13]
            window = _u16.unpack_from(data, transport_off + 14)[0]
            payload_bytes = max(0, ip_end - (transport_off + thl))
            wscale = 1
            if flags & 0x02:  # SYN -> look for WScale option
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
            return (ts, src_ip, dst_ip, sport, dport, proto,
                    payload_bytes, flags, window, wscale)

        if proto == bc.PROTO_UDP:
            sport = _u16.unpack_from(data, transport_off)[0]
            dport = _u16.unpack_from(data, transport_off + 2)[0]
            payload_bytes = max(0, (ip_end - transport_off) - 8)
            return (ts, src_ip, dst_ip, sport, dport, proto,
                    payload_bytes, 0, 0, 1)

        return None
    except (IndexError, struct.error, OSError):
        return None


# ---------------------------------------------------------------------------
# dpkt parser
# ---------------------------------------------------------------------------
def parse_dpkt(data, ts):
    try:
        eth = dpkt.ethernet.Ethernet(data)
        ip = eth.data
        if isinstance(ip, dpkt.llc.LLC):  # 802.3 LLC/SNAP -> unwrap to L3
            ip = ip.data
        if isinstance(ip, dpkt.ip.IP):
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            proto = ip.p
        elif isinstance(ip, dpkt.ip6.IP6):
            src_ip = socket.inet_ntop(socket.AF_INET6, ip.src)
            dst_ip = socket.inet_ntop(socket.AF_INET6, ip.dst)
            proto = ip.nxt
        else:
            return None

        l4 = ip.data
        if isinstance(l4, dpkt.tcp.TCP):
            flags = l4._off_flags & 0x01FF  # 9-bit flags incl. NS, matches Scapy
            wscale = 1
            if flags & 0x02 and l4.opts:
                for kind, val in dpkt.tcp.parse_opts(l4.opts):
                    if kind == dpkt.tcp.TCP_OPT_WSCALE and val:
                        wscale = 2 ** val[0]
                        break
            return (ts, src_ip, dst_ip, l4.sport, l4.dport, proto,
                    len(l4.data), flags, l4.win, wscale)
        if isinstance(l4, dpkt.udp.UDP):
            return (ts, src_ip, dst_ip, l4.sport, l4.dport, proto,
                    len(l4.data), 0, 0, 1)
        return None
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, IndexError, struct.error):
        return None


# ---------------------------------------------------------------------------
# Timing passes
# ---------------------------------------------------------------------------
def run_method(name, path, limit, parse_fn):
    # read-only pass
    with bc.Timer() as t_read:
        n_read = 0
        for _ts, _data in iter_pcap(path):
            n_read += 1
            if limit and n_read >= limit:
                break

    # read+parse pass
    with bc.Timer() as t_parse:
        n = 0
        last = None
        for ts, data in iter_pcap(path):
            rec = parse_fn(data, ts)
            if rec is not None:
                last = rec
                n += 1
            if limit and n >= limit:
                break
    bc.report(name, n_read, t_read.elapsed, n, t_parse.elapsed)
    return last


# ---------------------------------------------------------------------------
# Cross-parser verification
# ---------------------------------------------------------------------------
def verify(path, count):
    from scapy.all import Ether
    from bench_scapy import parse_record as parse_scapy

    mismatches = 0
    checked = 0
    for ts, data in iter_pcap(path):
        if checked >= count:
            break
        rs = parse_struct(data, ts)
        rd = parse_dpkt(data, ts)
        try:
            rc = parse_scapy(Ether(data), ts)
        except Exception:
            rc = None
        checked += 1
        if rs == rd == rc:
            continue
        # ignore packets nobody records (all None)
        if rs is None and rd is None and rc is None:
            continue
        mismatches += 1
        if mismatches <= 10:
            print(f"\nMISMATCH @pkt {checked}:")
            print(f"  struct: {rs}")
            print(f"  dpkt  : {rd}")
            print(f"  scapy : {rc}")
    print(f"\nVerify: {checked} packets checked, {mismatches} mismatches.")
    return mismatches == 0


def main():
    parser = bc.make_arg_parser(__doc__)
    parser.add_argument("--verify", type=int, metavar="N", default=0,
                        help="Cross-check struct/dpkt/Scapy on first N packets, then exit.")
    args = parser.parse_args()

    if args.verify:
        ok = verify(args.pcap, args.verify)
        sys.exit(0 if ok else 1)

    run_method("struct (hand-rolled)", args.pcap, args.limit, parse_struct)
    run_method("dpkt", args.pcap, args.limit, parse_dpkt)


if __name__ == "__main__":
    main()
