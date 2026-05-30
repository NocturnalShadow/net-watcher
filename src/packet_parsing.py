"""Packet parsing for flow reconstruction.

Parsing flow:
    Raw Packet --parse_packet--> Packet --trim_packet--> PacketData

`Packet` is the full per-packet parse result, including the 5-tuple used to key
flows. `PacketData` is the per-packet fields kept after the 5-tuple is dropped.
"""
import socket
import struct
from dataclasses import dataclass

import dpkt

from enums import Direction, TCPFlag


@dataclass(slots=True)
class PacketData:
    """Per-packet fields kept after trimming the 5-tuple."""
    time: float
    payload_bytes: int
    direction: object
    tcp_flags: int          # 0 for non-TCP
    tcp_window: int         # 0 for non-TCP
    tcp_wscale: int         # WScale from SYN options; 1 if absent or non-TCP


@dataclass(slots=True)
class Packet:
    """Full per-packet parse result, including the flow-keying 5-tuple."""
    time: float
    src_ip: str
    dst_ip: str
    sport: int
    dport: int
    protocol: int
    payload_bytes: int
    tcp_flags: int          # 0 for non-TCP
    tcp_window: int         # 0 for non-TCP
    tcp_wscale: int         # WScale from SYN options; 1 if absent or non-TCP
    direction: object = Direction.UNKNOWN


def resolve_link_layer_dissector(data_link_type):
    """Return the dpkt link-layer dissector for a libpcap DLT, or raise error."""
    # See https://www.tcpdump.org/linktypes.html for DLT all values.
    DLT_NULL = 0    # BSD loopback encapsulation
    DLT_EN10MB = 1  # Ethernet (10Mb, 100Mb, 1000Mb, and up)
    link_layer_dissector = {
        DLT_NULL: dpkt.loopback.Loopback,
        DLT_EN10MB: dpkt.ethernet.Ethernet,
    }

    try:
        return link_layer_dissector[data_link_type]
    except KeyError:
        raise ValueError(f"Unsupported link-layer type (DLT {data_link_type}); "
                         f"supported: {sorted(link_layer_dissector)}")


def parse_packet(raw_packet_data, timestamp, link_layer_dissector=dpkt.ethernet.Ethernet):
    """Parse raw link-layer bytes into a Packet (TCP/UDP only), or None."""
    try:
        ip = link_layer_dissector(raw_packet_data).data
        if isinstance(ip, dpkt.llc.LLC):  # 802.3 LLC/SNAP -> unwrap to L3
            ip = ip.data
        if isinstance(ip, dpkt.ip.IP):
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            protocol = ip.p
        elif isinstance(ip, dpkt.ip6.IP6):
            src_ip = socket.inet_ntop(socket.AF_INET6, ip.src)
            dst_ip = socket.inet_ntop(socket.AF_INET6, ip.dst)
            protocol = ip.nxt
        else:
            return None

        l4 = ip.data
        if isinstance(l4, dpkt.tcp.TCP):
            flags = l4._off_flags & 0x01FF  # 9-bit flags, including NS
            tcp_wscale = 1
            if (flags & TCPFlag.SYN) and l4.opts:
                for kind, val in dpkt.tcp.parse_opts(l4.opts):
                    if kind == dpkt.tcp.TCP_OPT_WSCALE and val:
                        tcp_wscale = 2 ** val[0]
                        break
            return Packet(
                time=float(timestamp), src_ip=src_ip, dst_ip=dst_ip,
                sport=l4.sport, dport=l4.dport, protocol=protocol,
                payload_bytes=len(l4.data),
                tcp_flags=flags, tcp_window=l4.win, tcp_wscale=tcp_wscale,
            )
        if isinstance(l4, dpkt.udp.UDP):
            return Packet(
                time=float(timestamp), src_ip=src_ip, dst_ip=dst_ip,
                sport=l4.sport, dport=l4.dport, protocol=protocol,
                payload_bytes=len(l4.data),
                tcp_flags=0, tcp_window=0, tcp_wscale=1,
            )
        return None
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, IndexError, struct.error):
        return None


def trim_packet(packet):
    """Drop the 5-tuple from a Packet, returning a PacketData."""
    return PacketData(
        time=packet.time,
        payload_bytes=packet.payload_bytes,
        direction=packet.direction,
        tcp_flags=packet.tcp_flags,
        tcp_window=packet.tcp_window,
        tcp_wscale=packet.tcp_wscale,
    )
