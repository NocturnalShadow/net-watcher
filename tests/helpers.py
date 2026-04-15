"""
Test helpers for net-watcher integration tests.

src/ is added to sys.path by conftest.py, so FlowReconstructor can be imported directly.
"""
import queue

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

from flow_reconstruction import FlowReconstructor


_CLIENT_MAC = "00:00:00:00:00:01"
_SERVER_MAC = "00:00:00:00:00:02"


def make_tcp_packet(src_ip, dst_ip, sport, dport, flags, seq, ack,
                    window=65535, payload=b"", t=0.0):
    """Build an Ether/IP/TCP[/Raw] packet with the given pcap timestamp."""
    pkt = (
        Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=window)
    )
    if payload:
        pkt = pkt / Raw(load=payload)
    pkt.time = t
    return pkt


def make_udp_packet(src_ip, dst_ip, sport, dport, payload=b"", t=0.0):
    """Build an Ether/IP/UDP[/Raw] packet with the given pcap timestamp."""
    pkt = (
        Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=sport, dport=dport)
    )
    if payload:
        pkt = pkt / Raw(load=payload)
    pkt.time = t
    return pkt


def write_pcap(packets, path):
    """Write a list of Scapy packets to a PCAP file."""
    wrpcap(path, packets)


def run_reconstruction(pcap_path, **kwargs):
    """
    Run FlowReconstructor in offline TCP mode on pcap_path.

    Overrides tcp_termination_check_interval to 0.1 s (from the default 5 s)
    to keep test wall-clock time under 1 second per test. The grace period is
    left at the default 1.0 s — PCAP timestamps must be designed so that
    (last_packet_pcap_time - fin_pcap_time) > 1.0 s.

    Returns a list of reconstructed flow dicts.
    """
    output_queue = queue.Queue()
    kwargs.setdefault("collect_stats", False)  # suppress stat logs in tests
    reconstructor = FlowReconstructor(output_queue=output_queue, **kwargs)
    # Speed-only overrides — do not change any termination logic:
    # - tcp_termination_check_interval: reduces ~5 s real-time wait for FIN/RST flows to ~100 ms
    # - timeout_termination_check_interval: runs idle/activity timeout checks every 0.5 s of
    #   pcap time instead of every 60 s, so synthetic PCAPs don't need multi-minute gaps
    reconstructor.tcp_termination_check_interval = 0.1
    reconstructor.timeout_termination_check_interval = 0.5
    with reconstructor:
        reconstructor.offline(pcap_path)

    flows = []
    while not output_queue.empty():
        flows.append(output_queue.get_nowait())
    return flows
