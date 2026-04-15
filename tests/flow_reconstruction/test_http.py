"""
Integration tests for HTTP flow reconstruction.

Scenarios:
  TestHTTPFlow — HTTP/1.1 GET with directional WScale features
"""
import math

import pytest
from scapy.all import Ether, IP, TCP

from helpers import make_tcp_packet, write_pcap, run_reconstruction


# ---------------------------------------------------------------------------
# Scenario: HTTP GET request over TCP
#
# HTTP/1.1 GET (380 B) followed by a split response (800 B + 420 B).
# Exercises directional window features and the WScale option code path.
#
# Client: window=1024, WScale=6  →  effective 1024×64  =   65 536
# Server: window=2048, WScale=7  →  effective 2048×128 =  262 144
#
#   t=0.000  SYN            client→server  window=1024, WScale=6
#   t=0.010  SYN-ACK        server→client  window=2048, WScale=7
#   t=0.020  ACK            client→server
#   t=0.025  PSH+ACK(380B)  client→server  HTTP GET /index.html
#   t=0.045  ACK            server→client  20 ms server processing
#   t=0.065  PSH+ACK(800B)  server→client  HTTP 200 OK + body part 1
#   t=0.070  PSH+ACK(420B)  server→client  body continuation
#   t=0.080  ACK            client→server
#   t=1.080  FIN+ACK        client→server  ← finalization_time=1.080
#   t=1.090  FIN+ACK        server→client
#   t=2.090  ACK            client→server  ← 2.090-1.080=1.010>1.0 ✓
# ---------------------------------------------------------------------------

_HTTP_CLIENT  = "10.0.2.1"
_HTTP_SERVER  = "10.0.2.2"
_HTTP_SPORT   = 54321
_HTTP_DPORT   = 80
_HTTP_REQUEST = b"A" * 380   # proxy for GET + headers
_HTTP_RESP_1  = b"B" * 800   # 200 OK + body part 1
_HTTP_RESP_2  = b"B" * 420   # body continuation


def _build_http_pcap(path):
    """
    11-packet HTTP/1.1 GET over TCP. SYN and SYN-ACK carry WScale options
    (built inline because make_tcp_packet does not expose TCP options).
    """
    c, s = _HTTP_CLIENT, _HTTP_SERVER
    sp, dp = _HTTP_SPORT, _HTTP_DPORT
    mc, ms = "00:00:00:00:00:01", "00:00:00:00:00:02"

    def _syn(src_mac, dst_mac, src_ip, dst_ip, sport, dport, flags,
             seq, ack, window, wscale, t):
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack,
                  window=window, options=[("WScale", wscale)])
        )
        pkt.time = t
        return pkt

    write_pcap([
        _syn(mc, ms, c, s, sp, dp, "S",  seq=1000, ack=0,    window=1024, wscale=6, t=0.000),
        _syn(ms, mc, s, c, dp, sp, "SA", seq=5000, ack=1001, window=2048, wscale=7, t=0.010),
        make_tcp_packet(c, s, sp, dp, "A",  seq=1001, ack=5001, window=1024, t=0.020),
        make_tcp_packet(c, s, sp, dp, "PA", seq=1001, ack=5001, window=1024, payload=_HTTP_REQUEST, t=0.025),
        make_tcp_packet(s, c, dp, sp, "A",  seq=5001, ack=1381, window=2048, t=0.045),
        make_tcp_packet(s, c, dp, sp, "PA", seq=5001, ack=1381, window=2048, payload=_HTTP_RESP_1,  t=0.065),
        make_tcp_packet(s, c, dp, sp, "PA", seq=5801, ack=1381, window=2048, payload=_HTTP_RESP_2,  t=0.070),
        make_tcp_packet(c, s, sp, dp, "A",  seq=1381, ack=6221, window=1024, t=0.080),
        make_tcp_packet(c, s, sp, dp, "FA", seq=1381, ack=6221, window=1024, t=1.080),
        make_tcp_packet(s, c, dp, sp, "FA", seq=6221, ack=1382, window=2048, t=1.090),
        make_tcp_packet(c, s, sp, dp, "A",  seq=1382, ack=6222, window=1024, t=2.090),
    ], path)


class TestHTTPFlow:
    """
    HTTP/1.1 GET request fully contained in one TCP flow.

    Verifies:
    - Directional window features: client and server advertise different raw
      window sizes and WScale factors (fwd_* ≠ bwd_*).
    - Payload asymmetry: small request (380 B) vs. split response (800+420 B).
    - Interarrival times: the 20 ms server gap and 1 s idle periods show up
      in min/max.
    """

    @pytest.fixture(scope="class")
    def flow(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "http.pcap")
        _build_http_pcap(pcap)
        result = run_reconstruction(pcap)
        assert len(result) == 1, f"Expected 1 flow, got {len(result)}"
        return result[0]

    def test_termination_reason(self, flow):
        assert flow["termination_reason"] == "FIN"

    def test_protocol(self, flow):
        assert flow["protocol"] == 6

    def test_dst_port(self, flow):
        assert flow["dst_port"] == 80

    def test_packets_count(self, flow):
        assert flow["packets_count"] == 11

    # --- payload stats ---

    def test_payload_bytes_total(self, flow):
        assert flow["payload_bytes_total"] == 1600  # 380 + 800 + 420

    def test_payload_bytes_min(self, flow):
        assert flow["payload_bytes_min"] == 0  # 8 zero-payload packets

    def test_payload_bytes_max(self, flow):
        assert flow["payload_bytes_max"] == 800  # largest response segment

    def test_payload_bytes_min_nonzero(self, flow):
        assert flow["payload_bytes_min_nonzero"] == 380  # the GET request

    def test_payload_bytes_avg_nonzero(self, flow):
        assert flow["payload_bytes_avg_nonzero"] == pytest.approx(1600 / 3)

    def test_payload_bytes_std_nonzero(self, flow):
        # stdev([380, 800, 420])
        assert flow["payload_bytes_std_nonzero"] == pytest.approx(math.sqrt(967200 / 18))

    # --- TCP flags ---

    def test_syn_count(self, flow):
        assert flow["syn_count"] == 2  # SYN + SYN-ACK

    def test_fin_count(self, flow):
        assert flow["fin_count"] == 2

    def test_rst_count(self, flow):
        assert flow["rst_count"] == 0

    def test_ack_count(self, flow):
        assert flow["ack_count"] == 10  # all except bare SYN

    def test_psh_count(self, flow):
        assert flow["psh_count"] == 3  # GET request + two response segments

    # --- timing ---

    def test_duration_s(self, flow):
        assert flow["duration_s"] == pytest.approx(2.090)

    def test_interarrival_time_s_min(self, flow):
        # Smallest gap: 0.005 s between the two response PSH+ACKs (t=0.065→0.070)
        assert flow["interarrival_time_s_min"] == pytest.approx(0.005)

    def test_interarrival_time_s_max(self, flow):
        # Largest gap: 1.000 s (idle before FIN and before final ACK)
        assert flow["interarrival_time_s_max"] == pytest.approx(1.000)

    # --- directional window features ---

    def test_fwd_window_scaling_factor(self, flow):
        assert flow["fwd_window_scaling_factor"] == 64   # 2^6

    def test_bwd_window_scaling_factor(self, flow):
        assert flow["bwd_window_scaling_factor"] == 128  # 2^7

    def test_fwd_initial_window_size(self, flow):
        assert flow["fwd_initial_window_size"] == 1024

    def test_bwd_initial_window_size(self, flow):
        assert flow["bwd_initial_window_size"] == 2048

    def test_fwd_window_size_avg(self, flow):
        assert flow["fwd_window_size_avg"] == pytest.approx(65536.0)   # 1024 × 64

    def test_bwd_window_size_avg(self, flow):
        assert flow["bwd_window_size_avg"] == pytest.approx(262144.0)  # 2048 × 128
