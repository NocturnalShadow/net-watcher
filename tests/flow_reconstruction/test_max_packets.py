"""
Integration tests for flows terminated by the max-packets cap.

When an active flow reaches flow_max_packets, it is terminated with reason
'packets_count' and the next packet of the same 5-tuple starts a fresh flow.
The cap applies to both TCP (process_tcp) and UDP (process_universal).

Scenarios:
  TestTCPMaxPacketsSplit — one TCP connection cut into thirds at the cap; the
                           continuation flows must reconstruct correctly.
  TestUDPMaxPacketsSplit — one UDP flow cut at the cap, with a continuation.
"""
import pytest

from helpers import make_tcp_packet, make_udp_packet, write_pcap, run_reconstruction


# ---------------------------------------------------------------------------
# Scenario: TCP connection split by the max-packets cap (flow_max_packets=5)
#
# A single client<->server connection (no FIN/RST) sends 12 packets. The cap
# slices it into three flows; every packet of the connection must land in
# exactly one flow, in order, with the same 5-tuple.
#
#   #   t     dir    flags  payload   -> flow
#   1   0.0   c->s   S        0        flow 1
#   2   0.1   s->c   SA       0        flow 1
#   3   0.2   c->s   A        0        flow 1
#   4   0.3   s->c   A        0        flow 1
#   5   0.4   c->s   PA      20        flow 1   (5th packet -> cap reached)
#   6   0.5   c->s   PA     100        flow 2   (cuts flow 1 = packets_count)
#   7   0.6   s->c   PA     200        flow 2
#   8   0.7   c->s   PA     300        flow 2
#   9   0.8   s->c   A        0        flow 2
#   10  0.9   c->s   PA     400        flow 2   (5th packet -> cap reached)
#   11  1.0   c->s   PA    1000        flow 3   (cuts flow 2 = packets_count)
#   12  1.1   s->c   A        0        flow 3
#   <PCAP ends>                                  flow 3 = unknown
# ---------------------------------------------------------------------------

_T_CLIENT = "10.0.5.1"
_T_SERVER = "10.0.5.2"
_T_SPORT  = 5555
_T_DPORT  = 80


def _build_tcp_max_packets_pcap(path):
    c, s, sp, dp = _T_CLIENT, _T_SERVER, _T_SPORT, _T_DPORT
    write_pcap([
        make_tcp_packet(c, s, sp, dp, "S",  seq=100, ack=0,   t=0.0),
        make_tcp_packet(s, c, dp, sp, "SA", seq=200, ack=101, t=0.1),
        make_tcp_packet(c, s, sp, dp, "A",  seq=101, ack=201, t=0.2),
        make_tcp_packet(s, c, dp, sp, "A",  seq=201, ack=101, t=0.3),
        make_tcp_packet(c, s, sp, dp, "PA", seq=101, ack=201, payload=b"X" * 20,  t=0.4),
        make_tcp_packet(c, s, sp, dp, "PA", seq=121, ack=201, payload=b"A" * 100, t=0.5),
        make_tcp_packet(s, c, dp, sp, "PA", seq=201, ack=221, payload=b"B" * 200, t=0.6),
        make_tcp_packet(c, s, sp, dp, "PA", seq=221, ack=401, payload=b"C" * 300, t=0.7),
        make_tcp_packet(s, c, dp, sp, "A",  seq=401, ack=521, t=0.8),
        make_tcp_packet(c, s, sp, dp, "PA", seq=521, ack=401, payload=b"D" * 400, t=0.9),
        make_tcp_packet(c, s, sp, dp, "PA", seq=921, ack=401, payload=b"E" * 1000, t=1.0),
        make_tcp_packet(s, c, dp, sp, "A",  seq=401, ack=1921, t=1.1),
    ], path)


class TestTCPMaxPacketsSplit:
    """A 12-packet TCP connection split into three flows by flow_max_packets=5."""

    @pytest.fixture(scope="class")
    def flows(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "tcp_max_packets.pcap")
        _build_tcp_max_packets_pcap(pcap)
        result = run_reconstruction(pcap, flow_max_packets=5)
        assert len(result) == 3, f"Expected 3 flows, got {len(result)}"
        # Order by first-packet time so flow_1/2/3 are deterministic.
        return sorted(result, key=lambda f: f["timestamp"])

    @pytest.fixture(scope="class")
    def flow_1(self, flows):
        return flows[0]

    @pytest.fixture(scope="class")
    def flow_2(self, flows):
        return flows[1]

    @pytest.fixture(scope="class")
    def flow_3(self, flows):
        return flows[2]

    # --- flow 1: first slice, cut at the cap ---

    def test_flow_1_termination_reason(self, flow_1):
        assert flow_1["termination_reason"] == "MAX_PACKETS"

    def test_flow_1_packets_count(self, flow_1):
        assert flow_1["packets_count"] == 5

    def test_flow_1_payload_bytes_total(self, flow_1):
        assert flow_1["payload_bytes_total"] == 20

    def test_flow_1_syn_count(self, flow_1):
        assert flow_1["syn_count"] == 2

    # --- flow 2: middle slice, also cut at the cap ---

    def test_flow_2_termination_reason(self, flow_2):
        assert flow_2["termination_reason"] == "MAX_PACKETS"

    def test_flow_2_packets_count(self, flow_2):
        assert flow_2["packets_count"] == 5

    def test_flow_2_payload_bytes_total(self, flow_2):
        assert flow_2["payload_bytes_total"] == 1000  # 100+200+300+0+400

    def test_flow_2_no_syn(self, flow_2):
        # Continuation must not inherit a SYN it never saw.
        assert flow_2["syn_count"] == 0

    # --- flow 3: final slice, ends with the PCAP ---

    def test_flow_3_termination_reason(self, flow_3):
        assert flow_3["termination_reason"] == "UNKNOWN"

    def test_flow_3_packets_count(self, flow_3):
        assert flow_3["packets_count"] == 2

    def test_flow_3_payload_bytes_total(self, flow_3):
        assert flow_3["payload_bytes_total"] == 1000

    def test_flow_3_no_syn(self, flow_3):
        assert flow_3["syn_count"] == 0

    # --- whole connection preserved across the splits ---

    def test_total_packets_preserved(self, flows):
        assert sum(f["packets_count"] for f in flows) == 12

    def test_same_5_tuple(self, flows):
        for f in flows:
            assert (f["src_ip"], f["dst_ip"], f["src_port"], f["dst_port"], f["protocol"]) \
                == (_T_CLIENT, _T_SERVER, _T_SPORT, _T_DPORT, 6)


# ---------------------------------------------------------------------------
# Scenario: the cap also bounds a FINALIZING flow (flow_max_packets=5)
#
# A connection sends FIN early, then is flooded with trailing packets *within*
# the grace window. The cap must insta-terminate it at max_packets (bypassing
# the grace period) so the post-FIN flow can't grow unbounded.
#
#   #   t     dir    flags  -> flow
#   1   0.0   c->s   S       flow 1
#   2   0.01  s->c   SA      flow 1
#   3   0.02  c->s   FA      flow 1   (FIN -> flow 1 starts finalizing)
#   4   0.03  s->c   A       flow 1   (appended during grace)
#   5   0.04  s->c   A       flow 1   (5th packet -> cap reached)
#   6   0.05  c->s   A       flow 2   (cuts finalizing flow 1 = MAX_PACKETS)
#   7   0.06  s->c   A       flow 2
#   <PCAP ends>                        flow 2 = UNKNOWN
#
# All timestamps are < 1.0 s after the FIN (t=0.02), so the grace terminator
# does NOT fire first — the cap is what cuts flow 1.
# ---------------------------------------------------------------------------

_F_CLIENT = "10.0.7.1"
_F_SERVER = "10.0.7.2"
_F_SPORT  = 6666
_F_DPORT  = 80


def _build_tcp_finalizing_cap_pcap(path):
    c, s, sp, dp = _F_CLIENT, _F_SERVER, _F_SPORT, _F_DPORT
    write_pcap([
        make_tcp_packet(c, s, sp, dp, "S",  seq=100, ack=0,   t=0.0),
        make_tcp_packet(s, c, dp, sp, "SA", seq=200, ack=101, t=0.01),
        make_tcp_packet(c, s, sp, dp, "FA", seq=101, ack=201, t=0.02),
        make_tcp_packet(s, c, dp, sp, "A",  seq=201, ack=102, t=0.03),
        make_tcp_packet(s, c, dp, sp, "A",  seq=201, ack=102, t=0.04),
        make_tcp_packet(c, s, sp, dp, "A",  seq=102, ack=201, t=0.05),
        make_tcp_packet(s, c, dp, sp, "A",  seq=201, ack=102, t=0.06),
    ], path)


class TestTCPMaxPacketsFinalizingFlow:
    """A finalizing (post-FIN) TCP flow is still cut at flow_max_packets=5."""

    @pytest.fixture(scope="class")
    def flows(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "tcp_finalizing_cap.pcap")
        _build_tcp_finalizing_cap_pcap(pcap)
        result = run_reconstruction(pcap, flow_max_packets=5)
        assert len(result) == 2, f"Expected 2 flows, got {len(result)}"
        return sorted(result, key=lambda f: f["timestamp"])

    @pytest.fixture(scope="class")
    def flow_1(self, flows):
        return flows[0]

    @pytest.fixture(scope="class")
    def flow_2(self, flows):
        return flows[1]

    def test_flow_1_capped_not_fin(self, flow_1):
        # Even though it saw a FIN and was finalizing, the cap takes over.
        assert flow_1["termination_reason"] == "MAX_PACKETS"

    def test_flow_1_saw_the_fin(self, flow_1):
        # Confirms it was genuinely a finalizing flow when the cap cut it.
        assert flow_1["fin_count"] == 1

    def test_flow_1_packets_count(self, flow_1):
        assert flow_1["packets_count"] == 5

    def test_flow_2_termination_reason(self, flow_2):
        assert flow_2["termination_reason"] == "UNKNOWN"

    def test_flow_2_packets_count(self, flow_2):
        assert flow_2["packets_count"] == 2

    def test_total_packets_preserved(self, flows):
        assert sum(f["packets_count"] for f in flows) == 7

    def test_same_5_tuple(self, flows):
        for f in flows:
            assert (f["src_ip"], f["dst_ip"], f["src_port"], f["dst_port"], f["protocol"]) \
                == (_F_CLIENT, _F_SERVER, _F_SPORT, _F_DPORT, 6)


# ---------------------------------------------------------------------------
# Scenario: UDP flow split by the max-packets cap (flow_max_packets=5)
#
# An 8-packet UDP flow is cut once at the cap into two flows.
#
#   #   t     dir    payload  -> flow
#   1   0.0   c->s    40       flow 1
#   2   0.1   s->c    50       flow 1
#   3   0.2   c->s    60       flow 1
#   4   0.3   s->c    70       flow 1
#   5   0.4   c->s    80       flow 1   (5th packet -> cap reached)
#   6   0.5   c->s    90       flow 2   (cuts flow 1 = packets_count)
#   7   0.6   s->c   100       flow 2
#   8   0.7   c->s   110       flow 2
#   <PCAP ends>                          flow 2 = unknown
# ---------------------------------------------------------------------------

_U_CLIENT = "10.0.6.1"
_U_SERVER = "10.0.6.2"
_U_SPORT  = 55555
_U_DPORT  = 9999   # generic port — avoids Scapy auto-dissection


def _build_udp_max_packets_pcap(path):
    c, s, sp, dp = _U_CLIENT, _U_SERVER, _U_SPORT, _U_DPORT
    write_pcap([
        make_udp_packet(c, s, sp, dp, payload=b"A" * 40,  t=0.0),
        make_udp_packet(s, c, dp, sp, payload=b"B" * 50,  t=0.1),
        make_udp_packet(c, s, sp, dp, payload=b"C" * 60,  t=0.2),
        make_udp_packet(s, c, dp, sp, payload=b"D" * 70,  t=0.3),
        make_udp_packet(c, s, sp, dp, payload=b"E" * 80,  t=0.4),
        make_udp_packet(c, s, sp, dp, payload=b"F" * 90,  t=0.5),
        make_udp_packet(s, c, dp, sp, payload=b"G" * 100, t=0.6),
        make_udp_packet(c, s, sp, dp, payload=b"H" * 110, t=0.7),
    ], path)


class TestUDPMaxPacketsSplit:
    """An 8-packet UDP flow split into two flows by flow_max_packets=5."""

    @pytest.fixture(scope="class")
    def flows(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "udp_max_packets.pcap")
        _build_udp_max_packets_pcap(pcap)
        result = run_reconstruction(pcap, filter="udp", flow_max_packets=5)
        assert len(result) == 2, f"Expected 2 flows, got {len(result)}"
        return sorted(result, key=lambda f: f["timestamp"])

    @pytest.fixture(scope="class")
    def flow_1(self, flows):
        return flows[0]

    @pytest.fixture(scope="class")
    def flow_2(self, flows):
        return flows[1]

    def test_flow_1_termination_reason(self, flow_1):
        assert flow_1["termination_reason"] == "MAX_PACKETS"

    def test_flow_1_packets_count(self, flow_1):
        assert flow_1["packets_count"] == 5

    def test_flow_1_payload_bytes_total(self, flow_1):
        assert flow_1["payload_bytes_total"] == 300  # 40+50+60+70+80

    def test_flow_1_protocol(self, flow_1):
        assert flow_1["protocol"] == 17

    def test_flow_2_termination_reason(self, flow_2):
        assert flow_2["termination_reason"] == "UNKNOWN"

    def test_flow_2_packets_count(self, flow_2):
        assert flow_2["packets_count"] == 3

    def test_flow_2_payload_bytes_total(self, flow_2):
        assert flow_2["payload_bytes_total"] == 300  # 90+100+110

    def test_total_packets_preserved(self, flows):
        assert sum(f["packets_count"] for f in flows) == 8

    def test_same_5_tuple(self, flows):
        for f in flows:
            assert (f["src_ip"], f["dst_ip"], f["src_port"], f["dst_port"], f["protocol"]) \
                == (_U_CLIENT, _U_SERVER, _U_SPORT, _U_DPORT, 17)
