"""
Integration tests for TCP flows terminated by timeout.

Scenarios:
  TestActivityTimeoutTermination — long-running connection split at activity timeout
  TestIdleTimeoutTermination     — flow silent for > idle_timeout
"""
import pytest

from helpers import make_tcp_packet, write_pcap, run_reconstruction


# ---------------------------------------------------------------------------
# Scenario: Activity timeout
#
# A connection whose total duration exceeds flow_activity_timeout is terminated
# and restarted as a new flow on the next incoming packet.
#
# Flow 1 (activity_timeout): packets at t=0.0–6.0
# Flow 2 (FIN):              continuation at t=6.1–8.5
#
#   t=0.0  SYN
#   t=0.1  SYN-ACK
#   t=0.2  ACK
#   t=0.3  PSH+ACK 15B
#   t=0.4  ACK
#   t=6.0  PSH+ACK 25B  ← added to flow 1; activity_time=6.0>5 → flow 1 terminated
#   t=6.1  ACK          ← no active flow → starts flow 2 (reversed 5-tuple)
#   t=7.0  FIN+ACK      ← finalization_time=7.0
#   t=7.5  FIN+ACK
#   t=8.5  ACK          ← 8.5-7.0=1.5>1.0 ✓
# ---------------------------------------------------------------------------

_ACT_CLIENT = "10.0.1.1"
_ACT_SERVER = "10.0.1.2"
_ACT_SPORT  = 3333
_ACT_DPORT  = 80


def _build_activity_timeout_pcap(path):
    c, s, sp, dp = _ACT_CLIENT, _ACT_SERVER, _ACT_SPORT, _ACT_DPORT
    write_pcap([
        make_tcp_packet(c, s, sp, dp, "S",  seq=100, ack=0,   t=0.0),
        make_tcp_packet(s, c, dp, sp, "SA", seq=200, ack=101, t=0.1),
        make_tcp_packet(c, s, sp, dp, "A",  seq=101, ack=201, t=0.2),
        make_tcp_packet(c, s, sp, dp, "PA", seq=101, ack=201, payload=b"X" * 15, t=0.3),
        make_tcp_packet(s, c, dp, sp, "A",  seq=201, ack=116, t=0.4),
        make_tcp_packet(c, s, sp, dp, "PA", seq=116, ack=201, payload=b"Y" * 25, t=6.0),
        make_tcp_packet(s, c, dp, sp, "A",  seq=201, ack=141, t=6.1),
        make_tcp_packet(c, s, sp, dp, "FA", seq=141, ack=201, t=7.0),
        make_tcp_packet(s, c, dp, sp, "FA", seq=201, ack=142, t=7.5),
        make_tcp_packet(c, s, sp, dp, "A",  seq=142, ack=202, t=8.5),
    ], path)


class TestActivityTimeoutTermination:
    """
    A long-running TCP connection is split into two flows at the activity timeout.

    Uses flow_activity_timeout=5 s and flow_idle_timeout=3 s.
    """

    @pytest.fixture(scope="class")
    def flows(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "tcp_activity_timeout.pcap")
        _build_activity_timeout_pcap(pcap)
        result = run_reconstruction(pcap, flow_idle_timeout=3, flow_activity_timeout=5)
        assert len(result) == 2, f"Expected 2 flows, got {len(result)}"
        return {f["termination_reason"]: f for f in result}

    @pytest.fixture(scope="class")
    def flow_1(self, flows):
        """First portion, terminated by activity timeout."""
        return flows["ACTIVITY_TIMEOUT"]

    @pytest.fixture(scope="class")
    def flow_2(self, flows):
        """Continuation after the split, terminated by FIN."""
        return flows["FIN"]

    # --- flow 1 (activity_timeout) ---

    def test_flow_1_termination_reason(self, flow_1):
        assert flow_1["termination_reason"] == "ACTIVITY_TIMEOUT"

    def test_flow_1_packets_count(self, flow_1):
        # SYN, SYN-ACK, ACK, PSH+ACK(15B), ACK, PSH+ACK(25B)
        assert flow_1["packets_count"] == 6

    def test_flow_1_payload_bytes_total(self, flow_1):
        assert flow_1["payload_bytes_total"] == 40  # 15 + 25

    def test_flow_1_duration_s(self, flow_1):
        assert flow_1["duration_s"] == pytest.approx(6.0)

    def test_flow_1_syn_count(self, flow_1):
        assert flow_1["syn_count"] == 2

    def test_flow_1_fin_count(self, flow_1):
        assert flow_1["fin_count"] == 0

    def test_flow_1_psh_count(self, flow_1):
        assert flow_1["psh_count"] == 2

    # --- flow 2 (FIN continuation) ---

    def test_flow_2_termination_reason(self, flow_2):
        assert flow_2["termination_reason"] == "FIN"

    def test_flow_2_packets_count(self, flow_2):
        # ACK(6.1), FIN+ACK(7.0), FIN+ACK(7.5), ACK(8.5)
        assert flow_2["packets_count"] == 4

    def test_flow_2_payload_bytes_total(self, flow_2):
        assert flow_2["payload_bytes_total"] == 0

    def test_flow_2_duration_s(self, flow_2):
        assert flow_2["duration_s"] == pytest.approx(2.4)

    def test_flow_2_fin_count(self, flow_2):
        assert flow_2["fin_count"] == 2


# ---------------------------------------------------------------------------
# Scenario: Idle timeout
#
# A flow receives no traffic for longer than flow_idle_timeout. A probe packet
# from a different 5-tuple advances current_time and triggers the timeout check.
#
#   t=0.0  SYN
#   t=0.1  SYN-ACK
#   t=0.2  ACK
#   t=0.3  PSH+ACK 10B    ← last activity; idle timer starts
#   t=0.4  ACK
#   t=4.0  SYN (probe)    ← idle_time=3.6>3.0 → idle flow terminated
#
# The probe flow (single SYN) ends with 'unknown' in __exit__.
# Two flows are output; tests focus on the idle_timeout flow.
# ---------------------------------------------------------------------------

_IDLE_CLIENT     = "10.0.2.1"
_IDLE_SERVER     = "10.0.2.2"
_IDLE_SPORT      = 4444
_IDLE_DPORT      = 80
_IDLE_PROBE      = "10.0.2.3"
_IDLE_PROBE_PORT = 9999


def _build_idle_timeout_pcap(path):
    c, s, sp, dp = _IDLE_CLIENT, _IDLE_SERVER, _IDLE_SPORT, _IDLE_DPORT
    write_pcap([
        make_tcp_packet(c, s, sp, dp, "S",  seq=100, ack=0,   t=0.0),
        make_tcp_packet(s, c, dp, sp, "SA", seq=200, ack=101, t=0.1),
        make_tcp_packet(c, s, sp, dp, "A",  seq=101, ack=201, t=0.2),
        make_tcp_packet(c, s, sp, dp, "PA", seq=101, ack=201, payload=b"Z" * 10, t=0.3),
        make_tcp_packet(s, c, dp, sp, "A",  seq=201, ack=111, t=0.4),
        make_tcp_packet(_IDLE_PROBE, s, _IDLE_PROBE_PORT, dp, "S", seq=1, ack=0, t=4.0),
    ], path)


class TestIdleTimeoutTermination:
    """
    A flow silent for > flow_idle_timeout is terminated with 'idle_timeout'.

    Uses flow_idle_timeout=3 s and flow_activity_timeout=5 s.
    """

    @pytest.fixture(scope="class")
    def flow(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "tcp_idle_timeout.pcap")
        _build_idle_timeout_pcap(pcap)
        result = run_reconstruction(pcap, flow_idle_timeout=3, flow_activity_timeout=5)
        assert len(result) == 2, f"Expected 2 flows (idle + probe), got {len(result)}"
        idle = next((f for f in result if f["termination_reason"] == "IDLE_TIMEOUT"), None)
        assert idle is not None, "No idle_timeout flow found"
        return idle

    def test_termination_reason(self, flow):
        assert flow["termination_reason"] == "IDLE_TIMEOUT"

    def test_packets_count(self, flow):
        assert flow["packets_count"] == 5

    def test_payload_bytes_total(self, flow):
        assert flow["payload_bytes_total"] == 10

    def test_payload_bytes_max(self, flow):
        assert flow["payload_bytes_max"] == 10

    def test_duration_s(self, flow):
        assert flow["duration_s"] == pytest.approx(0.4)

    def test_syn_count(self, flow):
        assert flow["syn_count"] == 2

    def test_fin_count(self, flow):
        assert flow["fin_count"] == 0

    def test_rst_count(self, flow):
        assert flow["rst_count"] == 0

    def test_psh_count(self, flow):
        assert flow["psh_count"] == 1