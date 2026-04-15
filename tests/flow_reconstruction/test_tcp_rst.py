"""
Integration tests for TCP flows terminated by RST.

Scenarios:
  TestRSTTermination           — server sends RST; flow terminates immediately
  TestBidirectionalRST         — both sides send RST; both packets land in one flow
  TestRepeatedSYNRejected      — each SYN→RST attempt becomes a separate flow
  TestRSTWithTrailingPackets   — packets after RST arrive within the grace period
"""
import pytest

from helpers import make_tcp_packet, write_pcap, run_reconstruction


# ---------------------------------------------------------------------------
# Scenario: Server RST
#
#   t=0.0  SYN          client→server
#   t=0.1  SYN-ACK      server→client
#   t=0.2  ACK          client→server
#   t=0.3  PSH+ACK 20B  client→server
#   t=0.4  RST          server→client  ← flow terminated
# ---------------------------------------------------------------------------

_RST_CLIENT  = "10.0.1.1"
_RST_SERVER  = "10.0.1.2"
_RST_SPORT   = 4321
_RST_DPORT   = 8080
_RST_PAYLOAD = b"C" * 20


def _build_rst_pcap(path):
    """5-packet TCP flow: handshake, client sends data, server aborts with RST."""
    c, s, sp, dp = _RST_CLIENT, _RST_SERVER, _RST_SPORT, _RST_DPORT
    write_pcap([
        make_tcp_packet(c, s, sp, dp, "S",  seq=100, ack=0,   t=0.0),
        make_tcp_packet(s, c, dp, sp, "SA", seq=200, ack=101, t=0.1),
        make_tcp_packet(c, s, sp, dp, "A",  seq=101, ack=201, t=0.2),
        make_tcp_packet(c, s, sp, dp, "PA", seq=101, ack=201, payload=_RST_PAYLOAD, t=0.3),
        make_tcp_packet(s, c, dp, sp, "R",  seq=201, ack=0,   t=0.4),
    ], path)


class TestRSTTermination:
    """Server terminates connection with RST."""

    @pytest.fixture(scope="class")
    def flow(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "tcp_rst.pcap")
        _build_rst_pcap(pcap)
        flows = run_reconstruction(pcap)
        assert len(flows) == 1, f"Expected 1 flow, got {len(flows)}"
        return flows[0]

    def test_termination_reason(self, flow):
        assert flow["termination_reason"] == "RST"

    def test_packets_count(self, flow):
        assert flow["packets_count"] == 5

    def test_payload_bytes_total(self, flow):
        assert flow["payload_bytes_total"] == 20

    def test_payload_bytes_max(self, flow):
        assert flow["payload_bytes_max"] == 20

    def test_syn_count(self, flow):
        assert flow["syn_count"] == 2

    def test_ack_count(self, flow):
        # SYN-ACK, ACK, PSH+ACK — bare RST carries no ACK flag
        assert flow["ack_count"] == 3

    def test_fin_count(self, flow):
        assert flow["fin_count"] == 0

    def test_rst_count(self, flow):
        assert flow["rst_count"] == 1

    def test_psh_count(self, flow):
        assert flow["psh_count"] == 1

    def test_duration_s(self, flow):
        assert flow["duration_s"] == pytest.approx(0.4)


# ---------------------------------------------------------------------------
# Scenario: Bidirectional RST
#
# Both sides independently send RST (e.g. simultaneous abort). Both packets
# must land in the same flow.
#
#   t=0.0  SYN
#   t=0.1  SYN-ACK
#   t=0.2  ACK
#   t=0.3  RST  client→server  ← flow moves to finalizing_flows
#   t=0.4  RST  server→client  ← appended to finalizing flow
# ---------------------------------------------------------------------------

_BIDIR_CLIENT = "10.0.2.1"
_BIDIR_SERVER = "10.0.2.2"
_BIDIR_SPORT  = 6666
_BIDIR_DPORT  = 80


def _build_bidirectional_rst_pcap(path):
    c, s, sp, dp = _BIDIR_CLIENT, _BIDIR_SERVER, _BIDIR_SPORT, _BIDIR_DPORT
    write_pcap([
        make_tcp_packet(c, s, sp, dp, "S",  seq=100, ack=0,   t=0.0),
        make_tcp_packet(s, c, dp, sp, "SA", seq=200, ack=101, t=0.1),
        make_tcp_packet(c, s, sp, dp, "A",  seq=101, ack=201, t=0.2),
        make_tcp_packet(c, s, sp, dp, "R",  seq=101, ack=201, t=0.3),
        make_tcp_packet(s, c, dp, sp, "R",  seq=201, ack=101, t=0.4),
    ], path)


class TestBidirectionalRST:
    """Both sides send RST; both packets land in the same flow."""

    @pytest.fixture(scope="class")
    def flow(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "bidir_rst.pcap")
        _build_bidirectional_rst_pcap(pcap)
        result = run_reconstruction(pcap)
        assert len(result) == 1, f"Expected 1 flow, got {len(result)}"
        return result[0]

    def test_termination_reason(self, flow):
        assert flow["termination_reason"] == "RST"

    def test_packets_count(self, flow):
        assert flow["packets_count"] == 5

    def test_rst_count(self, flow):
        assert flow["rst_count"] == 2

    def test_syn_count(self, flow):
        assert flow["syn_count"] == 2

    def test_ack_count(self, flow):
        # SYN-ACK, ACK — neither RST carries ACK flag
        assert flow["ack_count"] == 2

    def test_fin_count(self, flow):
        assert flow["fin_count"] == 0

    def test_duration_s(self, flow):
        assert flow["duration_s"] == pytest.approx(0.4)


# ---------------------------------------------------------------------------
# Scenario: Repeated SYN → RST/ACK (rejected connection attempts)
#
# Current behavior: a new SYN arriving while the previous attempt is still in
# finalizing_flows triggers terminate_flow + initiate_new_flow, so each attempt
# becomes a SEPARATE flow rather than being merged.
#
#   t=0.00  SYN (attempt 1)   → flow 1 created
#   t=0.10  RST/ACK           → flow 1 finalized
#   t=0.20  SYN (attempt 2)   → flow 1 terminated immediately, flow 2 starts
#   t=0.30  RST/ACK           → flow 2 finalized
#   t=0.35  RST/ACK (extra)   → appended to flow 2
#
# Result: 2 separate RST flows, not one merged flow.
# ---------------------------------------------------------------------------

_RECON_SYN_CLIENT = "10.0.3.1"
_RECON_SYN_SERVER = "10.0.3.2"
_RECON_SYN_SPORT  = 8888
_RECON_SYN_DPORT  = 80


def _build_repeated_syn_rst_pcap(path):
    c, s, sp, dp = _RECON_SYN_CLIENT, _RECON_SYN_SERVER, _RECON_SYN_SPORT, _RECON_SYN_DPORT
    write_pcap([
        make_tcp_packet(c, s, sp, dp, "S",  seq=100, ack=0,   t=0.00),
        make_tcp_packet(s, c, dp, sp, "RA", seq=0,   ack=101, t=0.10),
        make_tcp_packet(c, s, sp, dp, "S",  seq=100, ack=0,   t=0.20),
        make_tcp_packet(s, c, dp, sp, "RA", seq=0,   ack=101, t=0.30),
        make_tcp_packet(s, c, dp, sp, "RA", seq=0,   ack=101, t=0.35),  # extra RST
    ], path)


class TestRepeatedSYNRejected:
    """Each SYN attempt on a refused port produces a separate flow, not one merged flow."""

    @pytest.fixture(scope="class")
    def flows(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "repeated_syn_rst.pcap")
        _build_repeated_syn_rst_pcap(pcap)
        result = run_reconstruction(pcap)
        rst_flows = sorted(
            [f for f in result if f["termination_reason"] == "RST"],
            key=lambda f: f["packets_count"],
        )
        assert len(rst_flows) == 2, f"Expected 2 RST flows, got {rst_flows}"
        return rst_flows

    @pytest.fixture(scope="class")
    def flow_1(self, flows):
        """First attempt: SYN + RST/ACK (2 packets)."""
        return flows[0]

    @pytest.fixture(scope="class")
    def flow_2(self, flows):
        """Second attempt: SYN + RST/ACK + extra RST/ACK (3 packets)."""
        return flows[1]

    def test_produces_two_separate_flows(self, flows):
        assert len(flows) == 2

    def test_flow_1_packets_count(self, flow_1):
        assert flow_1["packets_count"] == 2

    def test_flow_1_rst_count(self, flow_1):
        assert flow_1["rst_count"] == 1

    def test_flow_1_syn_count(self, flow_1):
        assert flow_1["syn_count"] == 1

    def test_flow_1_termination_reason(self, flow_1):
        assert flow_1["termination_reason"] == "RST"

    def test_flow_2_packets_count(self, flow_2):
        assert flow_2["packets_count"] == 3

    def test_flow_2_rst_count(self, flow_2):
        assert flow_2["rst_count"] == 2

    def test_flow_2_syn_count(self, flow_2):
        assert flow_2["syn_count"] == 1

    def test_flow_2_termination_reason(self, flow_2):
        assert flow_2["termination_reason"] == "RST"


# ---------------------------------------------------------------------------
# Scenario: Trailing packets after RST (grace period acceptance)
#
# Server sends RST; client hasn't received it yet and keeps sending data.
# The server replies with more RSTs. All packets arrive within the 1-second
# grace period, so they all land in the same flow.
#
#   t=0.00  SYN
#   t=0.10  SYN-ACK
#   t=0.20  ACK
#   t=0.30  PSH+ACK (10 B)
#   t=0.40  ACK
#   t=0.50  RST/ACK       ← finalization_time=0.50
#   t=0.60  PSH+ACK 10 B  ← trailing; 0.60-0.50=0.10<1.0 s grace ✓
#   t=0.65  RST/ACK       ← server replies to trailing data
#   t=0.70  PSH+ACK 10 B  ← more trailing
#   t=0.75  RST/ACK
# ---------------------------------------------------------------------------

_RST_TRAIL_CLIENT = "10.0.4.1"
_RST_TRAIL_SERVER = "10.0.4.2"
_RST_TRAIL_SPORT  = 11111
_RST_TRAIL_DPORT  = 80


def _build_rst_trailing_pcap(path):
    c, s, sp, dp = _RST_TRAIL_CLIENT, _RST_TRAIL_SERVER, _RST_TRAIL_SPORT, _RST_TRAIL_DPORT
    write_pcap([
        make_tcp_packet(c, s, sp, dp, "S",  seq=100, ack=0,   t=0.00),
        make_tcp_packet(s, c, dp, sp, "SA", seq=200, ack=101, t=0.10),
        make_tcp_packet(c, s, sp, dp, "A",  seq=101, ack=201, t=0.20),
        make_tcp_packet(c, s, sp, dp, "PA", seq=101, ack=201, payload=b"A" * 10, t=0.30),
        make_tcp_packet(s, c, dp, sp, "A",  seq=201, ack=111, t=0.40),
        make_tcp_packet(s, c, dp, sp, "RA", seq=201, ack=111, t=0.50),
        make_tcp_packet(c, s, sp, dp, "PA", seq=111, ack=201, payload=b"B" * 10, t=0.60),
        make_tcp_packet(s, c, dp, sp, "RA", seq=201, ack=121, t=0.65),
        make_tcp_packet(c, s, sp, dp, "PA", seq=121, ack=201, payload=b"C" * 10, t=0.70),
        make_tcp_packet(s, c, dp, sp, "RA", seq=201, ack=131, t=0.75),
    ], path)


class TestRSTWithTrailingPackets:
    """Packets arriving after RST but within the grace period stay in the same flow."""

    @pytest.fixture(scope="class")
    def flow(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "rst_trailing.pcap")
        _build_rst_trailing_pcap(pcap)
        result = run_reconstruction(pcap)
        assert len(result) == 1, f"Expected 1 flow, got {len(result)}"
        return result[0]

    def test_termination_reason(self, flow):
        assert flow["termination_reason"] == "RST"

    def test_packets_count(self, flow):
        assert flow["packets_count"] == 10

    def test_rst_count(self, flow):
        assert flow["rst_count"] == 3  # server RST at t=0.50, 0.65, 0.75

    def test_psh_count(self, flow):
        assert flow["psh_count"] == 3  # client PSH at t=0.30, 0.60, 0.70

    def test_syn_count(self, flow):
        assert flow["syn_count"] == 2

    def test_fin_count(self, flow):
        assert flow["fin_count"] == 0

    def test_payload_bytes_total(self, flow):
        assert flow["payload_bytes_total"] == 30  # 3 PSH × 10 bytes

    def test_duration_s(self, flow):
        assert flow["duration_s"] == pytest.approx(0.75)