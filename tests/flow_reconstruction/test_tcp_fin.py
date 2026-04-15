"""
Integration tests for TCP flows terminated by graceful FIN.

Scenarios:
  TestFINTermination            — minimal 10-packet handshake + data + FIN
  TestMultipleSimultaneousFlows — two interleaved TCP connections separated by 5-tuple
  TestFINRetransmission         — client resends FIN before ACK arrives
  TestSYNRetransmission         — client resends SYN before SYN-ACK arrives
  TestTruncatedPCAP             — PCAP ends before grace period expires (__exit__ fix)
  TestHalfCloseAbort            — client FIN half-close followed by server data + RST
"""
import math

import pytest

from helpers import make_tcp_packet, write_pcap, run_reconstruction


# ---------------------------------------------------------------------------
# Scenario: Simple TCP flow
#
# Packet layout:
#   t=0.0  SYN          client→server
#   t=0.1  SYN-ACK      server→client
#   t=0.2  ACK          client→server
#   t=0.3  PSH+ACK 10B  client→server
#   t=0.4  ACK          server→client
#   t=0.5  PSH+ACK 30B  server→client
#   t=0.6  ACK          client→server
#   t=1.0  FIN+ACK      client→server  ← finalization_time=1.0
#   t=1.5  FIN+ACK      server→client
#   t=2.5  ACK          client→server  ← current_time=2.5; 2.5-1.0=1.5>1.0 ✓
# ---------------------------------------------------------------------------

_SIMPLE_CLIENT    = "10.0.1.1"
_SIMPLE_SERVER    = "10.0.1.2"
_SIMPLE_SPORT     = 1234
_SIMPLE_DPORT     = 80
_SIMPLE_PAYLOAD_C = b"A" * 10   # 10 bytes  client→server
_SIMPLE_PAYLOAD_S = b"B" * 30   # 30 bytes  server→client


def _build_simple_pcap(path):
    """10-packet TCP exchange: SYN handshake, 2 data packets, graceful FIN both ways."""
    c, s, sp, dp = _SIMPLE_CLIENT, _SIMPLE_SERVER, _SIMPLE_SPORT, _SIMPLE_DPORT
    write_pcap([
        make_tcp_packet(c, s, sp, dp, "S",  seq=100, ack=0,   t=0.0),
        make_tcp_packet(s, c, dp, sp, "SA", seq=200, ack=101, t=0.1),
        make_tcp_packet(c, s, sp, dp, "A",  seq=101, ack=201, t=0.2),
        make_tcp_packet(c, s, sp, dp, "PA", seq=101, ack=201, payload=_SIMPLE_PAYLOAD_C, t=0.3),
        make_tcp_packet(s, c, dp, sp, "A",  seq=201, ack=111, t=0.4),
        make_tcp_packet(s, c, dp, sp, "PA", seq=201, ack=111, payload=_SIMPLE_PAYLOAD_S, t=0.5),
        make_tcp_packet(c, s, sp, dp, "A",  seq=111, ack=231, t=0.6),
        make_tcp_packet(c, s, sp, dp, "FA", seq=111, ack=231, t=1.0),
        make_tcp_packet(s, c, dp, sp, "FA", seq=231, ack=112, t=1.5),
        make_tcp_packet(c, s, sp, dp, "A",  seq=112, ack=232, t=2.5),
    ], path)


class TestFINTermination:
    """
    Minimal TCP exchange with graceful FIN. Verifies packet count, payload
    statistics, and TCP flag counts.
    """

    @pytest.fixture(scope="class")
    def flow(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "tcp_simple.pcap")
        _build_simple_pcap(pcap)
        flows = run_reconstruction(pcap)
        assert len(flows) == 1, f"Expected 1 flow, got {len(flows)}"
        return flows[0]

    def test_termination_reason(self, flow):
        assert flow["termination_reason"] == "FIN"

    def test_protocol(self, flow):
        assert flow["protocol"] == 6  # TCP

    def test_packets_count(self, flow):
        assert flow["packets_count"] == 10

    def test_payload_bytes_total(self, flow):
        assert flow["payload_bytes_total"] == 40  # 10 + 30

    def test_payload_bytes_min(self, flow):
        assert flow["payload_bytes_min"] == 0  # 8 zero-payload packets

    def test_payload_bytes_max(self, flow):
        assert flow["payload_bytes_max"] == 30

    def test_payload_bytes_min_nonzero(self, flow):
        assert flow["payload_bytes_min_nonzero"] == 10

    def test_payload_bytes_avg_nonzero(self, flow):
        assert flow["payload_bytes_avg_nonzero"] == pytest.approx(20.0)

    def test_payload_bytes_std_nonzero(self, flow):
        # stdev([10, 30]) = sqrt(200) ≈ 14.142
        assert flow["payload_bytes_std_nonzero"] == pytest.approx(math.sqrt(200), rel=1e-5)

    def test_syn_count(self, flow):
        assert flow["syn_count"] == 2  # SYN + SYN-ACK

    def test_ack_count(self, flow):
        assert flow["ack_count"] == 9  # every packet except the bare SYN

    def test_fin_count(self, flow):
        assert flow["fin_count"] == 2

    def test_rst_count(self, flow):
        assert flow["rst_count"] == 0

    def test_psh_count(self, flow):
        assert flow["psh_count"] == 2

    def test_duration_s(self, flow):
        assert flow["duration_s"] == pytest.approx(2.5)


# ---------------------------------------------------------------------------
# Scenario: Two interleaved TCP flows
#
# Flow A: client:1111 → server:80  (15-byte payload)
# Flow B: client:2222 → server:80  (25-byte payload)
#
# Packets alternate in the PCAP to verify that FlowReconstructor correctly
# separates them by 5-tuple. Payload totals detect cross-contamination.
#
#   t=0.0  A-SYN        t=0.1  B-SYN
#   t=0.2  A-SYN-ACK    t=0.3  B-SYN-ACK
#   t=0.4  A-ACK        t=0.5  B-ACK
#   t=0.6  A-PSH+ACK    t=0.7  B-PSH+ACK
#   t=0.8  A-ACK        t=0.9  B-ACK
#   t=1.0  A-FIN+ACK    t=1.1  B-FIN+ACK  ← finalization_time A=1.0, B=1.1
#   t=1.5  A-FIN+ACK    t=1.6  B-FIN+ACK
#   t=2.5  A-ACK ← 2.5-1.0=1.5>1.0 ✓
#   t=2.6  B-ACK ← 2.6-1.1=1.5>1.0 ✓
# ---------------------------------------------------------------------------

_MULTI_CLIENT    = "10.0.3.1"
_MULTI_SERVER    = "10.0.3.2"
_MULTI_DPORT     = 80
_MULTI_SPORT_A   = 1111
_MULTI_SPORT_B   = 2222
_MULTI_PAYLOAD_A = b"A" * 15
_MULTI_PAYLOAD_B = b"B" * 25


def _build_multi_flow_pcap(path):
    """16-packet PCAP with two interleaved TCP flows (A: sport 1111, B: sport 2222)."""
    c, s, dp = _MULTI_CLIENT, _MULTI_SERVER, _MULTI_DPORT
    sa, sb = _MULTI_SPORT_A, _MULTI_SPORT_B
    write_pcap([
        make_tcp_packet(c, s, sa, dp, "S",  seq=100, ack=0,   t=0.0),
        make_tcp_packet(c, s, sb, dp, "S",  seq=300, ack=0,   t=0.1),
        make_tcp_packet(s, c, dp, sa, "SA", seq=200, ack=101, t=0.2),
        make_tcp_packet(s, c, dp, sb, "SA", seq=400, ack=301, t=0.3),
        make_tcp_packet(c, s, sa, dp, "A",  seq=101, ack=201, t=0.4),
        make_tcp_packet(c, s, sb, dp, "A",  seq=301, ack=401, t=0.5),
        make_tcp_packet(c, s, sa, dp, "PA", seq=101, ack=201, payload=_MULTI_PAYLOAD_A, t=0.6),
        make_tcp_packet(c, s, sb, dp, "PA", seq=301, ack=401, payload=_MULTI_PAYLOAD_B, t=0.7),
        make_tcp_packet(s, c, dp, sa, "A",  seq=201, ack=116, t=0.8),
        make_tcp_packet(s, c, dp, sb, "A",  seq=401, ack=326, t=0.9),
        make_tcp_packet(c, s, sa, dp, "FA", seq=116, ack=201, t=1.0),
        make_tcp_packet(c, s, sb, dp, "FA", seq=326, ack=401, t=1.1),
        make_tcp_packet(s, c, dp, sa, "FA", seq=201, ack=117, t=1.5),
        make_tcp_packet(s, c, dp, sb, "FA", seq=401, ack=327, t=1.6),
        make_tcp_packet(c, s, sa, dp, "A",  seq=117, ack=202, t=2.5),
        make_tcp_packet(c, s, sb, dp, "A",  seq=327, ack=402, t=2.6),
    ], path)


class TestMultipleSimultaneousFlows:
    """
    Two interleaved TCP connections must be correctly separated by 5-tuple.
    If any packet leaks between flows, both payload totals and packet counts
    would be wrong — that is the cross-contamination signal.
    """

    @pytest.fixture(scope="class")
    def flows(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "tcp_multi.pcap")
        _build_multi_flow_pcap(pcap)
        result = run_reconstruction(pcap)
        assert len(result) == 2, f"Expected 2 flows, got {len(result)}"
        return sorted(result, key=lambda f: f["src_port"])

    @pytest.fixture(scope="class")
    def flow_a(self, flows):
        return flows[0]  # src_port=1111

    @pytest.fixture(scope="class")
    def flow_b(self, flows):
        return flows[1]  # src_port=2222

    def test_flow_count(self, flows):
        assert len(flows) == 2

    # --- Flow A ---

    def test_flow_a_src_port(self, flow_a):
        assert flow_a["src_port"] == _MULTI_SPORT_A

    def test_flow_a_termination_reason(self, flow_a):
        assert flow_a["termination_reason"] == "FIN"

    def test_flow_a_packets_count(self, flow_a):
        assert flow_a["packets_count"] == 8

    def test_flow_a_payload_bytes_total(self, flow_a):
        assert flow_a["payload_bytes_total"] == 15

    def test_flow_a_syn_count(self, flow_a):
        assert flow_a["syn_count"] == 2

    def test_flow_a_fin_count(self, flow_a):
        assert flow_a["fin_count"] == 2

    def test_flow_a_duration_s(self, flow_a):
        assert flow_a["duration_s"] == pytest.approx(2.5)

    # --- Flow B ---

    def test_flow_b_src_port(self, flow_b):
        assert flow_b["src_port"] == _MULTI_SPORT_B

    def test_flow_b_termination_reason(self, flow_b):
        assert flow_b["termination_reason"] == "FIN"

    def test_flow_b_packets_count(self, flow_b):
        assert flow_b["packets_count"] == 8

    def test_flow_b_payload_bytes_total(self, flow_b):
        assert flow_b["payload_bytes_total"] == 25

    def test_flow_b_syn_count(self, flow_b):
        assert flow_b["syn_count"] == 2

    def test_flow_b_fin_count(self, flow_b):
        assert flow_b["fin_count"] == 2

    def test_flow_b_duration_s(self, flow_b):
        assert flow_b["duration_s"] == pytest.approx(2.5)


# ---------------------------------------------------------------------------
# Scenario: FIN retransmission
#
# Client retransmits FIN (same seq) before receiving ACK. Both FINs land in
# one flow; finalization_time stays at the first FIN.
#
#   t=0.0  SYN
#   t=0.1  SYN-ACK
#   t=0.2  ACK
#   t=0.5  FIN+ACK           ← finalization_time=0.5
#   t=0.9  FIN+ACK (retransmit, same seq)
#   t=1.3  server FIN+ACK
#   t=2.5  final ACK         ← 2.5-0.5=2.0>1.0 ✓
# ---------------------------------------------------------------------------

_FIN_RETX_CLIENT = "10.0.4.1"
_FIN_RETX_SERVER = "10.0.4.2"
_FIN_RETX_SPORT  = 5555
_FIN_RETX_DPORT  = 80


def _build_fin_retransmit_pcap(path):
    c, s, sp, dp = _FIN_RETX_CLIENT, _FIN_RETX_SERVER, _FIN_RETX_SPORT, _FIN_RETX_DPORT
    write_pcap([
        make_tcp_packet(c, s, sp, dp, "S",  seq=100, ack=0,   t=0.0),
        make_tcp_packet(s, c, dp, sp, "SA", seq=200, ack=101, t=0.1),
        make_tcp_packet(c, s, sp, dp, "A",  seq=101, ack=201, t=0.2),
        make_tcp_packet(c, s, sp, dp, "FA", seq=101, ack=201, t=0.5),
        make_tcp_packet(c, s, sp, dp, "FA", seq=101, ack=201, t=0.9),  # retransmit
        make_tcp_packet(s, c, dp, sp, "FA", seq=201, ack=102, t=1.3),
        make_tcp_packet(c, s, sp, dp, "A",  seq=102, ack=202, t=2.5),
    ], path)


class TestFINRetransmission:
    """Client retransmits FIN before receiving ACK; all packets land in one flow."""

    @pytest.fixture(scope="class")
    def flow(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "fin_retransmit.pcap")
        _build_fin_retransmit_pcap(pcap)
        result = run_reconstruction(pcap)
        assert len(result) == 1, f"Expected 1 flow, got {len(result)}"
        return result[0]

    def test_termination_reason(self, flow):
        assert flow["termination_reason"] == "FIN"

    def test_packets_count(self, flow):
        assert flow["packets_count"] == 7

    def test_fin_count(self, flow):
        # client FIN + client FIN retransmit + server FIN — all carry F flag
        assert flow["fin_count"] == 3

    def test_syn_count(self, flow):
        assert flow["syn_count"] == 2

    def test_ack_count(self, flow):
        # SYN-ACK, ACK, FIN+ACK, FIN+ACK retransmit, server FIN+ACK, final ACK
        assert flow["ack_count"] == 6

    def test_rst_count(self, flow):
        assert flow["rst_count"] == 0

    def test_duration_s(self, flow):
        assert flow["duration_s"] == pytest.approx(2.5)


# ---------------------------------------------------------------------------
# Scenario: PCAP ends before grace period expires (truncated capture)
#
# Regression for the __exit__ fix: a flow in finalizing state at PCAP end
# must be emitted, not abandoned.
#
#   t=0.0  SYN
#   t=0.1  SYN-ACK
#   t=0.2  ACK
#   t=0.3  FIN+ACK  ← finalization_time=0.3
#   t=0.4  ACK      ← current_time=0.4; 0.4-0.3=0.1<1.0 (grace not expired)
#   <PCAP ends>
# ---------------------------------------------------------------------------

_TRUNC_CLIENT = "10.0.6.1"
_TRUNC_SERVER = "10.0.6.2"
_TRUNC_SPORT  = 12345
_TRUNC_DPORT  = 80


def _build_truncated_pcap(path):
    c, s, sp, dp = _TRUNC_CLIENT, _TRUNC_SERVER, _TRUNC_SPORT, _TRUNC_DPORT
    write_pcap([
        make_tcp_packet(c, s, sp, dp, "S",  seq=100, ack=0,   t=0.0),
        make_tcp_packet(s, c, dp, sp, "SA", seq=200, ack=101, t=0.1),
        make_tcp_packet(c, s, sp, dp, "A",  seq=101, ack=201, t=0.2),
        make_tcp_packet(c, s, sp, dp, "FA", seq=101, ack=201, t=0.3),
        make_tcp_packet(s, c, dp, sp, "A",  seq=201, ack=102, t=0.4),
    ], path)


class TestTruncatedPCAP:
    """
    Flow in finalizing state at PCAP end must be emitted with reason='FIN'.
    Regression for the __exit__ fix (without it the flow would be abandoned).
    """

    @pytest.fixture(scope="class")
    def flow(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "truncated.pcap")
        _build_truncated_pcap(pcap)
        result = run_reconstruction(pcap)
        assert len(result) == 1, f"Expected 1 flow, got {len(result)}"
        return result[0]

    def test_termination_reason(self, flow):
        assert flow["termination_reason"] == "FIN"

    def test_packets_count(self, flow):
        assert flow["packets_count"] == 5

    def test_fin_count(self, flow):
        assert flow["fin_count"] == 1

    def test_syn_count(self, flow):
        assert flow["syn_count"] == 2


# ---------------------------------------------------------------------------
# Scenario: TCP half-close abort
#
# Client sends FIN+ACK (half-close: done sending, still accepting). Server
# ignores the half-close and sends data. Client aborts with RST.
#
# Key behavior: finalize_flow("RST") is a no-op when the flow is already in
# finalizing_flows. termination_reason stays "FIN".
#
#   t=0.0  SYN
#   t=0.1  SYN-ACK
#   t=0.2  ACK
#   t=0.3  FIN+ACK         ← half-close; finalization_time=0.3
#   t=0.4  PSH+ACK (20 B)  ← server sends data; appended to finalizing flow
#   t=0.5  RST             ← abort; finalize_flow("RST") is a no-op
#   <PCAP ends — __exit__ emits the flow>
# ---------------------------------------------------------------------------

_HALF_CLOSE_CLIENT  = "10.0.7.1"
_HALF_CLOSE_SERVER  = "10.0.7.2"
_HALF_CLOSE_SPORT   = 13131
_HALF_CLOSE_DPORT   = 80
_HALF_CLOSE_PAYLOAD = b"D" * 20


def _build_half_close_abort_pcap(path):
    c, s, sp, dp = _HALF_CLOSE_CLIENT, _HALF_CLOSE_SERVER, _HALF_CLOSE_SPORT, _HALF_CLOSE_DPORT
    write_pcap([
        make_tcp_packet(c, s, sp, dp, "S",  seq=100, ack=0,   t=0.0),
        make_tcp_packet(s, c, dp, sp, "SA", seq=200, ack=101, t=0.1),
        make_tcp_packet(c, s, sp, dp, "A",  seq=101, ack=201, t=0.2),
        make_tcp_packet(c, s, sp, dp, "FA", seq=101, ack=201, t=0.3),
        make_tcp_packet(s, c, dp, sp, "PA", seq=201, ack=102, payload=_HALF_CLOSE_PAYLOAD, t=0.4),
        make_tcp_packet(c, s, sp, dp, "R",  seq=102, ack=0,   t=0.5),
    ], path)


class TestHalfCloseAbort:
    """
    Client half-closes (FIN); server keeps sending; client aborts with RST.

    termination_reason is "FIN" because finalize_flow("RST") is a no-op once
    the flow is already in finalizing_flows.
    """

    @pytest.fixture(scope="class")
    def flow(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "half_close_abort.pcap")
        _build_half_close_abort_pcap(pcap)
        result = run_reconstruction(pcap)
        assert len(result) == 1, f"Expected 1 flow, got {len(result)}"
        return result[0]

    def test_termination_reason(self, flow):
        # RST on a finalizing flow is a no-op → reason set by FIN is preserved
        assert flow["termination_reason"] == "FIN"

    def test_packets_count(self, flow):
        assert flow["packets_count"] == 6

    def test_fin_count(self, flow):
        assert flow["fin_count"] == 1  # only client FIN+ACK

    def test_rst_count(self, flow):
        assert flow["rst_count"] == 1  # client RST abort

    def test_syn_count(self, flow):
        assert flow["syn_count"] == 2

    def test_psh_count(self, flow):
        assert flow["psh_count"] == 1  # server PSH+ACK with data

    def test_ack_count(self, flow):
        # SYN-ACK, ACK, FIN+ACK, PSH+ACK — bare RST carries no ACK flag
        assert flow["ack_count"] == 4

    def test_payload_bytes_total(self, flow):
        assert flow["payload_bytes_total"] == 20

    def test_duration_s(self, flow):
        assert flow["duration_s"] == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# Scenario: SYN retransmission
#
# Client retransmits SYN (same seq) before receiving SYN-ACK.
#
#   t=0.0  SYN             ← new flow created
#   t=0.3  SYN (retransmit, same seq)
#   t=0.6  SYN-ACK
#   t=0.7  ACK
#   t=1.0  FIN+ACK         ← finalization_time=1.0
#   t=1.5  server FIN+ACK
#   t=2.5  final ACK       ← 2.5-1.0=1.5>1.0 ✓
# ---------------------------------------------------------------------------

_SYN_RETX_CLIENT = "10.0.5.1"
_SYN_RETX_SERVER = "10.0.5.2"
_SYN_RETX_SPORT  = 7777
_SYN_RETX_DPORT  = 80


def _build_syn_retransmit_pcap(path):
    c, s, sp, dp = _SYN_RETX_CLIENT, _SYN_RETX_SERVER, _SYN_RETX_SPORT, _SYN_RETX_DPORT
    write_pcap([
        make_tcp_packet(c, s, sp, dp, "S",  seq=100, ack=0,   t=0.0),
        make_tcp_packet(c, s, sp, dp, "S",  seq=100, ack=0,   t=0.3),  # retransmit
        make_tcp_packet(s, c, dp, sp, "SA", seq=200, ack=101, t=0.6),
        make_tcp_packet(c, s, sp, dp, "A",  seq=101, ack=201, t=0.7),
        make_tcp_packet(c, s, sp, dp, "FA", seq=101, ack=201, t=1.0),
        make_tcp_packet(s, c, dp, sp, "FA", seq=201, ack=102, t=1.5),
        make_tcp_packet(c, s, sp, dp, "A",  seq=102, ack=202, t=2.5),
    ], path)


class TestSYNRetransmission:
    """Client retransmits SYN before receiving SYN-ACK; both SYNs land in one flow."""

    @pytest.fixture(scope="class")
    def flow(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "syn_retransmit.pcap")
        _build_syn_retransmit_pcap(pcap)
        result = run_reconstruction(pcap)
        assert len(result) == 1, f"Expected 1 flow, got {len(result)}"
        return result[0]

    def test_termination_reason(self, flow):
        assert flow["termination_reason"] == "FIN"

    def test_packets_count(self, flow):
        assert flow["packets_count"] == 7

    def test_syn_count(self, flow):
        # client SYN + retransmit + server SYN-ACK — all carry S flag
        assert flow["syn_count"] == 3

    def test_fin_count(self, flow):
        assert flow["fin_count"] == 2

    def test_ack_count(self, flow):
        # SYN-ACK, ACK, client FIN+ACK, server FIN+ACK, final ACK
        assert flow["ack_count"] == 5

    def test_rst_count(self, flow):
        assert flow["rst_count"] == 0

    def test_duration_s(self, flow):
        assert flow["duration_s"] == pytest.approx(2.5)
