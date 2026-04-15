"""
Integration tests for UDP flow reconstruction.

Scenarios:
  TestUDPSimpleFlow               — basic request/response, PCAP-end termination
  TestUDPIdleTimeout              — flow terminated after idle silence
  TestUDPActivityTimeout          — long-running flow split at activity timeout
  TestUDPMultipleSimultaneousFlows — three concurrent flows: DNS / NTP / Syslog
"""
import pytest
from scapy.all import DNS, DNSQR, DNSRR

from helpers import make_udp_packet, write_pcap, run_reconstruction


# ---------------------------------------------------------------------------
# Scenario: Simple UDP flow
#
# Basic request/response pair. No FIN/RST → terminates when PCAP ends.
# Uses a generic port (9999) to avoid Scapy auto-dissection.
#
#   t=0.0  client:54321→server:9999   40 B  request
#   t=0.1  server:9999→client:54321  120 B  response
#   <PCAP ends>
# ---------------------------------------------------------------------------

_SIMPLE_CLIENT = "10.0.1.1"
_SIMPLE_SERVER = "10.0.1.2"
_SIMPLE_SPORT  = 54321
_SIMPLE_DPORT  = 9999   # generic — avoids Scapy auto-dissection
_SIMPLE_QUERY  = b"Q" * 40
_SIMPLE_RESP   = b"R" * 120


def _build_udp_simple_pcap(path):
    c, s, sp, dp = _SIMPLE_CLIENT, _SIMPLE_SERVER, _SIMPLE_SPORT, _SIMPLE_DPORT
    write_pcap([
        make_udp_packet(c, s, sp, dp, payload=_SIMPLE_QUERY, t=0.0),
        make_udp_packet(s, c, dp, sp, payload=_SIMPLE_RESP,  t=0.1),
    ], path)


class TestUDPSimpleFlow:
    """
    Basic UDP request/response. Terminates when PCAP ends.

    Verifies: protocol=17, all TCP flag counts=0, window features=0.
    """

    @pytest.fixture(scope="class")
    def flow(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "udp_simple.pcap")
        _build_udp_simple_pcap(pcap)
        result = run_reconstruction(pcap, filter="udp")
        assert len(result) == 1, f"Expected 1 flow, got {len(result)}"
        return result[0]

    def test_termination_reason(self, flow):
        assert flow["termination_reason"] == "unknown"

    def test_protocol(self, flow):
        assert flow["protocol"] == 17

    def test_dst_port(self, flow):
        assert flow["dst_port"] == _SIMPLE_DPORT

    def test_packets_count(self, flow):
        assert flow["packets_count"] == 2

    def test_payload_bytes_total(self, flow):
        assert flow["payload_bytes_total"] == len(_SIMPLE_QUERY) + len(_SIMPLE_RESP)

    def test_payload_bytes_min(self, flow):
        assert flow["payload_bytes_min"] == len(_SIMPLE_QUERY)

    def test_payload_bytes_max(self, flow):
        assert flow["payload_bytes_max"] == len(_SIMPLE_RESP)

    def test_duration_s(self, flow):
        assert flow["duration_s"] == pytest.approx(0.1)

    # --- TCP flags must all be 0 for UDP ---

    def test_syn_count(self, flow):
        assert flow["syn_count"] == 0

    def test_fin_count(self, flow):
        assert flow["fin_count"] == 0

    def test_rst_count(self, flow):
        assert flow["rst_count"] == 0

    def test_ack_count(self, flow):
        assert flow["ack_count"] == 0

    def test_psh_count(self, flow):
        assert flow["psh_count"] == 0

    # --- window features must be 0 for UDP ---

    def test_fwd_window_scaling_factor(self, flow):
        assert flow["fwd_window_scaling_factor"] == 0

    def test_bwd_window_scaling_factor(self, flow):
        assert flow["bwd_window_scaling_factor"] == 0

    def test_fwd_initial_window_size(self, flow):
        assert flow["fwd_initial_window_size"] == 0

    def test_bwd_initial_window_size(self, flow):
        assert flow["bwd_initial_window_size"] == 0


# ---------------------------------------------------------------------------
# Scenario: UDP idle timeout
#
# Flow goes idle for > flow_idle_timeout. A probe packet from a different
# 5-tuple advances current_time and triggers the timeout check.
#
#   t=0.0  client→server  40 B  ← flow starts
#   t=0.1  server→client  50 B
#   t=0.2  client→server  30 B  ← last activity; idle timer starts
#   <3.8 s gap>
#   t=4.0  probe→server   10 B  ← idle_time=3.8>3.0 → main flow terminated
# ---------------------------------------------------------------------------

_IDLE_CLIENT     = "10.0.2.1"
_IDLE_SERVER     = "10.0.2.2"
_IDLE_SPORT      = 55555
_IDLE_DPORT      = 9998   # generic port
_IDLE_PROBE      = "10.0.2.3"
_IDLE_PROBE_PORT = 55556


def _build_udp_idle_timeout_pcap(path):
    c, s, sp, dp = _IDLE_CLIENT, _IDLE_SERVER, _IDLE_SPORT, _IDLE_DPORT
    write_pcap([
        make_udp_packet(c, s, sp, dp, payload=b"A" * 40, t=0.0),
        make_udp_packet(s, c, dp, sp, payload=b"B" * 50, t=0.1),
        make_udp_packet(c, s, sp, dp, payload=b"C" * 30, t=0.2),
        make_udp_packet(_IDLE_PROBE, s, _IDLE_PROBE_PORT, dp, payload=b"P" * 10, t=4.0),
    ], path)


class TestUDPIdleTimeout:
    """
    UDP flow terminated by idle timeout.

    Uses flow_idle_timeout=3 s and flow_activity_timeout=5 s.
    """

    @pytest.fixture(scope="class")
    def flows(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "udp_idle_timeout.pcap")
        _build_udp_idle_timeout_pcap(pcap)
        result = run_reconstruction(
            pcap, filter="udp", flow_idle_timeout=3, flow_activity_timeout=5
        )
        assert len(result) == 2, f"Expected 2 flows, got {len(result)}"
        return result

    @pytest.fixture(scope="class")
    def main_flow(self, flows):
        f = next((f for f in flows if f["termination_reason"] == "idle_timeout"), None)
        assert f is not None, "No idle_timeout flow found"
        return f

    @pytest.fixture(scope="class")
    def probe_flow(self, flows):
        f = next((f for f in flows if f["termination_reason"] == "unknown"), None)
        assert f is not None, "No unknown-termination flow found"
        return f

    # --- main flow ---

    def test_main_termination_reason(self, main_flow):
        assert main_flow["termination_reason"] == "idle_timeout"

    def test_main_packets_count(self, main_flow):
        assert main_flow["packets_count"] == 3

    def test_main_payload_bytes_total(self, main_flow):
        assert main_flow["payload_bytes_total"] == 120  # 40+50+30

    def test_main_duration_s(self, main_flow):
        assert main_flow["duration_s"] == pytest.approx(0.2)

    def test_main_protocol(self, main_flow):
        assert main_flow["protocol"] == 17

    # --- probe flow ---

    def test_probe_termination_reason(self, probe_flow):
        assert probe_flow["termination_reason"] == "unknown"

    def test_probe_packets_count(self, probe_flow):
        assert probe_flow["packets_count"] == 1

    def test_probe_payload_bytes_total(self, probe_flow):
        assert probe_flow["payload_bytes_total"] == 10


# ---------------------------------------------------------------------------
# Scenario: UDP activity timeout
#
# Flow active for > flow_activity_timeout → split into two flows.
#
#   t=0.0  client→server  40 B
#   t=2.0  server→client  50 B
#   t=4.0  client→server  60 B
#   t=5.5  server→client  70 B  ← activity_time=5.5>5 → flow 1 terminated
#   t=6.0  client→server  80 B  ← flow 2 starts
#   t=7.0  server→client  90 B
#   <PCAP ends>
# ---------------------------------------------------------------------------

_ACT_CLIENT = "10.0.3.1"
_ACT_SERVER = "10.0.3.2"
_ACT_SPORT  = 56789
_ACT_DPORT  = 123   # NTP port — Scapy may auto-dissect; payload_bytes unaffected


def _build_udp_activity_timeout_pcap(path):
    """6-packet PCAP: UDP flow exceeding activity timeout and splitting."""
    c, s, sp, dp = _ACT_CLIENT, _ACT_SERVER, _ACT_SPORT, _ACT_DPORT
    write_pcap([
        make_udp_packet(c, s, sp, dp, payload=b"A" * 40, t=0.0),
        make_udp_packet(s, c, dp, sp, payload=b"B" * 50, t=2.0),
        make_udp_packet(c, s, sp, dp, payload=b"C" * 60, t=4.0),
        make_udp_packet(s, c, dp, sp, payload=b"D" * 70, t=5.5),
        make_udp_packet(c, s, sp, dp, payload=b"E" * 80, t=6.0),
        make_udp_packet(s, c, dp, sp, payload=b"F" * 90, t=7.0),
    ], path)


class TestUDPActivityTimeout:
    """
    UDP flow active for > activity_timeout is split into two flows.

    Uses flow_idle_timeout=3 s and flow_activity_timeout=5 s.
    """

    @pytest.fixture(scope="class")
    def flows(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "udp_activity_timeout.pcap")
        _build_udp_activity_timeout_pcap(pcap)
        result = run_reconstruction(
            pcap, filter="udp", flow_idle_timeout=3, flow_activity_timeout=5
        )
        assert len(result) == 2, f"Expected 2 flows, got {len(result)}"
        return result

    @pytest.fixture(scope="class")
    def flow_1(self, flows):
        f = next((f for f in flows if f["termination_reason"] == "activity_timeout"), None)
        assert f is not None, "No activity_timeout flow found"
        return f

    @pytest.fixture(scope="class")
    def flow_2(self, flows):
        f = next((f for f in flows if f["termination_reason"] == "unknown"), None)
        assert f is not None, "No unknown-termination flow found"
        return f

    # --- flow 1 (activity_timeout) ---

    def test_flow_1_termination_reason(self, flow_1):
        assert flow_1["termination_reason"] == "activity_timeout"

    def test_flow_1_packets_count(self, flow_1):
        assert flow_1["packets_count"] == 4

    def test_flow_1_payload_bytes_total(self, flow_1):
        assert flow_1["payload_bytes_total"] == 220  # 40+50+60+70

    def test_flow_1_duration_s(self, flow_1):
        assert flow_1["duration_s"] == pytest.approx(5.5)

    def test_flow_1_protocol(self, flow_1):
        assert flow_1["protocol"] == 17

    # --- flow 2 (unknown, PCAP end) ---

    def test_flow_2_termination_reason(self, flow_2):
        assert flow_2["termination_reason"] == "unknown"

    def test_flow_2_packets_count(self, flow_2):
        assert flow_2["packets_count"] == 2

    def test_flow_2_payload_bytes_total(self, flow_2):
        assert flow_2["payload_bytes_total"] == 170  # 80+90

    def test_flow_2_duration_s(self, flow_2):
        assert flow_2["duration_s"] == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Scenario: Multiple simultaneous UDP flows (DNS / NTP / Syslog)
#
# Three flows active concurrently to well-known ports. All terminate when the
# PCAP ends (termination_reason='unknown').
#
# Flow A (port  53 / DNS):    query + response for "example.com" + repeated query
# Flow B (port 123 / NTP):    48-byte client request + server response
# Flow C (port 514 / Syslog): two RFC 3164 log messages, client→server only
#                              (syslog is fire-and-forget; no response)
#
# DNS and NTP ports are auto-dissected by Scapy on PCAP read-back.
# payload_bytes is computed from len(pkt[UDP].payload) regardless of layer
# type, verifying the preprocess() fix for well-known port auto-dissection.
#
#   t=0.0  A: DNS query         t=0.1  B: NTP request       t=0.2  C: Syslog msg 1
#   t=0.3  A: DNS response      t=0.4  B: NTP response       t=0.5  C: Syslog msg 2
#   t=0.6  A: DNS query (repeat)
#   <PCAP ends>
# ---------------------------------------------------------------------------

_MULTI_CLIENT = "10.0.4.1"
_MULTI_SERVER = "10.0.4.2"

# DNS payloads — real wire format; Scapy auto-dissects port 53 on PCAP read-back
_DNS_QUERY = bytes(DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com")))
_DNS_RESPONSE = bytes(
    DNS(
        id=0x1234, qr=1, aa=0, rd=1, ra=1,
        qd=DNSQR(qname="example.com"),
        an=DNSRR(rrname="example.com", ttl=60, rdata="93.184.216.34"),
    )
)

# NTP payloads — fixed 48 bytes; byte 0 encodes LI|VN|Mode:
#   0x23 = 00_100_011 → LI=0, NTPv4, Mode=3 (client)
#   0x24 = 00_100_100 → LI=0, NTPv4, Mode=4 (server)
_NTP_REQUEST  = bytes([0x23]) + bytes(47)
_NTP_RESPONSE = bytes([0x24]) + bytes(47)

# Syslog payloads — RFC 3164 text (fire-and-forget; no server response)
_SYSLOG_MSG1 = b"<34>Oct 11 22:14:15 mymachine sshd[1234]: Failed password for root"
_SYSLOG_MSG2 = b"<34>Oct 11 22:14:16 mymachine sshd[1234]: Accepted password for admin"


def _build_udp_multi_flow_pcap(path):
    c, s = _MULTI_CLIENT, _MULTI_SERVER
    write_pcap([
        make_udp_packet(c, s, 60001,  53, payload=_DNS_QUERY,    t=0.0),
        make_udp_packet(c, s, 60002, 123, payload=_NTP_REQUEST,  t=0.1),
        make_udp_packet(c, s, 60003, 514, payload=_SYSLOG_MSG1,  t=0.2),
        make_udp_packet(s, c,   53, 60001, payload=_DNS_RESPONSE, t=0.3),
        make_udp_packet(s, c,  123, 60002, payload=_NTP_RESPONSE, t=0.4),
        make_udp_packet(c, s, 60003, 514, payload=_SYSLOG_MSG2,  t=0.5),
        make_udp_packet(c, s, 60001,  53, payload=_DNS_QUERY,    t=0.6),
    ], path)


class TestUDPMultipleSimultaneousFlows:
    """
    Three concurrent UDP flows to well-known ports (DNS/NTP/Syslog).

    Verifies payload_bytes is computed correctly for auto-dissected protocols
    (DNS on port 53, NTP on port 123) and plain text (Syslog on port 514).
    """

    @pytest.fixture(scope="class")
    def flows(self, tmp_path_factory):
        pcap = str(tmp_path_factory.mktemp("pcap") / "udp_multi.pcap")
        _build_udp_multi_flow_pcap(pcap)
        result = run_reconstruction(pcap, filter="udp")
        assert len(result) == 3, f"Expected 3 flows, got {len(result)}"
        return result

    @pytest.fixture(scope="class")
    def flow_dns(self, flows):
        f = next((f for f in flows if f["dst_port"] == 53), None)
        assert f is not None, "No flow with dst_port=53"
        return f

    @pytest.fixture(scope="class")
    def flow_ntp(self, flows):
        f = next((f for f in flows if f["dst_port"] == 123), None)
        assert f is not None, "No flow with dst_port=123"
        return f

    @pytest.fixture(scope="class")
    def flow_syslog(self, flows):
        f = next((f for f in flows if f["dst_port"] == 514), None)
        assert f is not None, "No flow with dst_port=514"
        return f

    # --- common ---

    def test_all_termination_reasons(self, flows):
        for f in flows:
            assert f["termination_reason"] == "unknown"

    def test_all_protocols(self, flows):
        for f in flows:
            assert f["protocol"] == 17

    # --- DNS (auto-dissected by Scapy) ---

    def test_dns_packets_count(self, flow_dns):
        # t=0.0 query, t=0.3 response, t=0.6 repeated query
        assert flow_dns["packets_count"] == 3

    def test_dns_payload_bytes_total(self, flow_dns):
        assert flow_dns["payload_bytes_total"] == len(_DNS_QUERY) * 2 + len(_DNS_RESPONSE)

    def test_dns_payload_bytes_min_nonzero(self, flow_dns):
        assert flow_dns["payload_bytes_min_nonzero"] == len(_DNS_QUERY)

    def test_dns_duration_s(self, flow_dns):
        assert flow_dns["duration_s"] == pytest.approx(0.6)

    # --- NTP (fixed 48-byte packets) ---

    def test_ntp_packets_count(self, flow_ntp):
        assert flow_ntp["packets_count"] == 2

    def test_ntp_payload_bytes_total(self, flow_ntp):
        assert flow_ntp["payload_bytes_total"] == 96  # 48 + 48

    def test_ntp_payload_bytes_min(self, flow_ntp):
        assert flow_ntp["payload_bytes_min"] == 48

    def test_ntp_payload_bytes_max(self, flow_ntp):
        assert flow_ntp["payload_bytes_max"] == 48

    def test_ntp_duration_s(self, flow_ntp):
        assert flow_ntp["duration_s"] == pytest.approx(0.3)

    # --- Syslog (fire-and-forget text, no response) ---

    def test_syslog_packets_count(self, flow_syslog):
        assert flow_syslog["packets_count"] == 2

    def test_syslog_payload_bytes_total(self, flow_syslog):
        assert flow_syslog["payload_bytes_total"] == len(_SYSLOG_MSG1) + len(_SYSLOG_MSG2)

    def test_syslog_payload_bytes_min_nonzero(self, flow_syslog):
        assert flow_syslog["payload_bytes_min_nonzero"] == min(len(_SYSLOG_MSG1), len(_SYSLOG_MSG2))

    def test_syslog_payload_bytes_max(self, flow_syslog):
        assert flow_syslog["payload_bytes_max"] == max(len(_SYSLOG_MSG1), len(_SYSLOG_MSG2))

    def test_syslog_duration_s(self, flow_syslog):
        assert flow_syslog["duration_s"] == pytest.approx(0.3)