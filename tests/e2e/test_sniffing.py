"""E2E test for online sniffing mode.

Runs the real detector in sniff mode (run.py --role detector --sniff) capturing
the loopback adapter, generates known local TCP and UDP traffic, and asserts the
program logs a detection event for each flow. Like the other e2e tests, it only
runs the program as a subprocess and inspects its output (the event log) — no
internals are touched.

A tight BPF filter restricts capture to the test's own ports, so background
loopback traffic doesn't pollute the event log. Each flow is made to terminate
*during* capture (TCP via FIN, UDP via a small --flow-max-packets) so its event
is written live, before the process is stopped.

Skips if a live capture socket can't be opened (no Npcap / insufficient privs).
Run with:
    venv/Scripts/python -m pytest tests/e2e/test_sniffing.py -v -s
"""
import os
import socket
import subprocess
import sys
import threading
import time

import pytest

from scapy.all import conf

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
_RUN_PY = os.path.join(_ROOT, 'src', 'run.py')
_ARTIFACTS_DIR = os.path.join(_ROOT, 'artifacts', 'icsx-ctu-extended')
_MODEL_PATH = os.path.join(_ARTIFACTS_DIR, 'dnn_16_16_16.keras')
_SCALER_PATH = os.path.join(_ARTIFACTS_DIR, 'scaler.pkl')

_MAX_PACKETS = 4  # small cap so the UDP flow terminates (and is analyzed) live


def _capture_available(iface):
    try:
        conf.L2listen(iface=iface).close()
        return True
    except Exception:
        return False


def _generate_traffic(tcp_server, udp_server, udp_port):
    """Drive one TCP exchange (ends in FIN) and several one-way UDP datagrams."""
    def tcp_serve():
        conn, _ = tcp_server.accept()
        conn.recv(100)
        conn.sendall(b"reply")
        conn.close()

    def udp_drain():
        for _ in range(_MAX_PACKETS + 2):
            try:
                udp_server.recvfrom(100)
            except OSError:
                return

    threading.Thread(target=tcp_serve, daemon=True).start()
    threading.Thread(target=udp_drain, daemon=True).start()

    # TCP: connect, exchange a few segments, close (FIN) -> >=3 packets, terminates live
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect(("127.0.0.1", tcp_server.getsockname()[1]))
    c.sendall(b"hello")
    c.recv(100)
    c.close()

    # UDP: more datagrams than --flow-max-packets so a >=3-packet flow terminates live
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(_MAX_PACKETS + 2):
        u.sendto(b"udp-%d" % i, ("127.0.0.1", udp_port))
        time.sleep(0.05)
    u.close()


def _read_events(output_dir):
    """Return all event log lines written under output_dir (recursively)."""
    lines = []
    for root, _dirs, files in os.walk(output_dir):
        for name in files:
            if name.endswith(".log"):
                with open(os.path.join(root, name)) as f:
                    lines.extend(f)
    return lines


class TestSniffing:
    """Reconstruct + detect live loopback TCP and UDP flows via online sniffing."""

    @pytest.fixture(scope="class")
    def events(self, tmp_path_factory):
        iface = conf.loopback_name
        if not _capture_available(iface):
            pytest.skip("live capture unavailable (no Npcap or insufficient privileges)")

        tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_server.bind(("127.0.0.1", 0))
        tcp_server.listen(1)
        udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_server.bind(("127.0.0.1", 0))
        tcp_port = tcp_server.getsockname()[1]
        udp_port = udp_server.getsockname()[1]

        output_dir = str(tmp_path_factory.mktemp("sniff"))
        bpf = f"tcp port {tcp_port} or udp port {udp_port}"

        cmd = [
            sys.executable, _RUN_PY,
            '--role', 'detector', '--sniff',
            '--net-interface', iface,
            '--output-path', output_dir,
            '--output-filter', 'all',
            '--filter', bpf,
            '--flow-max-packets', str(_MAX_PACKETS),
            '--model-path', _MODEL_PATH,
            '--scaler-path', _SCALER_PATH,
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, cwd=_ROOT)

        output = []
        ready = threading.Event()

        def reader():
            for line in proc.stdout:
                output.append(line)
                if "live traffic" in line:  # online() logs this just before capturing
                    ready.set()

        threading.Thread(target=reader, daemon=True).start()

        try:
            if not ready.wait(90):  # model load + capture startup
                proc.terminate()
                raise RuntimeError(f"sniffer never started capturing:\n{''.join(output)}")
            time.sleep(2.0)  # let the capture socket fully come up

            _generate_traffic(tcp_server, udp_server, udp_port)

            # Wait for flows to terminate live (TCP FIN grace ~3-8s) + be analyzed (~2s batch).
            time.sleep(14.0)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
            tcp_server.close()
            udp_server.close()

        lines = _read_events(output_dir)
        return {"lines": lines, "output": output}

    def test_tcp_event_logged(self, events):
        tcp_events = [l for l in events["lines"] if "(TCP)" in l]
        assert tcp_events, (
            "no TCP event logged.\n--- events ---\n"
            f"{''.join(events['lines'])}\n--- program output ---\n{''.join(events['output'])}"
        )

    def test_udp_event_logged(self, events):
        udp_events = [l for l in events["lines"] if "(UDP)" in l]
        assert udp_events, (
            "no UDP event logged.\n--- events ---\n"
            f"{''.join(events['lines'])}\n--- program output ---\n{''.join(events['output'])}"
        )