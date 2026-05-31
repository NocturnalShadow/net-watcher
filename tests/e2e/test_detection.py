"""
E2E tests for offline detection mode.

Run with -s to see the metrics table printed to stdout:
    venv/Scripts/python -m pytest tests/e2e/ -v -s

Scenarios:
  TestBenignFalsePositiveRate  — FPR across the full benign test dataset
  TestMaliciousRecall          — recall across the full malicious test dataset (per-class breakdown)
"""

import os
import subprocess
import sys

import pytest

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
_RUN_PY = os.path.join(_ROOT, 'src', 'run.py')
_PCAP_ROOT = os.path.join(_ROOT, 'pcap', 'icsx-ctu-extended', 'test')
_MALICIOUS_ROOT = os.path.join(_PCAP_ROOT, 'malicious')
_BENIGN_ROOT = os.path.join(_PCAP_ROOT, 'benign')
_ARTIFACTS_DIR = os.path.join(_ROOT, 'artifacts', 'icsx-ctu-extended')
_MODEL_PATH = os.path.join(_ARTIFACTS_DIR, 'dnn_16_16_16.keras')
# _MODEL_PATH = os.path.join(_ARTIFACTS_DIR, 'dnn_24_24_24.keras')
_SCALER_PATH = os.path.join(_ARTIFACTS_DIR, 'scaler.pkl')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_detector(input_path, output_dir, model_path=_MODEL_PATH, scaler_path=_SCALER_PATH):
    """Run the detector on a file or directory (recursive); return (alerts, oks)."""
    os.makedirs(output_dir, exist_ok=True)
    cmd = [
        sys.executable, _RUN_PY,
        '--role', 'detector',
        '--input-path', input_path,
        '--output-path', output_dir,
        '--output-filter', 'all',
        '--model-path', model_path,
        '--scaler-path', scaler_path,
    ]
    print(f"\n[run_detector] $ {' '.join(cmd)}", flush=True)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Detector failed on {input_path!r}:\n"
            f"--- stdout ---\n{result.stdout}\n"
            f"--- stderr ---\n{result.stderr}"
        )
    alerts, oks = _parse_events(output_dir)
    print(f"[run_detector] done — {alerts} ALERT  {oks} OK", flush=True)
    return alerts, oks


def _parse_events(output_dir):
    """Count [ALERT]/[OK] lines across all .log files in output_dir."""
    alerts, oks = 0, 0
    log_files = [
        os.path.join(output_dir, f)
        for f in os.listdir(output_dir)
        if f.endswith('.log')
    ]
    if not log_files:
        print(f"[_parse_events] WARNING: no .log files found in {output_dir!r}", flush=True)
    for path in log_files:
        with open(path) as f:
            for line in f:
                if '[ALERT]' in line:
                    alerts += 1
                elif '[OK]' in line:
                    oks += 1
    return alerts, oks


def _malicious_subdirs():
    """Return sorted list of (name, path) for each subdirectory of _MALICIOUS_ROOT."""
    if not os.path.isdir(_MALICIOUS_ROOT):
        return []
    seen = set()
    result = []
    for entry in os.scandir(_MALICIOUS_ROOT):
        if entry.is_dir() and entry.name not in seen:
            seen.add(entry.name)
            result.append((entry.name, entry.path))
    return sorted(result)


def _class_recall(metrics, name):
    r = metrics['per_class'][name]
    total = r['alerts'] + r['oks']
    return r['alerts'] / total if total else 0.0


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

class TestBenignFalsePositiveRate:
    """False positive rate across the full benign test dataset."""

    @pytest.fixture(scope='class')
    def metrics(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp('benign')
        ben_alerts, ben_oks = run_detector(_BENIGN_ROOT, str(tmp))
        ben_total = ben_alerts + ben_oks
        fpr = ben_alerts / ben_total if ben_total else 0.0

        print(f"\n{'='*52}")
        print(f"  Benign False Positive Rate  (E2E · default threshold)")
        print(f"{'='*52}")
        print(f"  Benign: {ben_total:>6} flows — {ben_alerts:>6} ALERT  {ben_oks:>6} OK")
        print(f"  {'-'*48}")
        print(f"  False Positive Rate:  {fpr:.4f}  ({ben_alerts}/{ben_total})")
        print(f"{'='*52}")

        return {'fpr': fpr, 'ben_alerts': ben_alerts, 'ben_total': ben_total}

    def test_false_positive_rate(self, metrics):
        assert metrics['fpr'] < 0.0031, (
            f"FPR {metrics['fpr']:.4f} exceeds threshold 0.0031 "
            f"({metrics['ben_alerts']}/{metrics['ben_total']})"
        )


class TestMaliciousRecall:
    """Recall across the full malicious test dataset, with per-class breakdown."""

    @pytest.fixture(scope='class')
    def metrics(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp('malicious')
        subdirs = _malicious_subdirs()

        per_class = {}
        total_alerts = 0
        total_oks = 0

        for name, path in subdirs:
            out = os.path.join(str(tmp), name)
            alerts, oks = run_detector(path, out)
            per_class[name] = {'alerts': alerts, 'oks': oks}
            total_alerts += alerts
            total_oks += oks

        # Fallback: no subdirs — run on the whole malicious root
        if not subdirs:
            total_alerts, total_oks = run_detector(_MALICIOUS_ROOT, str(tmp))

        total = total_alerts + total_oks
        recall = total_alerts / total if total else 0.0

        return {
            'recall': recall,
            'mal_alerts': total_alerts,
            'mal_total': total,
            'per_class': per_class,
        }

    def test_breakdown(self, metrics):
        """Print per-class recall table (no assertion — informational only)."""
        per_class = metrics['per_class']
        print(f"\n{'='*52}")
        print(f"  Malicious Recall — Per-Class Breakdown")
        print(f"{'='*52}")
        for name, r in sorted(per_class.items()):
            cls_total = r['alerts'] + r['oks']
            cls_recall = r['alerts'] / cls_total if cls_total else 0.0
            print(f"  {name:<28} {cls_recall:.4f}  ({r['alerts']}/{cls_total})")
        print(f"  {'-'*48}")
        print(f"  Overall Recall:  {metrics['recall']:.4f}  ({metrics['mal_alerts']}/{metrics['mal_total']})")
        print(f"{'='*52}")

    # Overall
    def test_recall(self, metrics):
        assert metrics['recall'] >= 0.830, (
            f"Recall {metrics['recall']:.4f} < 0.830 "
            f"({metrics['mal_alerts']}/{metrics['mal_total']})"
        )

    # Per-class
    def test_recall_donbot(self, metrics):
        r = _class_recall(metrics, 'DonBot')
        assert r >= 0.910, f"DonBot recall {r:.4f} < 0.910"

    def test_recall_emotet(self, metrics):
        r = _class_recall(metrics, 'Emotet')
        assert r >= 0.970, f"Emotet recall {r:.4f} < 0.970"

    def test_recall_kazy(self, metrics):
        r = _class_recall(metrics, 'Kazy')
        assert r >= 0.530, f"Kazy recall {r:.4f} < 0.530"

    def test_recall_murlo(self, metrics):
        r = _class_recall(metrics, 'Murlo')
        assert r >= 0.300, f"Murlo recall {r:.4f} < 0.300"

    def test_recall_neris(self, metrics):
        r = _class_recall(metrics, 'Neris')
        assert r >= 0.660, f"Neris recall {r:.4f} < 0.660"

    def test_recall_rbot(self, metrics):
        r = _class_recall(metrics, 'RBot')
        assert r >= 0.940, f"RBot recall {r:.4f} < 0.940"

    def test_recall_trickbot(self, metrics):
        r = _class_recall(metrics, 'TrickBot')
        assert r >= 0.997, f"TrickBot recall {r:.4f} < 0.997"

    def test_recall_virut(self, metrics):
        r = _class_recall(metrics, 'Virut')
        assert r >= 0.950, f"Virut recall {r:.4f} < 0.950"

    def test_recall_wannacry(self, metrics):
        r = _class_recall(metrics, 'WannaCry')
        assert r >= 0.610, f"WannaCry recall {r:.4f} < 0.610"

    # Weasel: synthetic, unseen-by-training botnet — generalization probe (lower bar).
    # Synthetic botnet traffic per Zhao et al., "Botnet detection based on traffic
    # behavior analysis and flow intervals":
    # https://www.researchgate.net/publication/259117704_Botnet_detection_based_on_traffic_behavior_analysis_and_flow_intervals
    def test_recall_weasel(self, metrics):
        r = _class_recall(metrics, 'Weasel')
        assert r >= 0.580, f"Weasel recall {r:.4f} < 0.580"

    def test_recall_zeus(self, metrics):
        r = _class_recall(metrics, 'Zeus')
        assert r >= 0.043, f"Zeus recall {r:.4f} < 0.043"
