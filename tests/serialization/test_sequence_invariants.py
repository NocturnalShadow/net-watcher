"""
Serialization tests for the per-packet sequence columns.

Reconstructs flows, writes them to a parquet dataset the same way the observer
role does (flow_features.to_arrow_table), reads them back, and checks the
sequence-length / ordering invariants:
  TestSinglePacketFlow    — empty inter-arrival stays empty (not padded to [0.0])
  TestOutOfOrderPackets   — inter-arrivals are non-negative after timestamp sort
"""
import pandas as pd
import pyarrow.parquet as pq
import pytest

from flow_features import to_arrow_table
from helpers import make_tcp_packet, write_pcap, run_reconstruction


def _serialize_roundtrip(flows, out_dir):
    """Write reconstructed flows to a parquet dataset and read them back."""
    pq.write_to_dataset(to_arrow_table(pd.DataFrame(flows)), root_path=str(out_dir))
    return pd.read_parquet(str(out_dir))


# ---------------------------------------------------------------------------
# Scenario: single-packet flow (lone SYN)
#
#   t=0.0  SYN  client→server   ← 1 packet, no inter-arrival gaps
# ---------------------------------------------------------------------------

def _build_single_packet_pcap(path):
    write_pcap([
        make_tcp_packet("10.0.20.1", "10.0.20.2", 5555, 80, "S", seq=100, ack=0, t=0.0),
    ], path)


class TestSinglePacketFlow:
    """A single-packet flow has no gaps: interarrival stays [] through parquet."""

    @pytest.fixture(scope="class")
    def row(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("single")
        _build_single_packet_pcap(str(tmp / "single.pcap"))
        flows = run_reconstruction(str(tmp / "single.pcap"))
        assert len(flows) == 1, f"Expected 1 flow, got {len(flows)}"
        df = _serialize_roundtrip(flows, tmp / "dataset")
        return df.iloc[0]

    def test_packets_count(self, row):
        assert row["packets_count"] == 1

    def test_payload_seq_length(self, row):
        assert len(row["payload_bytes_seq"]) == row["packets_count"]

    def test_interarrival_seq_empty(self, row):
        assert len(row["interarrival_time_s_seq"]) == 0


# ---------------------------------------------------------------------------
# Scenario: out-of-order packets (t=0.5 recorded before t=0.4)
#
#   t=0.0  SYN          client→server
#   t=0.1  SYN-ACK      server→client
#   t=0.2  ACK          client→server
#   t=0.5  PSH+ACK 10B  client→server   ← later timestamp appears first
#   t=0.4  PSH+ACK 30B  server→client   ← out of order
#   t=0.6  ACK          client→server
#   t=1.0  FIN+ACK      client→server
#   t=1.5  FIN+ACK      server→client
#   t=2.5  ACK          client→server
# ---------------------------------------------------------------------------

def _build_out_of_order_pcap(path):
    c, s, sp, dp = "10.0.21.1", "10.0.21.2", 4444, 80
    write_pcap([
        make_tcp_packet(c, s, sp, dp, "S",  seq=100, ack=0,   t=0.0),
        make_tcp_packet(s, c, dp, sp, "SA", seq=200, ack=101, t=0.1),
        make_tcp_packet(c, s, sp, dp, "A",  seq=101, ack=201, t=0.2),
        make_tcp_packet(c, s, sp, dp, "PA", seq=101, ack=201, payload=b"A" * 10, t=0.5),
        make_tcp_packet(s, c, dp, sp, "PA", seq=201, ack=111, payload=b"B" * 30, t=0.4),
        make_tcp_packet(c, s, sp, dp, "A",  seq=111, ack=231, t=0.6),
        make_tcp_packet(c, s, sp, dp, "FA", seq=111, ack=231, t=1.0),
        make_tcp_packet(s, c, dp, sp, "FA", seq=231, ack=112, t=1.5),
        make_tcp_packet(c, s, sp, dp, "A",  seq=112, ack=232, t=2.5),
    ], path)


class TestOutOfOrderPackets:
    """Out-of-order capture timestamps must not produce negative inter-arrivals."""

    @pytest.fixture(scope="class")
    def row(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("ooo")
        _build_out_of_order_pcap(str(tmp / "ooo.pcap"))
        flows = run_reconstruction(str(tmp / "ooo.pcap"))
        assert len(flows) == 1, f"Expected 1 flow, got {len(flows)}"
        df = _serialize_roundtrip(flows, tmp / "dataset")
        return df.iloc[0]

    def test_packets_count(self, row):
        assert row["packets_count"] == 9

    def test_payload_seq_length(self, row):
        assert len(row["payload_bytes_seq"]) == row["packets_count"]

    def test_interarrival_seq_length(self, row):
        assert len(row["interarrival_time_s_seq"]) == row["packets_count"] - 1

    def test_interarrival_non_negative(self, row):
        assert min(row["interarrival_time_s_seq"]) >= 0

    def test_duration_non_negative(self, row):
        assert row["duration_s"] >= 0


class TestMixedShardsMerge:
    """A shard whose sequences are all empty must merge with a populated shard
    on read: the explicit cast keeps both as list<int64/double> instead of
    letting the empty shard infer list<null> (which fails to unify on read)."""

    @pytest.fixture(scope="class")
    def df(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("mixed")
        _build_single_packet_pcap(str(tmp / "single.pcap"))  # all sequences empty
        _build_out_of_order_pcap(str(tmp / "multi.pcap"))    # populated sequences
        dataset = tmp / "dataset"
        for pcap in ("single.pcap", "multi.pcap"):
            flows = run_reconstruction(str(tmp / pcap))
            pq.write_to_dataset(to_arrow_table(pd.DataFrame(flows)), root_path=str(dataset))
        return pd.read_parquet(str(dataset))

    def test_row_count(self, df):
        assert len(df) == 2

    def test_lengths_consistent(self, df):
        for _, row in df.iterrows():
            assert len(row["payload_bytes_seq"]) == row["packets_count"]
            assert len(row["interarrival_time_s_seq"]) == row["packets_count"] - 1
