import pandas as pd
import statistics

from enums import *
from logging_utils import log

import numpy as np
import os
import pyarrow as pa

# Feature columns, with the pyarrow type each is cast to at serialization time
# (see to_arrow_table). The "n" values are legacy positional ids.
flow_features_undirectional = [
    {"name": "duration_s", "n": 1, "type": pa.float64()},
    {"name": "packets_count", "n": 2, "type": pa.int64()},
    {"name": "payload_bytes_seq", "n": 3, "type": pa.list_(pa.int64())},
    {"name": "payload_bytes_total", "n": 4, "type": pa.int64()},
    {"name": "payload_bytes_min", "n": 5, "type": pa.int64()},
    {"name": "payload_bytes_max", "n": 6, "type": pa.int64()},
    {"name": "payload_bytes_std", "n": 7, "type": pa.float64()},
    {"name": "payload_bytes_min_nonzero", "n": 8, "type": pa.int64()},
    {"name": "payload_bytes_avg_nonzero", "n": 9, "type": pa.float64()},
    {"name": "payload_bytes_std_nonzero", "n": 10, "type": pa.float64()},
    {"name": "interarrival_time_s_seq", "n": 11, "type": pa.list_(pa.float64())},
    {"name": "interarrival_time_s_min", "n": 12, "type": pa.float64()},
    {"name": "interarrival_time_s_max", "n": 13, "type": pa.float64()},
    {"name": "interarrival_time_s_std", "n": 14, "type": pa.float64()},
    {"name": "syn_count", "n": 15, "type": pa.int64()},
    {"name": "fin_count", "n": 16, "type": pa.int64()},
    {"name": "rst_count", "n": 17, "type": pa.int64()},
    {"name": "ack_count", "n": 18, "type": pa.int64()},
    {"name": "psh_count", "n": 19, "type": pa.int64()},
    {"name": "urg_count", "n": 20, "type": pa.int64()},
    {"name": "ece_count", "n": 21, "type": pa.int64()},
    {"name": "cwr_count", "n": 22, "type": pa.int64()},
]

_n_undirectional = len(flow_features_undirectional)

flow_features_directional = [
    {"name": "window_size_seq", "n": _n_undirectional + 1, "type": pa.list_(pa.int64())},
    {"name": "window_size_min", "n": _n_undirectional + 3, "type": pa.int64()},
    {"name": "window_size_max", "n": _n_undirectional + 5, "type": pa.int64()},
    {"name": "window_size_avg", "n": _n_undirectional + 7, "type": pa.float64()},
    {"name": "window_size_std", "n": _n_undirectional + 9, "type": pa.float64()},
    {"name": "window_scaling_factor", "n": _n_undirectional + 11, "type": pa.int64()},
    {"name": "initial_window_size", "n": _n_undirectional + 13, "type": pa.int64()},
    {"name": "zero_window_count", "n": _n_undirectional + 15, "type": pa.int64()},
    {"name": "zero_window_update_count", "n": _n_undirectional + 17, "type": pa.int64()},
    # {"name": "zero_window_probe_count", "n": num_undirectional_features + 19, "type": pa.int64()},
]

def get_numeric_feature():
    numeric_fields = []
    # Order matters: first undirectional features, then directional
    for feature in flow_features_undirectional:
        numeric_fields.append(feature["name"])

    for prefix in ["bwd_", "fwd_"]:
        for feature in flow_features_directional:
            numeric_fields.append(prefix + feature["name"])
    
    return [field for field in numeric_fields if not field.endswith("_seq")]

flow_numeric_features = get_numeric_feature()

def flow_to_np_features(flow):
    return np.array([flow[field] for field in flow_numeric_features], dtype=np.float32)

def flows_df_to_np(df):
    feature_vectors = []
    metas = []
    for _, row in df.iterrows():
        features = np.array([row[field] for field in flow_numeric_features], dtype=np.float32)
        meta = {k: v for k, v in row.items() if k not in flow_numeric_features and not k.endswith("_seq")}
        feature_vectors.append(features)
        metas.append(meta)
    return np.array(feature_vectors), metas

def to_arrow_table(df):
    """Convert a flows DataFrame to a pyarrow Table, casting each feature column
    to its declared type. Explicit casts keep the parquet schema stable across
    shards — in particular an all-empty list column would otherwise infer
    list<null> and break reads that merge it with a typed shard."""
    table = pa.Table.from_pandas(df)
    for prefix, features in (("", flow_features_undirectional),
                             ("fwd_", flow_features_directional),
                             ("bwd_", flow_features_directional)):
        for feature in features:
            name = prefix + feature["name"]
            if name not in table.column_names:
                log.warning(f"Column '{name}' not found in the DataFrame.")
                continue
            i = table.schema.get_field_index(name)
            table = table.set_column(i, pa.field(name, feature["type"]),
                                     table.column(i).cast(feature["type"]))
    return table

def first_packet_time(flow):
    return float(flow["packets"][0].time)

def last_packet_time(flow):
    return float(flow["packets"][-1].time)

def calculate_tcp_window_features(flow, packets):
    feature_set = {
        'initial_window_size': 0,
        'window_scaling_factor': 1,
        'window_size_seq': [], # list of window sizes for ACK packets (scaled by window_scaling_factor)
        'window_size_min': 0,
        'window_size_max': 0,
        'window_size_avg': 0,
        'window_size_std': 0,
        'zero_window_count': 0,
        'zero_window_update_count': 0,
        # 'zero_window_probe_count': 0,
    }

    features = {
        Direction.FORWARD: feature_set,
        Direction.BACKWARD: feature_set.copy()
    }

    ack_window_sizes = {Direction.FORWARD: [], Direction.BACKWARD: []}

    for packet in packets:
        direction = packet.direction
        flags = packet.tcp_flags

        if flags & TCPFlag.SYN:
            # WScale was pre-extracted during packet parsing; defaults to 1 if absent.
            features[direction]["window_scaling_factor"] = packet.tcp_wscale
            features[direction]['initial_window_size'] = packet.tcp_window

        # Adjust window size by scaling factor
        packet_window_size = packet.tcp_window * features[direction]["window_scaling_factor"]

        # Only consider ACK packets for window size stats (other than initial_window_size)
        if flags & TCPFlag.ACK:
            ack_window_sizes[direction].append(packet_window_size)

    # Calculate average and standard deviation for window sizes
    for direction in [Direction.FORWARD, Direction.BACKWARD]:
        window_sizes = ack_window_sizes[direction]
        features[direction]['window_size_seq'] = window_sizes
        features[direction]['window_size_min'] = min(window_sizes) if window_sizes else 0
        features[direction]['window_size_max'] = max(window_sizes) if window_sizes else 0
        features[direction]['window_size_avg'] = sum(window_sizes) / len(window_sizes) if window_sizes else 0
        features[direction]['window_size_std'] = statistics.stdev(window_sizes) if len(window_sizes) > 1 else 0
        features[direction]['zero_window_count'] = window_sizes.count(0)
        features[direction]['zero_window_update_count'] = sum(1 for i in range(1, len(window_sizes)) 
                                                            if window_sizes[i-1] == 0 and window_sizes[i] != 0)
        # TODO: zero_window_probe_count = 1+ byte of payload packets until window size transitions from 0 to non-zero

    # Prefix features with direction
    for direction, prefix in [(Direction.FORWARD, 'fwd_'), (Direction.BACKWARD, 'bwd_')]:
        for key, value in features[direction].items():
            flow[f'{prefix}{key}'] = value

    return flow

def calculate_features(flow):
    # NOTE: flow packets must be preprocessed before calling this function
    packets = flow["packets"]
    # Sort by timestamp so out-of-order packets don't yield negative inter-arrivals.
    packets.sort(key=lambda packet: packet.time)
    interarrival_time_s_seq = [float(packets[i].time - packets[i-1].time) for i in range(1, len(packets))] if len(packets) > 1 else []
    payload_bytes_seq = [packet.payload_bytes for packet in packets]
    src_ip = flow["src_ip"]
    dst_ip = flow["dst_ip"]
    sport = flow["sport"]
    dport = flow["dport"]
    protocol = flow["protocol"]
    # TODO: consider merging with the flow object to avoid different meanign of "flow" in different contexts (or just use classes)
    flow = {
        "id": f"{src_ip}-{dst_ip}-{sport}-{dport}-{protocol}",
        "timestamp": float(packets[0].time),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": sport,
        "dst_port": dport,
        "protocol": protocol,
        "termination_reason": flow["termination_reason"],
        "duration_s": float(packets[-1].time - packets[0].time),
        "packets_count": len(packets),
        "payload_bytes_seq": payload_bytes_seq,
        "payload_bytes_total": sum(payload_bytes_seq),
        "payload_bytes_min": min(payload_bytes_seq) if payload_bytes_seq else 0, # Consider discarding SYN, FIN and RST min (or remove this feature altogether)
        "payload_bytes_max": max(payload_bytes_seq) if payload_bytes_seq else 0,
        "payload_bytes_std": statistics.stdev(payload_bytes_seq) if len(payload_bytes_seq) > 1 else 0,
        "interarrival_time_s_seq": interarrival_time_s_seq,
        "interarrival_time_s_min": min(interarrival_time_s_seq) if interarrival_time_s_seq else 0,
        "interarrival_time_s_max": max(interarrival_time_s_seq) if interarrival_time_s_seq else 0,
        "interarrival_time_s_std": statistics.stdev(interarrival_time_s_seq) if len(interarrival_time_s_seq) > 1 else 0,
        # TODO: add fwd/bwd ratio (bytes, backet count, duration) OR separate features for each direction
        # TODO: consider UPD packets sizes with no payload (e.g. DNS requests with no resolution result)
        # TODO: verify that duration is always <= active timeout
        # TODO: verify that max interarrival time is always <= idle timeout
        # TODO: consider adding more features:
        # - bulk throughput, download/upload ratio
        # - active-to-idle time ratio
        # - number of packets with at least 1 byte payload
        # - number of packets with no payload
        # - number of packets falling into a specific "bucket" (of payload sizes, interarrival times, window sizes, etc.)
        # - Active periods duration (subsequent packets are passed in less than a certain time)
        # - Idle periods duration (no packets are passed in more than a certain time)
    }

    payload_bytes_seq_nonzero = [x for x in payload_bytes_seq if x > 0]
    flow["payload_bytes_min_nonzero"] = min(payload_bytes_seq_nonzero) if payload_bytes_seq_nonzero else 0
    flow["payload_bytes_avg_nonzero"] = sum(payload_bytes_seq_nonzero) / len(payload_bytes_seq_nonzero) if payload_bytes_seq_nonzero else 0
    flow["payload_bytes_std_nonzero"] = statistics.stdev(payload_bytes_seq_nonzero) if len(payload_bytes_seq_nonzero) > 1 else 0

    if flow["protocol"] == Protocol.TCP.value:
        flags = [packet.tcp_flags for packet in packets]
        flow["syn_count"] = sum([1 for flag in flags if flag & TCPFlag.SYN])
        flow["fin_count"] = sum([1 for flag in flags if flag & TCPFlag.FIN])
        flow["rst_count"] = sum([1 for flag in flags if flag & TCPFlag.RST])
        flow["ack_count"] = sum([1 for flag in flags if flag & TCPFlag.ACK])
        flow["psh_count"] = sum([1 for flag in flags if flag & TCPFlag.PSH])
        flow["urg_count"] = sum([1 for flag in flags if flag & TCPFlag.URG])
        flow["ece_count"] = sum([1 for flag in flags if flag & TCPFlag.ECE])
        flow["cwr_count"] = sum([1 for flag in flags if flag & TCPFlag.CWR])

        calculate_tcp_window_features(flow, packets)

        # TODO: add TCP features: 
        # - (TCP) header size, initial RTT (SYN -> SYN-ACK), RTT statisitcs
        # - retransmissions, duplicate ACKs, out-of-order packets
        # - termination direction (when adding directional features)

    else:
        flow["syn_count"] = 0
        flow["fin_count"] = 0
        flow["rst_count"] = 0
        flow["ack_count"] = 0
        flow["psh_count"] = 0
        flow["urg_count"] = 0
        flow["ece_count"] = 0
        flow["cwr_count"] = 0
        flow["window_size_max"] = 0
        flow["window_size_min"] = 0
        flow["window_size_avg"] = 0
        flow["window_size_std"] = 0

        for prefix in ["fwd_", "bwd_"]:
            flow[prefix + "window_size_seq"] = []
            flow[prefix + "window_size_min"] = 0
            flow[prefix + "window_size_max"] = 0
            flow[prefix + "window_size_avg"] = 0
            flow[prefix + "window_size_std"] = 0
            flow[prefix + "window_scaling_factor"] = 0
            flow[prefix + "initial_window_size"] = 0
            flow[prefix + "zero_window_count"] = 0
            flow[prefix + "zero_window_update_count"] = 0
            # flow[prefix + "zero_window_probe_count"] = 0

    return flow

if __name__ == "__main__":
    # Load DataFrame from Parquet dataset
    dataset_path = os.path.join("flows", "train", "Neris")
    df = pd.read_parquet(dataset_path)
    print(f"Loaded DataFrame with {len(df)} rows.")

    # Convert DataFrame to array
    vectors, metas = flows_df_to_np(df)

    print(f"Loaded {len(vectors)} flow vectors.")
    print(f"First row: {df.iloc[0]}")
    print(f"Vector shape: {vectors.shape}")
    print(f"Meta data: {metas[0]}")
    print(f"Vector: {vectors[0]}")
