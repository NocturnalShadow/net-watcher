import time
import pickle
import os

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow as tf

from datetime import datetime
from enums import Protocol

from flow_features import flow_to_np
from logging_utils import try_log

model_location = "./artifacts/model.keras"
scaler_path = './artifacts/scaler.pkl'

# Function to classify a single flow
def classify_single_flow(flow, model, scaler, threshold=0.98):
    # Scale the flow features
    scaled_flow = scaler.transform([flow])
    prediction_prob = model.predict(scaled_flow, verbose=0).ravel()[0]
    predicted_class = (prediction_prob >= threshold).astype(int)
    return predicted_class, prediction_prob

def to_local_time(timestamp):
    dt = datetime.fromtimestamp(timestamp)
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def pretty_print_flow(flow, label=""):
    protocol = Protocol(flow['protocol']).name
    curent_time = to_local_time(time.time()) #(flow['timestamp'])
    flow_signature = f"{flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']} ({ protocol })"
    return f"{curent_time} {label} {flow_signature}"

def analyze_flows(network_flows, event_log_file, output_filter="all"):
    # TODO: turn into enum
    log_ok_events = output_filter == "all" or output_filter == "ok"
    log_alert_events = output_filter == "all" or output_filter == "alerts" 

    # Load the pretrained model
    model = tf.keras.models.load_model(model_location)

    # Load the scaler
    with open(scaler_path, 'rb') as f:
        scaler = pickle.load(f)

    while True:
        flow = network_flows.get()
        if flow is None:
            break
        
        if flow["packets_count"] < 3:
            continue

        features, meta = flow_to_np(flow)
        # print(f"Analyzing flow {meta}")
        predicted_class, _ = classify_single_flow(features, model, scaler, threshold=0.5)
        if predicted_class == 1 and log_alert_events:
            try_log(event_log_file, pretty_print_flow(flow, label="[ALERT]"))
        elif log_ok_events:
            try_log(event_log_file, pretty_print_flow(flow, label="[OK]"))

        network_flows.task_done()

# if __name__ == "__main__": 
#     input_pcap_file = "pcap/train/benign/benign.pcap"
#     network_flows = queue.Queue()
#     flow_analyzer_thread = threading.Thread(
#         target=analyze_flows,
#         args=(network_flows, ),
#         daemon=True)
#     flow_analyzer_thread.start()

#     with FlowReconstructor(output_queue=network_flows, net_interface=scapy.all.conf.iface, stats_log_step=100000) as reconstructor:
#         reconstructor.offline(input_pcap_file)

#     network_flows.put(None)
#     flow_analyzer_thread.join()
