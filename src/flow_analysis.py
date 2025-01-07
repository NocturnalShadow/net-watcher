import os
import sys
import time
import pickle

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import numpy as np
import tensorflow as tf

from datetime import datetime
from enums import Protocol

from flow_features import flow_to_np_and_meta
from logging_utils import *

def get_resource_path(relative_path):
    """ Get the absolute path to a resource, works for dev and for PyInstaller """
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")
    return os.path.normpath(os.path.join(base_path, relative_path))

model_location = get_resource_path("./artifacts/model.keras")
scaler_path = get_resource_path("./artifacts/scaler.pkl")

# Function to classify a single flow
def classify_single_flow(flow, model, scaler, threshold=0.98):
    # Scale the flow features
    scaled_flow = scaler.transform([flow])
    prediction_prob = model.predict(scaled_flow, verbose=0).ravel()[0]
    predicted_class = (prediction_prob >= threshold).astype(int)
    return predicted_class, prediction_prob

# Function to classify a batch of flows
def classify_flows(flows, model, scaler, threshold=0.98):
    # Scale the flow features
    scaled_flows = scaler.transform(flows)
    prediction_probs = model.predict(scaled_flows, verbose=0).ravel()
    predicted_classes = (prediction_probs >= threshold).astype(int)
    return predicted_classes, prediction_probs

def to_local_time(timestamp):
    dt = datetime.fromtimestamp(timestamp)
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def pretty_print_flow(flow, label=""):
    protocol = Protocol(flow['protocol']).name
    curent_time = to_local_time(time.time())
    duration_s = flow['duration_s']
    if duration_s < 1:
        duration_str = f"{round(duration_s * 1000)} ms"
    else:
        seconds = int(duration_s)
        milliseconds = round((duration_s - seconds) * 1000)
        duration_str = f"{seconds}s {milliseconds}ms"
    flow_signature = f"{flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']} ({protocol}): {flow['packets_count']} packets, {flow['payload_bytes_total']} bytes, {duration_str}"
    return f"{curent_time} {label} {flow_signature}"

def analyze_flows(network_flows, event_log_file, output_filter="all", stop_event=None):
    try:
        _analyze_flows(network_flows, event_log_file, output_filter, stop_event)
    except Exception as e:
        log.error(f"Flow analysis failed: {e}", exc_info=True)
        raise e

def _analyze_flows(network_flows, event_log_file, output_filter="all", stop_event=None):
    # TODO: turn into enum
    log_ok_events = output_filter == "all" or output_filter == "ok"
    log_alert_events = output_filter == "all" or output_filter == "alerts" 

    # Load the pretrained model
    model = tf.keras.models.load_model(model_location)

    # Load the scaler
    with open(scaler_path, 'rb') as f:
        scaler = pickle.load(f)

    flows_batch = []
    features_batch = []
    batch_size = 64
    wait_timeout = 2
    threshold = 0.98
    start_wait_time = time.time()
    analyzed_flows_count = 0
    skipped_flows_count = 0

    def process_batch():
        predicted_classes, _ = classify_flows(np.array(features_batch), model, scaler, threshold)
        for flow_class, flow in zip(predicted_classes, flows_batch):
            if flow_class == 1 and log_alert_events:
                try_log(event_log_file, pretty_print_flow(flow, label="[ALERT]"))
            elif log_ok_events:
                try_log(event_log_file, pretty_print_flow(flow, label="[OK]"))

    while True:
        if network_flows.qsize() >= batch_size or (time.time() - start_wait_time >= wait_timeout):
            while not network_flows.empty() and len(features_batch) < batch_size:
                flow = network_flows.get()
                if flow is None:
                    if features_batch:
                        process_batch()
                    log.info(f"Finished analyzing flows in the queue. Analyzed: {analyzed_flows_count}, Skipped: {skipped_flows_count}")
                    return
                if flow["packets_count"] < 3:
                    skipped_flows_count += 1
                    continue
                features, _ = flow_to_np_and_meta(flow)
                flows_batch.append(flow)
                features_batch.append(features)
                analyzed_flows_count += 1

            if features_batch:
                start_wait_time = time.time()
                process_batch()
                features_batch = []
                metas_batch = []
        
        if stop_event is not None and stop_event.is_set():
            log.info("Flow analysis was interupted...")
            return
        
        time.sleep(0.1)

if __name__ == "__main__": 
    import queue
    import threading
    import scapy.all
    from flow_reconstruction import FlowReconstructor
    from logging_utils import configure_app_logger

    configure_app_logger()

    output_filter = "all"
    event_log_file = "log/flow_analysis_debug.log"
    input_pcap_file = "pcap/train/malicious/IRC.pcap"
    network_flows = queue.Queue()
    stop_event = threading.Event()
    flow_analyzer_thread = threading.Thread(
        target=analyze_flows,
        args=(network_flows, event_log_file, output_filter),
        daemon=True)
        
    flow_analyzer_thread.start()

    with FlowReconstructor(output_queue=network_flows, net_interface=scapy.all.conf.iface, stats_log_step=10000) as reconstructor:
        reconstructor.offline(input_pcap_file)
    network_flows.put(None)
    flow_analyzer_thread.join()

