import argparse
import queue
import threading
import logging
import os, glob

import scapy
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from flow_reconstruction import FlowReconstructor
from flow_analysis import analyze_flows
from flow_features import ensure_type_consistency
from logging_utils import *
from enums import *

# needed for pyinstaller to work
import sklearn 

# Offline flow analysis (from PCAP files)
# python src/run.py --role observer --input-path pcap/train/malicious/ --output-path flows/train/ --output-batch-size 1000
# python src/run.py --role detector --input-path pcap/train/malicious/ --output-path log/

# Online flow analysis (sniffing)
# python src/run.py --role observer --sniff --output-path flows/sniffed/ --stats-log-step 500 --output-batch-size 50
# python src/run.py --role detector --sniff --output-path log/ --stats-log-step 500

# With custom network interface
# python src/run.py --role observer --sniff --net-interface "Software Loopback Interface 1" --output-path log/ --stats-log-step 500
# python src/run.py --role detector --sniff --net-interface "Software Loopback Interface 1" --output-path log/ --stats-log-step 500


def log_operational_info(args):
    operational_role = 'Reconstructing flows' if args.role == 'observer' else 'Detecting threats'
    network_role = 'online' if args.sniff else 'offline'
    source = args.input_path if not args.sniff else args.net_interface
    log.info(f"""{operational_role} [{network_role}]...
                                Source: {source}
                                Output: {args.output_path}
                                Output batch size: {args.output_batch_size}
                                Flow idle timeout: {args.flow_idle_timeout}
                                Flow activity timeout: {args.flow_activity_timeout}""")

def main():
    parser = argparse.ArgumentParser(description="Process data online or offline.")
    
    # Add parameters
    parser.add_argument('--role', type=str, choices=['observer', 'detector'], required=True, help='Execution role: observer (network flows reconstruction) or detector (threat detection)')
    parser.add_argument('--sniff', action='store_true', help='Enable online sniffing role')
    parser.add_argument('--net-interface', type=str, help='Network interface to capture packets from (can only be used with --sniff). If not specified, the default one will be used.')
    parser.add_argument('--input-path', type=str, help='Path to a file or directory containing PCAP files for analysis (can not be used with --sniff)')
    parser.add_argument('--output-path', type=str, help='Path to a directory where network flows (--role observer) or detection events (--role detector) will be stored')
    parser.add_argument('--output-filter', type=str, default='alerts', help='The type of the events to output: ok, alerts or all (default "alerts") (--role detector only)')
    parser.add_argument('--output-batch-size', type=int, default=5000, help='Batch size for dumping the flows to disk during reconstruction (--role observer only)')
    parser.add_argument('--flow-activity-timeout', type=int, default=1000, help='Flow activity timeout in seconds')
    parser.add_argument('--flow-idle-timeout', type=int, default=600, help='Flow idle timeout in seconds')
    parser.add_argument('--stats-log-step', type=int, default=100_000, help='Log traffic processing statistics every N packets')
    parser.add_argument('--log-path', type=str, help='Path to the application log file. If not specified, logs will be sent to stdout.')

    args = parser.parse_args()
    kwargs = {k: v for k, v in vars(args).items() if v is not None} # remove None values

    # Setup logging
    configure_app_logger(args.log_path, level=logging.INFO, maxFileSizeMb=5)

    if args.log_path:
        print("================================================================")
        print("=========================> NetWatcher <=========================")
        print("================================================================")
        print(f"Output path: {args.output_path}")
        print(f"Application logs path: {args.log_path}")

    # Validate parameters
    if args.sniff and args.input_path:
        parser.error("--sniff and --input-path cannot be used together.")
    if args.net_interface:
        if args.sniff:
            parser.error("--net-interface can only be used with --sniff.")
    else:
        # use default network interface if not specified
        kwargs["net_interface"] = str(scapy.all.conf.iface)

    # Validate output_filter
    if args.role == 'detector' and args.output_filter not in ['ok', 'alerts', 'all']:
        parser.error("--output-filter must be one of 'ok', 'alerts', or 'all'.")

    try:
        log_operational_info(args) # TODO: pass kwargs instead of args
        if args.role == 'observer':
            if args.sniff:
                flow_reconstruction_online(**kwargs)
            else:
                flow_reconstruction_offline(**kwargs)
        elif args.role == 'detector':
            if args.sniff:
                detection_online(**kwargs)
            else:
                detection_offline(**kwargs)
        else:
            raise ValueError(f"Invalid role: {args.role}")
    except Exception as e:
        logging.error(e, exc_info=True)
    except KeyboardInterrupt:
        logging.info("Execution interrupted by user. Finishing the process...")

def setup_sniff_output_path(**kwargs):
    output_path = kwargs.get("output_path")
    if os.path.isfile(output_path):
        raise ValueError(f"The destination path '{output_path}' is a file, not a directory.")

    net_interface_sanitized = ''.join(e for e in kwargs.get("net_interface") if e.isalnum() or e.isspace())
    # create a subdirectory named after the network interface
    output_path = os.path.abspath(os.path.join(output_path, net_interface_sanitized))
    os.makedirs(output_path, exist_ok=True)

    return output_path

def detection_online(**kwargs):
    net_interface = kwargs.get("net_interface")
    output_path = setup_sniff_output_path(**kwargs)
    output_filter = kwargs.get("output_filter")
    event_log_file = os.path.join(output_path, "detector_events.log")
    log.info(f"Running threat detection for interface {net_interface}")
    log.info(f"Detection events will be logged to {event_log_file}")
    log.info(f"Events output filter: {output_filter}")

    event_log_rotator_thread = start_log_rotation(
        event_log_file, interval=60, max_log_files=10, max_file_size=5*1024*1024) # TODO: make configurable

    network_flows = queue.Queue()
    flow_analyzer_thread = threading.Thread(
        target=analyze_flows,
        args=(network_flows, event_log_file, output_filter),
        daemon=True)
    flow_analyzer_thread.start()
    
    with FlowReconstructor(output_queue=network_flows, **kwargs) as reconstructor:
        reconstructor.online()

    network_flows.put(None)

    flow_analyzer_thread.join()
    event_log_rotator_thread.join()

def detection_offline(**kwargs):
    input_path = kwargs.get("input_path")
    output_path = kwargs.get("output_path")
    output_filter = kwargs.get("output_filter")

    os.makedirs(output_path, exist_ok=True)

    def process_pcap_file(input_pcap_file):
        event_log_file = os.path.join(output_path, f"{os.path.basename(input_pcap_file)}.log")
        log.info(f"Running threat detection for {input_pcap_file}")
        log.info(f"Detection events will be logged to {event_log_file}")

        network_flows = queue.Queue()
        flow_analyzer_thread = threading.Thread(
            target=analyze_flows,
            args=(network_flows, event_log_file, output_filter),
            daemon=True)
        flow_analyzer_thread.start()

        with FlowReconstructor(output_queue=network_flows, **kwargs) as reconstructor:
            reconstructor.offline(input_pcap_file)

        network_flows.put(None)
        flow_analyzer_thread.join()

    src_pcap_files = locate_pcap_files(input_path)
    for src_pcap_file in src_pcap_files:
        process_pcap_file(src_pcap_file)

def flow_reconstruction_online(**kwargs):
    output_path = setup_sniff_output_path(**kwargs)

    network_flows = queue.Queue()
    flows_writer_thread = batch_process_async(
        network_flows,
        lambda buffer: save_as_df(buffer, output_path),
        batch_size=kwargs.get("output_batch_size"))

    with FlowReconstructor(output_queue=network_flows, **kwargs) as reconstructor:
        reconstructor.online()

    network_flows.put(None)
    flows_writer_thread.join()

def flow_reconstruction_offline(**kwargs):
    input_path = kwargs.get("input_path")
    output_path = kwargs.get("output_path")
    if os.path.isfile(output_path):
        raise ValueError(f"The destination path '{output_path}' is a file, not a directory.")

    # create destination folder if it doesn't exist
    os.makedirs(output_path, exist_ok=True)

    def process_pcap_file(input_pcap_file, output_path):
        network_flows = queue.Queue()
        flows_writer = batch_process_async(
            network_flows,
            lambda buffer: save_as_df(buffer, output_path),
            batch_size=kwargs.get("output_batch_size"))

        with FlowReconstructor(output_queue=network_flows, **kwargs) as reconstructor:
            reconstructor.offline(input_pcap_file)

        network_flows.put(None)
        flows_writer.join()

    src_pcap_files = locate_pcap_files(input_path)
    for src_pcap_file in src_pcap_files:
        # for each source pcap file there will be a destination subdirectory
        src_pcap_name = os.path.splitext(os.path.basename(src_pcap_file))[0]
        dest_subdir_path = os.path.join(output_path, src_pcap_name)
        clear_parquet_files(dest_subdir_path)
        process_pcap_file(src_pcap_file, dest_subdir_path)

def locate_pcap_files(input_path):
    file_ext = "*.pcap"
    if os.path.isdir(input_path):
        src_pcap_files = glob.glob(os.path.join(input_path, '**', file_ext), recursive=True)
        if not src_pcap_files:
            raise ValueError(f"No pcap files found in the source directory: {input_path}")
    else:
        if not os.path.exists(input_path): 
            raise ValueError(f"Path does not exist: {input_path}")
        if not input_path.endswith(file_ext[1:]):
            raise ValueError(f"Invalid file extension: {input_path}, expected {file_ext}")
        src_pcap_files = [input_path]
    return src_pcap_files

def save_as_df(buffer, path):
    df = pd.DataFrame(buffer)
    df = ensure_type_consistency(df)
    table = pa.Table.from_pandas(df)
    os.makedirs(path, exist_ok=True)
    pq.write_to_dataset(table, root_path=path, partition_cols=None)

def clear_parquet_files(path):
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.endswith(".parquet"):
                    os.remove(os.path.join(root, file))
    elif os.path.isfile(path) and path.endswith(".parquet"):
        os.remove(path)

def batch_process(queue, action, batch_size):
    buffer = []
    while True:
        element = queue.get()
        if element is None:
            if buffer:
                action(buffer)
            break

        buffer.append(element)
        if len(buffer) >= batch_size:
            action(buffer)
            buffer.clear()

def batch_process_async(_queue, action, batch_size):
    def try_batch_process(_queue, action, batch_size):
        try:
            batch_process(_queue, action, batch_size)
        except Exception as e:
            log.error(f"Batch processing failed: {e}")
            raise e

    t = threading.Thread(
        target=try_batch_process,
        args=(_queue, action, batch_size),
        daemon=True)
    t.start()
    return t

if __name__ == "__main__":
    main()

    # input_path = "pcap/benign/benign.pcap"
    # output_path = "flows/"
    # flow_reconstruction_offline(input_path, output_path, 500)

    ## output_path = "flows/sniffed"
    # df = pd.read_parquet(output_path)
    # print(df.info())
    # print(df.head(50)
