# NetWatcher

NetWatcher is a network monitoring tool that reconstructs network flows from packet captures or sniffing network interfaces. It extracts features from these flows and uses a pre-trained classification model to determine if the traffic is malicious. Alerts for malicious traffic are logged for further inspection.

## Features
- Offline Analysis: Process PCAP files to reconstruct network flows and detect threats.
- Online Analysis: Sniff live network traffic for real-time flow reconstruction and threat detection.
- AI-based Detection: Utilizes pretrained models to classify network flows.

## Installation
1. Clone the repository:
```
git clone https://github.com/NocturnalShadow/net-watcher.git
cd NetWatcher
```
2. Install the required dependencies:
```
pip install -r requirements.txt
```
3. Ensure that the artifacts/ directory contains the `model.keras` and `scaler.pkl`.

## Project Structure
- `src/`: Source code for flow reconstruction, feature extraction, and classification.
- `playbooks/`: Jupyter notebooks for manipulating datasets, training and evaluating models.
- `artifacts/`: Directory containing pre-trained models and scalers.

## Usage
The main script `run.py` provides both flow reconstruction (`observer` role) and threat detection (`detector` role) functionalities. You can process data offline from PCAP files or online by sniffing network interfaces.

### Examples
#### Online flow analysis (sniffing)
```
python src/run.py --role observer --sniff --output-path flows/sniffed/ --stats-log-step 500 --output-batch-size 2000
python src/run.py --role detector --sniff --output-path log/ --stats-log-step 500
```
##### Online with custom network interface
```
python src/run.py --role observer --sniff --net-interface "Software Loopback Interface 1" --output-path log/ --stats-log-step 500
python src/run.py --role detector --sniff --net-interface "Software Loopback Interface 1" --output-path log/ --stats-log-step 500
```
##### Offline flow analysis (from PCAP files)
```
python src/run.py --role observer --input-path pcap/train/malicious/ --output-path flows/train/ --output-batch-size 1000
python src/run.py --role detector --input-path pcap/train/malicious/ --output-path log/
```

### Parameters
- `--role`: Execution role (observer or detector). Required.
- `--sniff`: Enable online sniffing mode.
- `--net-interface`: Specify the network interface to capture packets from (used with `--sniff`). If not specified, the default interface is used.
- `--input-path`: Path to a file or directory containing PCAP files for analysis (not used with `--sniff`).
- `--output-path`: Path to a directory where network flows (observer role) or detection events (detector role) will be stored.
- `--flow-activity-timeout`: Flow activity timeout in seconds (default: 1000).
- `--flow-idle-timeout`: Flow idle timeout in seconds (default: 600).
- `--output-batch-size`: Batch size for dumping flows to disk during reconstruction (observer role only) (default: 5000).
- `--stats-log-step`: Log traffic processing statistics every N packets (default: 100000).
- `--log-all-events`: If set, logs all events to the output file, not just alerts.

## Detection Event Logs

Detection events will be logge if NetWatcher is run in the role of detector (`--role detector`). Event log files will be create and rotate in the directory specified by `--output-path` parametrs. Log file `detector_events.log` is automatically rotated upon reaching 5 MB size (up to 10 rotated log files are preserved). 
Event log have the following format:

```
2024-12-30 00:35:27 [ALERT] 149.154.167.41:80 -> 192.168.88.10:53680 (TCP)
2024-12-30 00:35:27 [OK] 20.238.236.234:443 -> 192.168.88.10:53729 (TCP)
2024-12-30 00:37:56 [OK] 192.168.88.10:58610 -> 13.89.178.27:443 (TCP)
2024-12-30 00:38:01 [OK] 192.168.88.10:58603 -> 20.50.88.238:443 (TCP)
```
- `[ALERT]` indicates a potentially malicious flow.
- `[OK]` indicates normal traffic and are only logged if `--log-all-events` flag was set.

## AI Training and Evaluation

The model was trained using the [ISCX-Botnet-2014](https://www.unb.ca/cic/datasets/botnet.html) dataset. The training and evaluation process is documented in `playbooks/ai_training.ipynb`.

### Model Evaluation Results

- **Training AUROC**: 0.9993
- **Training Accuracy**: 0.9876
- **Training Precision**: 0.9690
- **Training Recall**: 0.9952
- **False Positives**: 0.0108 (but for unseen benign data could be much higher...)

`playbooks/ai_training.ipynb` contains Jupyter notebooks for training and evaluating the default classification model located under `artifacts/model.keras`.

## Flow Attributes

### Metadata
| Attribute Name          | Description                                                                  |
|-------------------------|------------------------------------------------------------------------------|
| `id`                    | Identifier of the flow: `<src_ip>-<dst_ip>-<src_port>-<dst_port>-<protocol>` |
| `timestamp`             | Unix timestamp when the flow was created                                     |
| `src_ip`                | Source IP address of the flow                                                |
| `dst_ip`                | Destination IP address of the flow                                           |
| `src_port`              | Source port number                                                           |
| `dst_port`              | Destination port number                                                      |
| `protocol`              | Transport layer protocol used (e.g., TCP, UDP)                               |
| `termination_reason`    | Reason for flow termination (e.g., FIN, RST)                                 |

### Features
| Attribute Name          | Description                                                                  | Directional |
|-------------------------|------------------------------------------------------------------------------|-------------|
| `duration_s`            | Duration of the flow in seconds (time between first and last packet)         | No          |
| `packets_count`         | Total number of packets in the flow                                          | No          |
| `payload_bytes_seq`     | Sequence of payload bytes for each packet                                    | No          |
| `payload_bytes_total`   | Total number of payload bytes (excluding headers) in the flow                | No          |
| `payload_bytes_min`     | Minimum payload bytes in the flow                                            | No          |
| `payload_bytes_max`     | Maximum payload bytes in the flow                                            | No          |
| `payload_bytes_std`     | Standard deviation of payload bytes in the flow                              | No          |
| `payload_bytes_min_nonzero` | Minimum payload bytes (excluding zero payloads) in the flow              | No          |
| `payload_bytes_avg_nonzero` | Average payload bytes (excluding zero payloads) in the flow              | No          |
| `payload_bytes_std_nonzero` | Standard deviation of payload bytes (excluding zero payloads) in the flow| No          |
| `interarrival_time_s_seq` | Sequence of interarrival times between packets                             | No          |
| `interarrival_time_s_min` | Minimum interarrival time between packets                                  | No          |
| `interarrival_time_s_max` | Maximum interarrival time between packets                                  | No          |
| `interarrival_time_s_std` | Standard deviation of interarrival times between packets                   | No          |
| `syn_count`             | Number of packets with SYN flag set                                          | No          |
| `fin_count`             | Number of packets with FIN flag set                                          | No          |
| `rst_count`             | Number of packets with RST flag set                                          | No          |
| `ack_count`             | Number of packets with ACK flag set                                          | No          |
| `psh_count`             | Number of packets with PSH flag set                                          | No          |
| `urg_count`             | Number of packets with URG flag set                                          | No          |
| `ece_count`             | Number of packets with ECE flag set                                          | No          |
| `cwr_count`             | Number of packets with CWR flag set                                          | No          |
| `fwd_window_size_seq`   | Sequence of window sizes for forward direction                               | Yes         |
| `fwd_window_size_min`   | Minimum window size for forward direction                                    | Yes         |
| `fwd_window_size_max`   | Maximum window size for forward direction                                    | Yes         |
| `fwd_window_size_avg`   | Average window size for forward direction                                    | Yes         |
| `fwd_window_size_std`   | Standard deviation of window sizes for forward direction                     | Yes         |
| `fwd_window_scaling_factor` | Window scaling factor for forward direction                              | Yes         |
| `fwd_initial_window_size` | Initial window size for forward direction                                  | Yes         |
| `fwd_zero_window_count` | Number of zero window size occurrences for forward direction                 | Yes         |
| `fwd_zero_window_update_count` | Number of zero window size updates for forward direction              | Yes         |
| `bwd_window_size_seq`   | Sequence of window sizes for backward direction                              | Yes         |
| `bwd_window_size_min`   | Minimum window size for backward direction                                   | Yes         |
| `bwd_window_size_max`   | Maximum window size for backward direction                                   | Yes         |
| `bwd_window_size_avg`   | Average window size for backward direction                                   | Yes         |
| `bwd_window_size_std`   | Standard deviation of window sizes for backward direction                    | Yes         |
| `bwd_window_scaling_factor` | Window scaling factor for backward direction                             | Yes         |
| `bwd_initial_window_size` | Initial window size for backward direction                                 | Yes         |
| `bwd_zero_window_count` | Number of zero window size occurrences for backward direction                | Yes         |
| `bwd_zero_window_update_count` | Number of zero window size updates for backward direction             | Yes         |

