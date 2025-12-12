# NetWatcher
NetWatcher is a network monitoring tool that reconstructs network flows from packet captures or sniffing network interfaces. It extracts features from these flows and uses a pre-trained classification model to determine if the traffic is malicious. Alerts for malicious traffic are logged for further inspection.

## Features
- Offline Analysis: Process PCAP files to reconstruct network flows and detect threats.
- Online Analysis: Sniff live network traffic for real-time flow reconstruction and threat detection.
- AI-based Detection: Utilizes pretrained models to classify network flows.

## How to run
### Run from executable (Linux)
1. Download latest released `netwatcher` binary. Run `chmod 755 netwatcher` if necessary. 
    - [netwatcher-v0.1.1-linux-x86.tar.gz (S3 bucket, 703Mb)](https://github-releases-f9ebd6ea-5a01-475b-a887-16eebedde4a1.s3.eu-central-1.amazonaws.com/net-watcher/netwatcher-v0.1.1-linux-x86.tar.gz)
2. Give the binary the permissions to capture traffic (required only for `--sniff` mode):
```
sudo setcap cap_net_raw+ep netwatcher
```
> _NOTE:_ you can skip this step, but then `sudo` will be required for running the executable.

3. Run `netwatcher` executable:
```
netwatcher --role detector --sniff --output-filter all --output-path events/ --log-path logs/
```
### Run from executable (Windows)
1. Download latest released `netwatcher.exe` binary.
    - [netwatcher-v0.1.1-windows-x86.zip (S3 bucket, 487Mb)](https://github-releases-f9ebd6ea-5a01-475b-a887-16eebedde4a1.s3.eu-central-1.amazonaws.com/net-watcher/netwatcher-v0.1.1-windows-x86.zip)
2. Run `netwatcher` executable:
```
netwatcher --role detector --sniff --output-filter all --output-path events/ --log-path logs/
```

### Run from source
1. Clone the repository:
```
git clone https://github.com/NocturnalShadow/net-watcher.git
cd NetWatcher
```
2. Install the required dependencies `pip install -r requirements.txt`
3. Ensure that the artifacts/ directory contains the `model.keras` and `scaler.pkl`.
4. Run `python src/run.py` (`sudo` may be needed on Linux):
```
python src/run.py --role detector --sniff --output-filter all --output-path events/ --log-path logs/
```

## How to package source as an executable
1. Download and install `pyinstaller`.
2. Install project dependencies `pip install -r requirements.txt`
3. Package executable (will be located under `dist/`)
```
pyinstaller --name netwatcher --onefile src/run.py --add-data artifacts/*:artifacts --clean
```

## Clean Ubuntu install
```
1  mkdir github
2  cd github
3  sudo apt update
4  sudo apt install git -y
5  sudo apt install python3.10-venv python3.10-dev -y
6  git clone https://github.com/NocturnalShadow/net-watcher
7  cd net-watcher
8  python3.10 -m venv .venv
9  source .venv/bin/activate
10  pip install -r requirements.txt
11  sudo $(which python) src/run.py --role detector --sniff --output-filter all --output-path events/ --log-path logs/
```

## Project Structure
- `src/`: Source code for flow reconstruction, feature extraction, and classification.
- `playbooks/`: Jupyter notebooks for manipulating datasets, training and evaluating models.
- `artifacts/`: Directory containing pre-trained models and scalers.

## Usage
The main script `run.py` provides both flow reconstruction (`observer` role) and threat detection (`detector` role) functionalities. You can process data offline from PCAP files or online by sniffing network interfaces.

### Examples
_NOTE: For examples below when running as executable just replace `python src/run.py` with `netwatcher`._
#### Online flow analysis (sniffing)
```
python src/run.py --role observer --sniff --output-path flows/ --output-batch-size 2000 --log-path /logs --stats-log-step 500
python src/run.py --role detector --sniff --output-path events/ --output-filter all --log-path /logs --stats-log-step 500 
```
##### Online with custom network interface
```
python src/run.py --role observer --sniff --output-path flows/ --net-interface "Software Loopback Interface 1"
python src/run.py --role detector --sniff --output-path events/ --net-interface "Software Loopback Interface 1"
```
##### Offline flow analysis (from PCAP files)
```
python src/run.py --role observer --input-path pcap/train/malicious/ --output-path flows/train/ --output-batch-size 1000
python src/run.py --role detector --input-path pcap/train/malicious/ --output-path events/
```

### Parameters
- `--role`: Execution role (observer or detector). Required.
- `--sniff`: Enable online sniffing mode.
- `--net-interface`: Specify the network interface to capture packets from (used with `--sniff`). If not specified, the default interface is used.
- `--input-path`: Path to a file or directory containing PCAP files for analysis (not used with `--sniff`).
- `--output-path`: Path to a directory where network flows (for `--role observer`) or detection events (for `--role detector`) will be stored.
- `--output-filter`: The type of the events to output: `ok`, `alerts` or `all` (`--role detector` only) (default: `alerts`).
- `--output-batch-size`: Batch size for dumping flows to disk during reconstruction (observer role only) (default: 5000).
- `--flow-activity-timeout`: Flow activity timeout in seconds (default: 1000).
- `--flow-idle-timeout`: Flow idle timeout in seconds (default: 600).
- `--stats-log-step`: Log traffic processing statistics every N packets (default: 100000).
- `--log-path`: Path to the application log file. If not specified, logs will be sent to stdout.

## Detection Event Logs

Detection events will be logge if NetWatcher is run in the role of detector (`--role detector`). Event log files will be create and rotate in the directory specified by `--output-path` parametrs. Log file `detector_events.log` is automatically rotated upon reaching 5 MB size (up to 10 rotated log files are preserved). 
Event log have the following format:

```
2025-01-07 17:47:33 [ALERT] 192.168.1.103:1090 -> 192.168.5.122:143 (TCP): 9 packets, 0 bytes, 959s 948ms
2025-01-07 17:47:33 [OK] 192.168.2.113:4491 -> 192.168.5.122:22 (TCP): 20 packets, 1278 bytes, 5s 399ms
2025-01-07 17:47:33 [OK] 192.168.1.103:1705 -> 192.168.5.122:22 (TCP): 20 packets, 1278 bytes, 5s 478ms
2025-01-07 17:47:33 [OK] 192.168.2.113:4492 -> 192.168.5.122:22 (TCP): 22 packets, 1278 bytes, 5s 446ms
2025-01-07 17:47:33 [ALERT] 192.168.1.103:1706 -> 192.168.5.122:22 (TCP): 22 packets, 1278 bytes, 5s 395ms
```
- `[ALERT]` indicates a potentially malicious flow. Logged by default.
- `[OK]` indicates normal traffic. Logged only if set `--output-filter all`.

## AI Training and Evaluation

- The model was trained using the [ISCX-Botnet-2014](https://www.unb.ca/cic/datasets/botnet.html) dataset.
- The script used for splitting dataset into different classes availible at [playbooks/process_data.ipynb](https://github.com/NocturnalShadow/net-watcher/blob/main/playbooks/process_data.ipynb)
- The training and evaluation process of the detection model is captured in [playbooks/ai_training.ipynb](https://github.com/NocturnalShadow/net-watcher/blob/main/playbooks/ai_training.ipynb). The resulting models and other resources can be found under `artifacts`.

### Model Evaluation Results

- **Training AUROC**: 0.9993
- **Training Accuracy**: 0.9876
- **Training Precision**: 0.9690
- **Training Recall**: 0.9952
- **False Positives**: 0.0108 (but for unseen benign data could be much higher...)

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
| `termination_reason`    | Reason for flow termination (FIN, RST, idle_timeout, activity_timeout)       |

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

