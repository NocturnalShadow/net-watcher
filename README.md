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
3. Ensure that the `artifacts/` directory contains the model and scaler (defaults: `icsx-ctu-extended/dnn_16_16_16.keras` and `icsx-ctu-extended/scaler.pkl`).
4. Run `python src/run.py` (`sudo` may be needed on Linux):
```
python src/run.py --role detector --sniff --output-filter all --output-path events/ --log-path logs/
```

## Running tests

Tests require `pytest` and `scapy` (already present if you installed `requirements.txt`). Install the test runner before running for the first time:

```
pip install pytest
```

Run all flow reconstruction tests:
```
python -m pytest tests/ -v
```

Run a specific test file:
```
python -m pytest tests/flow_reconstruction/test_tcp_fin.py -v
```

Run a single scenario:
```
python -m pytest tests/flow_reconstruction/test_tcp_fin.py::TestFINTermination -v
```

Run E2E detection metrics (prints recall and FPR; use `-s` to see the table):
```
python -m pytest tests/e2e/ -v -s
```

## Memory profiling

Run the detector against `pcap/icsx-ctu-extended/test/` and sample RSS every 0.5s:

```
python profile_memory.py
```

Outputs to `memory_profile/`: `memory_samples_<commit>.csv` (raw samples) and `memory_usage_<commit>.png` (graph). Detection events are written to `memory_profile/events/`.

## How to package source as an executable
1. Download and install `pyinstaller`.
2. Install project dependencies `pip install -r requirements.txt`
3. Package executable (will be located under `dist/`)
```
pyinstaller --name netwatcher --onefile src/run.py --add-data artifacts/*:artifacts --clean
```

## Quick Ubuntu install
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
- `--filter`: BPF-style input traffic filter (default: `tcp`).
- `--input-path`: Path to a file or directory containing PCAP files for analysis (not used with `--sniff`).
- `--output-path`: Path to a directory where network flows (for `--role observer`) or detection events (for `--role detector`) will be stored.
- `--output-filter`: The type of the events to output: `ok`, `alerts` or `all` (`--role detector` only) (default: `alerts`).
- `--output-batch-size`: Batch size for dumping flows to disk during reconstruction (observer role only) (default: 5000).
- `--analysis-batch-size`: Number of flows per classification batch (detector role only) (default: 64).
- `--flow-activity-timeout`: Flow activity timeout in seconds (default: 1000).
- `--flow-idle-timeout`: Flow idle timeout in seconds (default: 600).
- `--flow-max-packets`: Maximum number of packets per flow; flow is closed and a new one is created on overflow (default: 100).
- `--flow-queue-max-size`: Maximum number of reconstructed flows queued for processing (default: 10000).
- `--stats-log-step`: Log traffic processing statistics every N packets (default: 100000).
- `--log-path`: Path to the application log file. If not specified, logs will be sent to stdout.
- `--model-path`: Path to the classification model file. The format is resolved from the extension: `.keras` implies a TensorFlow DNN, `.pkl` implies a pickled scikit-learn model. Two trained models are available: `artifacts/icsx-ctu-extended/dnn_16_16_16.keras` (DNN, default) and `artifacts/icsx-ctu-extended/pca_12_rf_9.pkl` (PCA + Random Forest pipeline).
- `--scaler-path`: Path to the scaler pickle file (default: `artifacts/icsx-ctu-extended/scaler.pkl`).
- `--threshold`: Detection threshold for classifying a flow as malicious (detector role only). If not specified, the model's calibrated operating point at FPR ≤ 0.3% is used: 0.59 for the DNN (`.keras`), 0.52 for the Random Forest (`.pkl`).

## Detection Event Logs

Detection events are logged when NetWatcher runs in the detector role (`--role detector`). Event log files are created and rotated in the directory specified by the `--output-path` parameter. The `detector_events.log` file is automatically rotated upon reaching 5 MB (up to 10 rotated log files are preserved).
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

The detection model is trained on a curated combination of three public datasets —
[CTU-13](https://www.stratosphereips.org/datasets-ctu13),
[ISCX-Botnet-2014](https://www.unb.ca/cic/datasets/botnet.html), and CTU (selected captures
from [malware](https://www.stratosphereips.org/datasets-malware) and
[normal](https://www.stratosphereips.org/datasets-normal)). Train and test splits are kept
disjoint; note that ISCX-Botnet-2014 re-packages some CTU-13 captures under different names,
so such duplicates are excluded from one side.

Source captures used (per dataset / split):

| Dataset | Train | Test |
|---------|-------|------|
| **CTU‑13** | — | DonBot `47` · Murlo `49` · Neris `43`,`50` · RBot `45-rbot-dos` · Virut `54` |
| **ISCX‑Botnet‑2014** | benign `benign.pcap` · IRC · Neris · RBot · Virut | benign `benign.pcap` · Zeus · Weasel (synthetic, unseen-type probe) |
| **CTU** (parts) | benign `12-normal-p2p`,`22-normal` · Emotet `264_2`,`268_1` · Kazy `116_2` · TrickBot `238_1`,`243_1` (~½ of flows) · WannaCry `252_1`,`253_1`,`254_1`,`256_1`,`258_1`,`270_1`,`283_1`,`284_1` · Zeus `78_2` (~⅓ of flows) | benign `7-normal-p2p`,`20`–`26-normal` · Emotet `114_2`,`271_1`,`272_1`,`276_2`,`279_1` · Kazy `116_3`,`116_4` · TrickBot `247_1`,`324_1`,`325_1`,`327_1` · WannaCry `285_1`,`286_1`,`287_1`,`295_1`,`296_1`,`297_1` · Zeus `25_6` |

> For access to the curated dataset, contact the repository owner.

Workflow:
1. ISCX-Botnet-2014 packets are labeled and split per malware class in [playbooks/process_data.ipynb](https://github.com/NocturnalShadow/net-watcher/blob/main/playbooks/process_data.ipynb).
2. The labeled ISCX captures and the selected CTU / CTU-13 captures are combined into a single dataset with the train/test split enumerated in the table above.
3. The model is trained and evaluated in [playbooks/training_icsx_ctu_extended_dnn.ipynb](https://github.com/NocturnalShadow/net-watcher/blob/main/playbooks/training_icsx_ctu_extended_dnn.ipynb); resulting artifacts are saved under `artifacts/icsx-ctu-extended/`.

### Model Evaluation Results

Model `dnn_16_16_16` at decision threshold **0.66**, measured on the held-out test split (traffic unseen during training):

- **Overall recall**: 83.5%
- **False positive rate**: 0.30% (252 / 82,967 benign flows)

Per-class recall:

| Class | Recall | Class | Recall |
|-------|--------|-------|--------|
| TrickBot | 0.999 | Neris | 0.669 |
| Emotet | 0.981 | WannaCry | 0.623 |
| Virut | 0.957 | Weasel* | 0.589 |
| RBot | 0.948 | Kazy | 0.532 |
| DonBot | 0.917 | Murlo | 0.309 |
| | | Zeus | 0.044 |

\* Weasel is a synthetic botnet not represented in training — included as an unseen-type generalization check (see [Zhao et al., *Botnet detection based on traffic behavior analysis and flow intervals*](https://ieeexplore.ieee.org/document/6550394)).

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
| `termination_reason`    | Reason for flow termination (FIN, RST, ACTIVITY_TIMEOUT, IDLE_TIMEOUT, MAX_PACKETS, UNKNOWN) |

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

