# GNN-IDS: Real-Time Graph Neural Network Intrusion Detection System

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![PyTorch Geometric](https://img.shields.io/badge/PyTorch-Geometric-red.svg)
![ONNX Runtime](https://img.shields.io/badge/ONNX-Runtime-lightgrey.svg)
![Fedora Linux](https://img.shields.io/badge/Fedora-RPM_Packaged-darkblue.svg)



## 📖 Overview
**GNN-IDS** is a production-grade Network Intrusion Detection System that captures live network traffic, extracts temporal flow features, and utilizes a **GraphSAGE** neural network to classify zero-day and known cyber-attacks in real-time. 

Traditional heuristic or isolated-vector ML models evaluate packets in a vacuum. GNN-IDS evaluates network traffic contextually. It constructs dynamic sub-graphs in memory, analyzing the structural and mathematical relationships between concurrent flows to detect distributed attacks (e.g., DDoS, horizontal port scans).

To achieve sub-millisecond production latency without GPU dependencies, the trained PyTorch model is structurally collapsed and exported to an **ONNX CPU Execution Runtime**, deployed as a lightweight, globally distributable system-level daemon (`systemd`).

## ✨ Key Features
* **Dynamic Topological Inference:** Maintains a 250-node ring buffer of active flows, dynamically constructing an `edge_index` to evaluate incoming packets alongside their temporal neighbors.
* **Hardware-Agnostic Deployment:** Trains on heavy GPU clusters (CUDA) but compiles to an optimized ONNX IR for CPU-bound edge deployment.
* **Strict Feature Parity:** The `StandardScaler` transformations are mathematically aligned strictly with live-calculable Scapy metrics, completely eliminating out-of-distribution (OOD) zero-variance distortion.
* **Automated MLOps Packaging:** Uses a custom Bash/RPM build system (`build_rpm.sh`) to handle C-extension binary compilation, strict dependency isolation (bypassing Conda leakage), and `systemd` daemon registration.
* **Kernel-Level Noise Mitigation:** Implements BPF (Berkeley Packet Filter) configuration via `gnn-ids.conf` to drop noisy local broadcast protocols (e.g., SSDP) prior to ingestion.

## 📂 Repository Structure

```text
GNN-IDS/
├── data/                       # Raw CIC-IDS-2017 CSV files (Ignored in Git)
├── docs/releases/x86_64/       # GitHub Pages DNF Repository Metadata & RPMs
├── src/
│   ├── train_gpu.py            # PyTorch GraphSAGE training engine & ONNX exporter
│   ├── main.py                 # Live Scapy capture, graph construction, and logging daemon
│   └── inference.py            # ONNX Runtime CPU inference layer
├── packaging/
│   ├── gnn-ids.spec            # Fedora RPM specifications & dependency declarations
│   ├── gnn-ids.service         # systemd daemon configuration
│   └── gnn-ids.conf            # Environment variables and BPF filters
├── build_rpm.sh                # Automated RPM packager
├── simulate_attack.py          # Scapy TCP SYN flood generator for live testing
└── README.md

```

## 🚀 Global Installation (Fedora / RHEL)

To bypass manual compilation and distribute the binary globally, this project hosts a YUM/DNF repository via GitHub Pages. DNF resolves dependencies via XML metadata hosted at this URL.

**1. Add the GNN-IDS Repository:**

```bash
sudo nano /etc/yum.repos.d/gnn-ids.repo

```

Paste the following configuration:

```ini
[gnn-ids]
name=GNN-IDS Production Repository
baseurl=[https://Udaykirancheera15.github.io/GNN-IDS/releases/x86_64/](https://Udaykirancheera15.github.io/GNN-IDS/releases/x86_64/)
enabled=1
gpgcheck=0

```

**2. Install the Package:**

```bash
sudo dnf update
sudo dnf install gnn-ids

```

**3. Configure & Start the Daemon:**
Add any desired BPF filters (e.g., ignoring local SSDP broadcasts) to `/etc/gnn-ids/gnn-ids.conf`:

```bash
echo 'GNN_IDS_FILTER="ip and not dst host 239.255.255.250 and not udp port 1900"' | sudo tee -a /etc/gnn-ids/gnn-ids.conf

```

Enable and start the service:

```bash
sudo systemctl enable --now gnn-ids

```

## 📊 Usage & Monitoring

Once the `gnn-ids` service is running, it automatically binds to your active internet-facing NIC and begins silently capturing and evaluating traffic.

Monitor the live inference logs and periodic statistics:

```bash
journalctl -u gnn-ids -f

```

### Simulating an Attack

To verify the engine's real-time detection capabilities, inject a raw TCP SYN flood using the provided simulation script. *Note: Forging raw packets requires kernel-level network privileges (root).*

```bash
sudo python3 simulate_attack.py

```

Exactly 60 seconds after the simulation completes (the `FLOW_TIMEOUT`), the `journalctl` logs will populate with `[ALERT/HIGH]` notifications identifying the target ports of the port scan.

## 🧠 Training the Model (Source Build)

To retrain the model on new data or update the feature space:

1. Place your labeled network traffic CSVs in the `data/` directory.
2. Run the PyTorch training script on a CUDA-enabled machine:
```bash
python3 src/train_gpu.py

```


3. The script will dynamically sample the data, train the GraphSAGE architecture, trace the JIT graph, and output `model.onnx` and `feature_extractor.pkl` to the `src/` directory.
4. Repackage the RPM using `./build_rpm.sh` to deploy the updated weights.

## 🚧 Limitations & Enterprise Scalability (Future Work)

While the deployment pipeline is production-ready, this architecture is a prototype. For a true 10Gbps+ enterprise deployment, the following systems-engineering upgrades are required:

| Vulnerability | Root Cause | Required Enterprise Architecture |
| --- | --- | --- |
| **Ingestion Bottleneck** | Python `scapy` operates in user-space and is bound by the GIL, causing packet drops under heavy load. | **Kernel Bypass:** Rewrite feature extraction in C++/Rust utilizing **eBPF/XDP** to parse packet buffers at the NIC driver level. |
| **State Exhaustion (OOM)** | Unbounded Python Hash Map tracking active 5-tuple flows. Vulnerable to spoofed SYN floods. | **Memory Management:** Migrate state to a fixed-size Least Recently Used (LRU) Cache protected by probabilistic Bloom Filters. |
| **Concept Drift** | Static model trained on legacy 2017 distributions fails on modern multiplexed/encrypted traffic. | **Continuous Training (CT):** Implement an SQLite shadow database for heuristic auto-labeling and automated nightly retraining. |

## 📄 License
MIT License. All rights reserved.
