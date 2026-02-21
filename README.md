    # GNN Network Intrusion Detection System
    ## Research-to-Production Workflow
```
    ┌──────────────────────────────────────────────────────────────┐
    │  YOU (Packager)                   RESEARCHER (GPU Server)     │
    │                                                               │
    │  1. Run generator                                             │
    │     python generate_final_gnn_project.py                     │
    │                                                               │
    │  2. Send to researcher ──────────────────►  src/train_gpu.py │
    │     (this project + 8 CSV files)            data/*.csv       │
    │                                                               │
    │                              Train ◄── conda activate gnn-ids│
    │                                         python src/train_gpu.py
    │                                                               │
    │  3. Receive artifacts  ◄────────────────  src/model.onnx     │
    │                                           src/feature_extractor.pkl
    │                                                               │
    │  4. Build RPM                                                 │
    │     ./build_rpm.sh                                            │
    │                                                               │
    │  5. Deploy to Fedora                                          │
    │     sudo dnf install ~/rpmbuild/RPMS/x86_64/gnn-ids-*.rpm   │
    │     sudo systemctl enable --now gnn-ids                      │
    └──────────────────────────────────────────────────────────────┘
```

    ## Quick Start

    ### For the Researcher (GPU Server)
```bash
    # 1. Create environment
    conda env create -f environment.yml
    conda activate gnn-ids

    # 2. Place CSV files
    cp /path/to/CIC-IDS-2017/*.csv data/

    # 3. Train (takes ~30-60 min on a single V100)
    python src/train_gpu.py \
        --epochs 50 \
        --batch-size 512 \
        --hidden 128

    # 4. Verify deliverables
    ls -lh src/model.onnx src/feature_extractor.pkl
```

    ### For the Packager (Fedora)
```bash
    # 1. Receive model.onnx + feature_extractor.pkl from researcher
    #    Place them in src/

    # 2. Install build tools
    sudo dnf install -y rpmdevtools rpm-build python3-onnx

    # 3. Build RPM
    chmod +x build_rpm.sh
    ./build_rpm.sh

    # 4. Install and start service
    sudo dnf install ~/rpmbuild/RPMS/x86_64/gnn-ids-*.rpm
    sudo systemctl enable --now gnn-ids

    # 5. Monitor
    journalctl -u gnn-ids -f
    tail -f /var/log/gnn-ids/gnn_ids.log
```

    ## Project Structure
```
    gnn_ids_project/
    ├── data/                    # Place 8 CIC-IDS-2017 CSV files here
    ├── src/
    │   ├── train_gpu.py         # GPU training engine (researcher)
    │   ├── inference.py         # ONNX inference engine (production)
    │   ├── main.py              # Live packet capture service (production)
    │   ├── model.onnx           # [RESEARCHER DELIVERABLE]
    │   └── feature_extractor.pkl# [RESEARCHER DELIVERABLE]
    ├── packaging/
    │   ├── gnn-ids.spec         # RPM specification
    │   ├── gnn-ids.service      # systemd unit file
    │   └── gnn-ids.conf         # Runtime configuration
    ├── build_rpm.sh             # RPM build automation
    ├── environment.yml          # Conda environment (GPU + CPU deps)
    └── README.md
```

    ## Architecture

    | Component       | Technology           | Purpose                          |
    |-----------------|----------------------|----------------------------------|
    | GNN Model       | GraphSAGE (3-layer)  | Flow-level threat classification |
    | Normalisation   | BatchNorm1d          | Training stability               |
    | Export Format   | ONNX Opset 12 / IR 8 | Hardware-agnostic deployment     |
    | CPU Inference   | ONNX Runtime 1.16+   | No GPU needed in production      |
    | Feature Parity  | StandardScaler.pkl   | Train/serve distribution match   |
    | Packet Capture  | Scapy                | Live network traffic analysis    |
    | Service Manager | systemd              | Production process supervision   |
    | Package Manager | RPM / dnf            | Fedora deployment                |
