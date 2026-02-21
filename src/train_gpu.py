#!/usr/bin/env python3
"""
train_gpu.py — Enterprise GNN-IDS Training Engine
Phase 1 + Phase 3: Strict Feature Parity & Dynamic Topological Export
"""

import os, sys, glob, hashlib, logging, pickle, argparse, warnings
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.utils import resample
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.optim import Adam
from torch.optim.lr_scheduler import ReduceLROnPlateau
from torch_geometric.data import Data, DataLoader as GeoDataLoader
from torch_geometric.nn import SAGEConv
import onnx
import onnxruntime as ort

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DATA_DIR        = Path("data")
MODEL_OUT       = Path("src/model.onnx")
EXTRACTOR_OUT   = Path("src/feature_extractor.pkl")
SEED            = 42

# Phase 1 Upgrade: Strict Feature Parity (58 Features)
# Removed all features that main.py hardcodes to 0 to prevent z-score distortion.
FEATURE_COLS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max",
    "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max",
    "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
    "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags",
    "Fwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length",
    "Max Packet Length", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "SYN Flag Count",
    "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "URG Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "act_data_pkt_fwd", "min_seg_size_forward", "Protocol"
]

def load_and_preprocess(data_dir: Path) -> pd.DataFrame:
    frames = []
    for fp in data_dir.glob("*.csv"):
        log.info(f"Loading {fp.name}...")
        try:
            df = pd.read_csv(fp, encoding="utf-8", low_memory=False)
        except UnicodeDecodeError:
            df = pd.read_csv(fp, encoding="latin-1", low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        frames.append(df)
    combined = pd.concat(frames, ignore_index=True)
    
    # Create surrogate node IDs for graph construction
    combined["node_id"] = combined.apply(
        lambda r: hashlib.md5(f"{r.get('Destination Port', 0)}_{r.get('Protocol', 0)}_{r.get('Flow Duration', 0)}".encode()).hexdigest(), 
        axis=1
    )
    combined.replace([np.inf, -np.inf], np.nan, inplace=True)
    for col in FEATURE_COLS:
        if col not in combined.columns:
            combined[col] = 0.0
            
    combined["binary_label"] = (combined["Label"].str.strip() != "BENIGN").astype(int)
    return combined

def stratified_sample(df: pd.DataFrame) -> pd.DataFrame:
    benign = df[df["binary_label"] == 0]
    attack = df[df["binary_label"] == 1]
    benign_sampled = resample(benign, replace=False, n_samples=int(len(benign) * 0.10), random_state=SEED)
    return pd.concat([benign_sampled, attack], ignore_index=True).sample(frac=1, random_state=SEED)

def build_graph(X: np.ndarray, y: np.ndarray, node_ids: list) -> Data:
    bucket_map = {}
    for idx, nid in enumerate(node_ids):
        bucket_map.setdefault(nid[:4], []).append(idx)

    edge_src, edge_dst = [], []
    for indices in bucket_map.values():
        for i in range(len(indices)):
            for j in range(i + 1, min(i + 4, len(indices))):
                edge_src.extend([indices[i], indices[j]])
                edge_dst.extend([indices[j], indices[i]])

    edge_index = torch.tensor([edge_src, edge_dst], dtype=torch.long)
    return Data(x=torch.tensor(X, dtype=torch.float), edge_index=edge_index, y=torch.tensor(y, dtype=torch.long))

class GraphSAGEIDS(nn.Module):
    def __init__(self, in_channels: int, hidden_channels: int, num_classes: int):
        super().__init__()
        self.conv1 = SAGEConv(in_channels, hidden_channels)
        self.bn1   = nn.BatchNorm1d(hidden_channels)
        self.conv2 = SAGEConv(hidden_channels, hidden_channels)
        self.bn2   = nn.BatchNorm1d(hidden_channels)
        self.conv3 = SAGEConv(hidden_channels, hidden_channels // 2)
        self.bn3   = nn.BatchNorm1d(hidden_channels // 2)
        self.classifier = nn.Linear(hidden_channels // 2, num_classes)
        self.dropout    = nn.Dropout(p=0.3)

    def forward(self, x, edge_index):
        x = F.relu(self.bn1(self.conv1(x, edge_index)))
        x = self.dropout(x)
        x = F.relu(self.bn2(self.conv2(x, edge_index)))
        x = self.dropout(x)
        x = F.relu(self.bn3(self.conv3(x, edge_index)))
        return self.classifier(x)

# Phase 3 Upgrade: Dynamic Edge Index Wrapper
class ONNXWrapper(nn.Module):
    def __init__(self, model: GraphSAGEIDS):
        super().__init__()
        self.model = model

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        return self.model(x, edge_index)

def export_onnx(model: GraphSAGEIDS, sample_data: Data, out_path: Path):
    model.eval()
    wrapper = ONNXWrapper(model).eval()

    dummy_x = sample_data.x[:64].cpu()
    dummy_edge_index = torch.tensor([[0, 1], [1, 0]], dtype=torch.long)

    torch.onnx.export(
        wrapper,
        (dummy_x, dummy_edge_index),
        str(out_path),
        export_params=True,
        opset_version=12,
        do_constant_folding=True,
        input_names=["node_features", "edge_index"],
        output_names=["logits"],
        dynamic_axes={
            "node_features": {0: "num_nodes"},
            "edge_index": {1: "num_edges"},
            "logits": {0: "num_nodes"}
        },
    )
    
    m = onnx.load(str(out_path))
    m.ir_version = 8
    onnx.save(m, str(out_path))
    log.info(f"ONNX model saved → {out_path} (opset=12, IR=8, Dynamic Topology Enabled)")

def main():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    log.info(f"Using device: {device}")

    df = stratified_sample(load_and_preprocess(DATA_DIR))
    
    X_raw = np.nan_to_num(df[FEATURE_COLS].values.astype(np.float32))
    y = df["binary_label"].values.astype(np.int64)
    nids = df["node_id"].tolist()

    scaler = StandardScaler()
    X = scaler.fit_transform(X_raw).astype(np.float32)

    X_tr, X_va, y_tr, y_va, nid_tr, nid_va = train_test_split(X, y, nids, test_size=0.2, stratify=y, random_state=SEED)

    train_graph = build_graph(X_tr, y_tr, nid_tr).to(device)
    val_graph   = build_graph(X_va, y_va, nid_va).to(device)

    model = GraphSAGEIDS(len(FEATURE_COLS), 128, 2).to(device)
    optimizer = Adam(model.parameters(), lr=1e-3, weight_decay=1e-5)
    criterion = nn.CrossEntropyLoss()

    best_val = float("inf")
    for epoch in range(1, 51):
        model.train()
        optimizer.zero_grad()
        out = model(train_graph.x, train_graph.edge_index)
        loss = criterion(out, train_graph.y)
        loss.backward()
        optimizer.step()
        
        model.eval()
        with torch.no_grad():
            v_out = model(val_graph.x, val_graph.edge_index)
            v_loss = criterion(v_out, val_graph.y)
            
        if v_loss < best_val:
            best_val = v_loss
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
        
        if epoch % 10 == 0:
            log.info(f"Epoch {epoch}/50 | Train Loss: {loss.item():.4f} | Val Loss: {v_loss.item():.4f}")

    model.load_state_dict(best_state)
    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    export_onnx(model.cpu(), train_graph, MODEL_OUT)
    
    with open(EXTRACTOR_OUT, "wb") as f:
        pickle.dump({"scaler": scaler, "feature_cols": FEATURE_COLS}, f, protocol=pickle.HIGHEST_PROTOCOL)

if __name__ == "__main__":
    main()
