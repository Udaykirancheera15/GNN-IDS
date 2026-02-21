#!/usr/bin/env python3
import os, sys, time, socket, logging, argparse, signal, subprocess, collections
from pathlib import Path
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, conf as scapy_conf
from inference import IDSInferenceEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
                    handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler("/var/log/gnn-ids/gnn_ids.log", mode="a")])
log = logging.getLogger("gnn-ids")

def detect_active_interface() -> str:
    try:
        result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            if "dev" in line.split(): return line.split()[line.split().index("dev") + 1]
    except Exception: pass
    return "eth0"

class FlowRecord:
    __slots__ = ["start_ts", "last_ts", "dst_port", "protocol", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
                 "pkt_lengths", "fwd_iats", "bwd_iats", "flow_iats", "fin", "syn", "rst", "psh", "ack", "urg"]
    def __init__(self, pkt, direction):
        self.start_ts = self.last_ts = pkt.time
        self.dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        self.protocol = pkt[IP].proto if pkt.haslayer(IP) else 0
        self.fwd_pkts, self.bwd_pkts = (1, 0) if direction == "fwd" else (0, 1)
        self.fwd_bytes, self.bwd_bytes = (len(pkt), 0) if direction == "fwd" else (0, len(pkt))
        self.pkt_lengths, self.fwd_iats, self.bwd_iats, self.flow_iats = [len(pkt)], [], [], []
        self.fin = self.syn = self.rst = self.psh = self.ack = self.urg = 0
        self._update_flags(pkt)

    def _update_flags(self, pkt):
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            self.fin += bool(flags & 0x01); self.syn += bool(flags & 0x02); self.rst += bool(flags & 0x04)
            self.psh += bool(flags & 0x08); self.ack += bool(flags & 0x10); self.urg += bool(flags & 0x20)

    def update(self, pkt, direction):
        iat = pkt.time - self.last_ts
        self.flow_iats.append(iat)
        if direction == "fwd":
            self.fwd_pkts += 1; self.fwd_bytes += len(pkt); self.fwd_iats.append(iat)
        else:
            self.bwd_pkts += 1; self.bwd_bytes += len(pkt); self.bwd_iats.append(iat)
        self.pkt_lengths.append(len(pkt))
        self.last_ts = pkt.time
        self._update_flags(pkt)

    def to_feature_vector(self, feature_cols) -> np.ndarray:
        dur = float(self.last_ts - self.start_ts) * 1e6
        pkt_arr = np.array(self.pkt_lengths, dtype=np.float32)
        fwd_arr = np.array(self.fwd_iats, dtype=np.float32) if self.fwd_iats else np.array([0.0])
        bwd_arr = np.array(self.bwd_iats, dtype=np.float32) if self.bwd_iats else np.array([0.0])
        flow_arr = np.array(self.flow_iats, dtype=np.float32) if self.flow_iats else np.array([0.0])
        total_pkts = self.fwd_pkts + self.bwd_pkts + 1e-9

        # Phase 1 Upgrade: Only strictly calculable live features
        raw = {
            "Destination Port": self.dst_port, "Flow Duration": dur,
            "Total Fwd Packets": self.fwd_pkts, "Total Backward Packets": self.bwd_pkts,
            "Total Length of Fwd Packets": self.fwd_bytes, "Total Length of Bwd Packets": self.bwd_bytes,
            "Fwd Packet Length Max": pkt_arr.max(), "Fwd Packet Length Min": pkt_arr.min(),
            "Fwd Packet Length Mean": pkt_arr.mean(), "Fwd Packet Length Std": pkt_arr.std(),
            "Bwd Packet Length Max": bwd_arr.max() if self.bwd_pkts else 0, "Bwd Packet Length Min": bwd_arr.min() if self.bwd_pkts else 0,
            "Bwd Packet Length Mean": bwd_arr.mean() if self.bwd_pkts else 0, "Bwd Packet Length Std": bwd_arr.std() if self.bwd_pkts else 0,
            "Flow Bytes/s": (self.fwd_bytes + self.bwd_bytes) / (dur / 1e6 + 1e-9), "Flow Packets/s": total_pkts / (dur / 1e6 + 1e-9),
            "Flow IAT Mean": flow_arr.mean(), "Flow IAT Std": flow_arr.std(), "Flow IAT Max": flow_arr.max(), "Flow IAT Min": flow_arr.min(),
            "Fwd IAT Total": fwd_arr.sum(), "Fwd IAT Mean": fwd_arr.mean(), "Fwd IAT Std": fwd_arr.std(),
            "Fwd IAT Max": fwd_arr.max(), "Fwd IAT Min": fwd_arr.min(), "Bwd IAT Total": bwd_arr.sum(),
            "Bwd IAT Mean": bwd_arr.mean(), "Bwd IAT Std": bwd_arr.std(), "Bwd IAT Max": bwd_arr.max(), "Bwd IAT Min": bwd_arr.min(),
            "Fwd PSH Flags": self.psh, "Fwd URG Flags": self.urg, "Fwd Header Length": 20 * self.fwd_pkts,
            "Bwd Header Length": 20 * self.bwd_pkts, "Fwd Packets/s": self.fwd_pkts / (dur / 1e6 + 1e-9),
            "Bwd Packets/s": self.bwd_pkts / (dur / 1e6 + 1e-9), "Min Packet Length": pkt_arr.min(),
            "Max Packet Length": pkt_arr.max(), "Packet Length Mean": pkt_arr.mean(), "Packet Length Std": pkt_arr.std(),
            "Packet Length Variance": pkt_arr.var(), "FIN Flag Count": self.fin, "SYN Flag Count": self.syn,
            "RST Flag Count": self.rst, "PSH Flag Count": self.psh, "ACK Flag Count": self.ack, "URG Flag Count": self.urg,
            "Down/Up Ratio": self.bwd_pkts / max(self.fwd_pkts, 1), "Average Packet Size": pkt_arr.mean(),
            "Avg Fwd Segment Size": self.fwd_bytes / max(self.fwd_pkts, 1), "Avg Bwd Segment Size": self.bwd_bytes / max(self.bwd_pkts, 1),
            "Subflow Fwd Packets": self.fwd_pkts, "Subflow Fwd Bytes": self.fwd_bytes,
            "Subflow Bwd Packets": self.bwd_pkts, "Subflow Bwd Bytes": self.bwd_bytes,
            "act_data_pkt_fwd": self.fwd_pkts, "min_seg_size_forward": 20, "Protocol": self.protocol,
        }
        return np.array([float(raw.get(col, 0.0)) for col in feature_cols], dtype=np.float32)

class PacketProcessor:
    def __init__(self, engine: IDSInferenceEngine):
        self.engine = engine
        self.flows = {}
        self.stats = collections.Counter()
        
        # Phase 3 Upgrade: Ring Buffer for Temporal Graph Context
        self.history_features = []
        self.history_keys = []
        self.max_history = 250

    def _make_key(self, pkt):
        if not pkt.haslayer(IP): return None
        sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        return (min(pkt[IP].src, pkt[IP].dst), max(pkt[IP].src, pkt[IP].dst), min(sport, dport), max(sport, dport), pkt[IP].proto)

    def process_packet(self, pkt):
        key = self._make_key(pkt)
        if not key: return
        if key in self.flows: self.flows[key].update(pkt, "fwd")
        else: self.flows[key] = FlowRecord(pkt, "fwd")

        now = time.time()
        for k in [k for k, v in self.flows.items() if (now - float(v.last_ts)) > 60]:
            self._classify_and_alert(k, self.flows.pop(k))

    def _classify_and_alert(self, key, flow):
        try:
            fv = flow.to_feature_vector(self.engine.feature_cols)
            self.history_features.append(fv)
            self.history_keys.append(key)
            if len(self.history_features) > self.max_history:
                self.history_features.pop(0)
                self.history_keys.pop(0)
            
            # Phase 3 Upgrade: Dynamic Edge Resolution 
            edges_src, edges_dst = [], []
            curr_idx = len(self.history_features) - 1
            
            for i, h_key in enumerate(self.history_keys):
                if i != curr_idx and (key[2] == h_key[2] or key[3] == h_key[3]): 
                    edges_src.extend([i, curr_idx])
                    edges_dst.extend([curr_idx, i])
                        
            edge_index = np.array([edges_src, edges_dst], dtype=np.int64)
            feature_matrix = np.vstack(self.history_features)
            
            # Sub-graph batch evaluation
            preds, probs = self.engine.predict(feature_matrix, edge_index)
            
            curr_prob = probs[curr_idx]
            self.stats["total"] += 1
            
            if preds[curr_idx] == 1 and curr_prob > 0.85:
                self.stats["attacks"] += 1
                log.warning(f"[ALERT/HIGH] Attack detected | flow={key} | prob={curr_prob:.3f} | dst_port={flow.dst_port} proto={flow.protocol}")
            else:
                self.stats["benign"] += 1
        except Exception as exc:
            log.error(f"Classification error: {exc}")

def main():
    iface = detect_active_interface()
    engine = IDSInferenceEngine(Path("/opt/gnn-ids/model.onnx"), Path("/opt/gnn-ids/feature_extractor.pkl"))
    engine.load()
    processor = PacketProcessor(engine)
    
    import threading
    def _stats_loop():
        while True:
            time.sleep(60)
            log.info(f"STATS | total={processor.stats['total']} benign={processor.stats['benign']} attacks={processor.stats['attacks']} active_flows={len(processor.flows)}")
    threading.Thread(target=_stats_loop, daemon=True).start()

    log.info(f"Starting packet capture on {iface}")
    scapy_conf.verb = 0
    sniff(iface=iface, filter="ip", prn=processor.process_packet, store=False)

if __name__ == "__main__": main()
