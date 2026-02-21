"""
inference.py — CPU ONNX Inference Engine
Phase 3 Upgrade: Supports dynamic topological input (edge_index).
"""
import pickle, logging
import numpy as np
import onnxruntime as ort
from pathlib import Path
from typing import List, Tuple

log = logging.getLogger(__name__)

class IDSInferenceEngine:
    def __init__(self, model_path: Path, extractor_path: Path):
        self.model_path = Path(model_path)
        self.extractor_path = Path(extractor_path)

    def load(self):
        sess_opts = ort.SessionOptions()
        sess_opts.intra_op_num_threads = 4
        self._session = ort.InferenceSession(str(self.model_path), sess_options=sess_opts, providers=["CPUExecutionProvider"])
        with open(self.extractor_path, "rb") as fh:
            payload = pickle.load(fh)
        self._scaler = payload["scaler"]
        self._feature_cols = payload["feature_cols"]

    @property
    def feature_cols(self) -> List[str]:
        return self._feature_cols

    def predict(self, raw_features: np.ndarray, edge_index: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        # raw_features: (N, 58), edge_index: (2, E)
        scaled = self._scaler.transform(raw_features).astype(np.float32)
        
        if edge_index.size == 0:
            edge_index = np.zeros((2, 0), dtype=np.int64)

        logits = self._session.run(
            ["logits"], 
            {"node_features": scaled, "edge_index": edge_index.astype(np.int64)}
        )[0]
        
        e = np.exp(logits - logits.max(axis=1, keepdims=True))
        probs = e / e.sum(axis=1, keepdims=True)
        predictions = (probs[:, 1] >= 0.8).astype(int) # High strictness
        return predictions, probs[:, 1]
