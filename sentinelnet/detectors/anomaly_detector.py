"""
SentinelNet - ML-Based Anomaly Detector
=========================================
Behavioral anomaly detection using Isolation Forest and statistical z-score
methods applied to network flow feature vectors.

Features:
- Unsupervised anomaly detection (no labeled data needed)
- Incremental learning (adapts to baseline over time)
- Per-source IP profiling
- Flow feature normalization
- Explainable anomaly scores

Dependencies: scikit-learn, numpy
"""

import uuid
import time
import logging
import threading
import pickle
from collections import deque
from typing import Dict, List, Optional, Tuple
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)


class FlowProfiler:
    """
    Maintains a rolling statistical profile (mean, std) for a source IP.
    Used for z-score based anomaly detection.
    """
    FEATURE_NAMES = [
        "duration", "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
        "bytes_per_sec", "packets_per_sec", "avg_fwd_iat", "avg_bwd_iat",
        "syn_count", "fin_count", "rst_count", "psh_count",
        "flag_ratio", "fwd_payload", "bwd_payload", "pkt_size_ratio",
    ]
    N_FEATURES = len(FEATURE_NAMES)

    def __init__(self, window_size: int = 500):
        self.window_size = window_size
        self._buffer: deque = deque(maxlen=window_size)
        self._mean: Optional[np.ndarray] = None
        self._std: Optional[np.ndarray] = None
        self._lock = threading.Lock()

    def update(self, features: Dict[str, float]):
        vec = self._dict_to_vector(features)
        with self._lock:
            self._buffer.append(vec)
            if len(self._buffer) >= 10:
                data = np.array(self._buffer)
                self._mean = data.mean(axis=0)
                self._std = data.std(axis=0) + 1e-8

    def zscore(self, features: Dict[str, float]) -> Optional[np.ndarray]:
        """Compute per-feature z-scores relative to the profile."""
        with self._lock:
            if self._mean is None:
                return None
            vec = self._dict_to_vector(features)
            return np.abs((vec - self._mean) / self._std)

    def anomaly_score(self, features: Dict[str, float]) -> Tuple[float, List[str]]:
        """
        Returns:
            score (float): 0 = normal, 1 = highly anomalous
            top_features (List[str]): names of most anomalous features
        """
        zs = self.zscore(features)
        if zs is None:
            return 0.0, []

        score = float(np.tanh(np.mean(zs) / 3.0))  # normalize to [0, 1]
        top_idx = np.argsort(zs)[::-1][:3]
        top_features = [f"{self.FEATURE_NAMES[i]} (z={zs[i]:.2f})" for i in top_idx]
        return score, top_features

    def _dict_to_vector(self, features: Dict[str, float]) -> np.ndarray:
        return np.array([features.get(k, 0.0) for k in self.FEATURE_NAMES], dtype=np.float64)

    @property
    def sample_count(self) -> int:
        return len(self._buffer)


class IsolationForestDetector:
    """
    Global anomaly detector using Isolation Forest.
    Retrains periodically on the accumulated flow buffer.

    The Isolation Forest algorithm isolates observations by randomly
    selecting a feature and a split value. Anomalies require fewer splits
    to isolate, resulting in shorter average path lengths.
    """

    def __init__(
        self,
        n_estimators: int = 100,
        contamination: float = 0.05,
        retrain_interval: int = 1000,   # flows between retrains
        model_path: Optional[str] = None,
    ):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.retrain_interval = retrain_interval
        self.model_path = model_path

        self._model = None
        self._buffer: List[np.ndarray] = []
        self._flows_since_retrain = 0
        self._lock = threading.Lock()

        if model_path and Path(model_path).exists():
            self._load_model(model_path)
        else:
            self._init_model()

    def _init_model(self):
        from sklearn.ensemble import IsolationForest
        self._model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        logger.info("IsolationForest initialized (not yet fitted)")

    def _load_model(self, path: str):
        try:
            with open(path, "rb") as f:
                self._model = pickle.load(f)
            logger.info("IsolationForest model loaded from %s", path)
        except Exception as e:
            logger.warning("Failed to load model: %s. Initializing fresh.", e)
            self._init_model()

    def save_model(self, path: str):
        with open(path, "wb") as f:
            pickle.dump(self._model, f)
        logger.info("IsolationForest model saved to %s", path)

    def feed(self, feature_vec: np.ndarray) -> Optional[float]:
        """
        Feed a flow feature vector.
        Returns anomaly score (0=normal, 1=anomaly) or None if model not fitted.
        """
        with self._lock:
            self._buffer.append(feature_vec)
            self._flows_since_retrain += 1

            if self._flows_since_retrain >= self.retrain_interval:
                self._retrain()
                self._flows_since_retrain = 0

            if not self._is_fitted():
                return None

            score = self._model.decision_function([feature_vec])[0]
            # Convert to [0, 1]: more negative = more anomalous
            normalized = 1.0 - (score - (-0.5)) / (0.5 - (-0.5))
            return float(np.clip(normalized, 0.0, 1.0))

    def _retrain(self):
        if len(self._buffer) < 50:
            return
        data = np.array(self._buffer[-5000:])  # use recent history
        try:
            self._model.fit(data)
            logger.info("IsolationForest retrained on %d samples", len(data))
            if self.model_path:
                self.save_model(self.model_path)
        except Exception as e:
            logger.error("IsolationForest retrain failed: %s", e)

    def _is_fitted(self) -> bool:
        try:
            from sklearn.exceptions import NotFittedError
            from sklearn.utils.validation import check_is_fitted
            check_is_fitted(self._model)
            return True
        except Exception:
            return False


class AnomalyDetectionEngine:
    """
    Combines per-IP statistical profiling (z-score) with global
    IsolationForest to produce robust anomaly detection.

    Emits ThreatEvents to the EventBus when anomalies are detected.
    """

    def __init__(self, bus, anomaly_threshold: float = 0.75, model_path: Optional[str] = None):
        from ..core.event_bus import EventBus, ThreatEvent, Severity
        self.bus = bus
        self.threshold = anomaly_threshold
        self.Severity = Severity
        self.ThreatEvent = ThreatEvent

        self._profilers: Dict[str, FlowProfiler] = {}
        self._iso_forest = IsolationForestDetector(model_path=model_path)
        self._profiler_lock = threading.Lock()
        self._stats = {"analyzed": 0, "anomalies": 0}

    def analyze_flow(self, flow) -> Optional[float]:
        """
        Analyze a completed flow record.
        Returns combined anomaly score or None.
        """
        features = flow.to_feature_vector()
        feat_vec = np.array([features.get(k, 0.0) for k in FlowProfiler.FEATURE_NAMES])

        # Update per-IP profiler
        with self._profiler_lock:
            if flow.src_ip not in self._profilers:
                self._profilers[flow.src_ip] = FlowProfiler()
            profiler = self._profilers[flow.src_ip]

        profiler.update(features)
        zscore_score, top_features = profiler.anomaly_score(features)
        iso_score = self._iso_forest.feed(feat_vec) or 0.0

        # Weighted combination: 40% z-score + 60% IsoForest
        combined = 0.4 * zscore_score + 0.6 * iso_score
        self._stats["analyzed"] += 1

        if combined >= self.threshold:
            self._stats["anomalies"] += 1
            self._emit_anomaly(flow, combined, top_features, zscore_score, iso_score)

        return combined

    def _emit_anomaly(self, flow, score: float, top_features: List[str],
                      zscore_score: float, iso_score: float):
        event = self.ThreatEvent(
            event_id=str(uuid.uuid4()),
            source="AnomalyDetectionEngine",
            severity=self.Severity.HIGH if score > 0.9 else self.Severity.MEDIUM,
            threat_type="behavioral_anomaly",
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            score=round(score, 4),
            description=f"Behavioral anomaly from {flow.src_ip} → {flow.dst_ip} (score={score:.3f})",
            evidence={
                "zscore_component": round(zscore_score, 4),
                "isolation_forest_component": round(iso_score, 4),
                "top_anomalous_features": top_features,
                "flow_duration": flow.duration,
                "total_bytes": flow.total_bytes,
            },
            mitre_tactic="Unknown",
            mitre_technique="",
        )
        self.bus.publish(event)

    def get_stats(self) -> Dict[str, int]:
        return dict(self._stats)

    def get_profiler_summary(self) -> List[Dict]:
        with self._profiler_lock:
            return [
                {"src_ip": ip, "samples": p.sample_count}
                for ip, p in self._profilers.items()
            ]
