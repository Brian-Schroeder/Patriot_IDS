"""
ML-based anomaly detection using scikit-learn's Isolation Forest.
Fits on baseline/normal traffic and flags anomalies.
"""
from typing import List, Optional, Dict, Any
from datetime import datetime
import logging
import random

from detection.anomaly_classifier import AnomalyEvent
from detection.ml_feature_extractor import PacketWindow, FeatureVector, FEATURE_NAMES
from detection.packet_analyzer import PacketInfo

logger = logging.getLogger(__name__)


def _generate_baseline_features(n_samples: int = 200) -> List[List[float]]:
    """
    Generate synthetic 'normal' traffic features for initial model fitting.
    Represents low-volume, typical browsing/connection behavior.
    """
    samples = []
    for _ in range(n_samples):
        samples.append([
            random.uniform(5, 80),       # packet_count
            random.uniform(2, 10),       # log bytes
            random.uniform(1, 8),        # unique_dest_ports
            random.uniform(1, 5),       # unique_dest_ips
            random.uniform(1, 20),      # unique_src_ips
            random.uniform(2, 30),      # max_packets_per_ip
            random.uniform(1, 6),       # max_ports_per_ip
            random.uniform(0, 0.3),     # syn_ratio
            random.uniform(200, 800),   # avg_packet_size
            random.uniform(0.5, 1.0),   # protocol_tcp_ratio
        ])
    return samples


class MLAnomalyDetector:
    """
    Isolation Forest-based anomaly detector.
    Fits on baseline traffic (or synthetic normal data) and flags anomalies.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 100,
        min_samples_to_fit: int = 50,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.min_samples_to_fit = min_samples_to_fit
        self._model = None
        self._fitted = False
        self._packet_window = PacketWindow(max_size=500)
        self._calibration_samples: List[List[float]] = []
        self._predictions_count = 0
        self._anomalies_detected = 0

    def add_packet(self, packet: PacketInfo) -> None:
        """Add packet to the rolling window"""
        self._packet_window.add(packet)

    def _ensure_fitted(self) -> bool:
        """Ensure model is fitted. Uses calibration samples or synthetic baseline."""
        if self._fitted and self._model is not None:
            return True

        try:
            import numpy as np
            from sklearn.ensemble import IsolationForest
        except ImportError as e:
            logger.warning("scikit-learn not installed. ML anomaly detection disabled. pip install scikit-learn numpy")
            return False

        # Use calibration samples if we have enough, else synthetic
        if len(self._calibration_samples) >= self.min_samples_to_fit:
            X = np.array(self._calibration_samples, dtype=np.float64)
            logger.info(f"Fitting ML anomaly detector on {len(X)} calibration samples")
        else:
            X = np.array(_generate_baseline_features(200), dtype=np.float64)
            logger.info("Fitting ML anomaly detector on synthetic baseline (no calibration data yet)")

        self._model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=42,
        )
        self._model.fit(X)
        self._fitted = True
        return True

    def extract_and_predict(self, packet: PacketInfo) -> Optional[AnomalyEvent]:
        """
        Extract features from window and run prediction.
        Returns AnomalyEvent if anomaly detected, else None.
        """
        if not self._packet_window.should_extract():
            return None

        fv = self._packet_window.extract_features()
        if fv is None:
            return None

        import numpy as np

        # Collect calibration samples during warmup; fit on first run (synthetic or real data)
        if not self._fitted:
            self._calibration_samples.append(fv.values)

        if not self._ensure_fitted():
            return None

        X = np.array([fv.values], dtype=np.float64)
        if self._model is None:
            return None
        pred = self._model.predict(X)[0]
        score = self._model.decision_function(X)[0]
        self._predictions_count += 1

        # -1 = anomaly, 1 = normal
        if pred == -1:
            self._anomalies_detected += 1
            return AnomalyEvent(
                anomaly_type="ML_ANOMALY",
                source_ip=fv.source_ip,
                timestamp=datetime.utcnow(),
                description=f"ML anomaly detected (Isolation Forest score: {score:.4f})",
                suggested_severity="MEDIUM",
                features={
                    "anomaly_score": float(score),
                    "packet_count": fv.packet_count,
                    "model": "IsolationForest",
                },
            )
        return None

    def add_calibration_sample(self, feature_vector: List[float]) -> None:
        """Add a feature vector for calibration (optional manual feeding)"""
        if len(feature_vector) == len(FEATURE_NAMES):
            self._calibration_samples.append(feature_vector)

    def reset_calibration(self) -> None:
        """Clear calibration data; next fit will use synthetic baseline"""
        self._calibration_samples.clear()
        self._fitted = False
        self._model = None

    def get_stats(self) -> Dict[str, Any]:
        return {
            "fitted": self._fitted,
            "calibration_samples": len(self._calibration_samples),
            "predictions_count": self._predictions_count,
            "anomalies_detected": self._anomalies_detected,
        }
