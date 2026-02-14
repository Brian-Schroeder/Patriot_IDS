"""
Classifier that takes anomaly events from the anomaly detector and produces
final alerts with attack type and severity classification.
Designed to be extended with ML models (e.g., scikit-learn) later.
"""
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from datetime import datetime
import logging

from models.alert import Alert, AlertLevel
from detection.packet_analyzer import PacketInfo

logger = logging.getLogger(__name__)


@dataclass
class AnomalyEvent:
    """Raw anomaly detected by the anomaly model - input to the classifier"""
    anomaly_type: str  # e.g., PORT_SCAN, TRAFFIC_SPIKE, SYN_FLOOD
    source_ip: str
    timestamp: datetime
    description: str
    features: Dict[str, Any] = field(default_factory=dict)
    suggested_severity: str = "MEDIUM"  # hint from detector
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None


# Attack type taxonomy (aligned with frontend)
ATTACK_TYPE_MAP = {
    "PORT_SCAN": "Port Scan",
    "HIGH_TRAFFIC_VOLUME": "DDoS",
    "TRAFFIC_SPIKE": "DDoS",
    "CONNECTION_FLOOD": "DDoS",
    "SYN_FLOOD": "DDoS",
    "BRUTE_FORCE": "Brute Force",
    "PACKET_ANOMALY": "Buffer Overflow",  # invalid flags, etc.
    "MALICIOUS_PAYLOAD": "Malware C2",  # or could be SQLi/XSS based on payload
    "ML_ANOMALY": "Anomaly",  # ML-detected (Isolation Forest)
}

# Severity refinement based on anomaly strength
SEVERITY_MAP = {
    "LOW": AlertLevel.LOW,
    "MEDIUM": AlertLevel.MEDIUM,
    "HIGH": AlertLevel.HIGH,
    "CRITICAL": AlertLevel.CRITICAL,
}


class AnomalyClassifier:
    """
    Classifies anomaly events into alerts with attack types and severity.
    Uses rule-based mapping by default; can be extended with ML models.
    """

    def __init__(self):
        self.classifications_count: int = 0

    def classify(self, anomaly: AnomalyEvent, packet: Optional[PacketInfo] = None) -> Alert:
        """
        Classify an anomaly event into a final alert.
        Args:
            anomaly: The raw anomaly event from the detector
            packet: Optional packet context (for additional features)
        Returns:
            Alert with attack_type and severity
        """
        self.classifications_count += 1

        # Map anomaly type to attack type
        base_type = anomaly.anomaly_type.split(":")[-1] if ":" in anomaly.anomaly_type else anomaly.anomaly_type
        attack_type = ATTACK_TYPE_MAP.get(base_type, f"Anomaly:{base_type}")

        # Refine severity (classifier can override detector's suggestion)
        severity = self._refine_severity(anomaly, attack_type)

        return Alert(
            alert_type=attack_type,
            source_ip=anomaly.source_ip,
            destination_ip=anomaly.destination_ip,
            destination_port=anomaly.destination_port,
            description=anomaly.description,
            level=severity,
            metadata={
                "anomaly_type": anomaly.anomaly_type,
                "classifier": "rule_based",
                **anomaly.features,
            },
            timestamp=anomaly.timestamp,
        )

    def _refine_severity(self, anomaly: AnomalyEvent, attack_type: str) -> AlertLevel:
        """Refine severity based on anomaly features and attack type"""
        try:
            base_level = SEVERITY_MAP.get(
                anomaly.suggested_severity.upper(),
                AlertLevel.MEDIUM
            )
        except (KeyError, AttributeError):
            base_level = AlertLevel.MEDIUM

        # Escalate based on feature severity (e.g., very high port count)
        features = anomaly.features
        if "ports_scanned" in features and features["ports_scanned"] > 100:
            return max(base_level, AlertLevel.HIGH, key=lambda x: x.value)
        if "syn_count" in features and features["syn_count"] > 1000:
            return AlertLevel.CRITICAL
        if "failed_attempts" in features and features["failed_attempts"] > 20:
            return max(base_level, AlertLevel.HIGH, key=lambda x: x.value)
        # ML anomalies: lower score = more anomalous
        if "anomaly_score" in features:
            score = features["anomaly_score"]
            if score < -0.3:
                return max(base_level, AlertLevel.HIGH, key=lambda x: x.value)
            if score < -0.5:
                return AlertLevel.CRITICAL

        return base_level

    def classify_batch(self, anomalies: List[AnomalyEvent], packet: Optional[PacketInfo] = None) -> List[Alert]:
        """Classify multiple anomalies"""
        return [self.classify(a, packet) for a in anomalies]

    def get_stats(self) -> Dict[str, Any]:
        return {"classifications_count": self.classifications_count}
