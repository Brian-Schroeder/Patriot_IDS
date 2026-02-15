"""
Anomaly Pipeline - reads traffic from DB1, runs anomaly detection, writes to DB2.
Trigger via POST /api/v1/pipeline/run-anomaly or run as scheduled job.
"""
import logging
from datetime import datetime, timedelta
from typing import List

from detection.packet_analyzer import PacketAnalyzer, PacketInfo
from detection.anomaly_detector import AnomalyDetector
from detection.anomaly_classifier import AnomalyEvent
from detection.ml_anomaly_detector import MLAnomalyDetector

from services.db1_traffic_client import fetch_traffic_batch, MONGODB_URI_DB1
from services.db2_anomalies_client import (
    write_anomalies,
    save_pipeline_state,
    get_last_processed_at,
    MONGODB_URI_DB2,
)

logger = logging.getLogger(__name__)


def run_anomaly_pipeline(
    batch_size: int = 500,
    use_ml_detector: bool = True,
    hours_back: int = 1,
) -> dict:
    """
    Run the anomaly detection pipeline:
    1. Fetch traffic from DB1
    2. Run statistical + ML anomaly detectors
    3. Write anomalies to DB2

    Returns dict with counts and status.
    """
    if not MONGODB_URI_DB1:
        return {
            "success": False,
            "message": "MONGODB_URI_DB1 not configured",
            "traffic_fetched": 0,
            "anomalies_written": 0,
        }
    if not MONGODB_URI_DB2:
        return {
            "success": False,
            "message": "MONGODB_URI_DB2 not configured",
            "traffic_fetched": 0,
            "anomalies_written": 0,
        }

    since = get_last_processed_at()
    if since is None:
        since = datetime.utcnow() - timedelta(hours=hours_back)

    packet_data_list = fetch_traffic_batch(since=since, limit=batch_size)
    if not packet_data_list:
        return {
            "success": True,
            "message": "No new traffic to process",
            "traffic_fetched": 0,
            "anomalies_written": 0,
        }

    analyzer = PacketAnalyzer()
    anomaly_detector = AnomalyDetector(time_window_minutes=5)
    ml_detector = MLAnomalyDetector() if use_ml_detector else None

    all_anomalies: List[AnomalyEvent] = []
    max_ts = since

    for pd in packet_data_list:
        try:
            packet_info = analyzer.analyze(pd)
            if hasattr(packet_info.timestamp, "replace"):
                max_ts = max(max_ts, packet_info.timestamp)

            anomaly_events: List[AnomalyEvent] = []

            packet_anomalies = analyzer.check_packet_anomalies(packet_info)
            for desc in packet_anomalies:
                anomaly_events.append(
                    AnomalyEvent(
                        anomaly_type="PACKET_ANOMALY",
                        source_ip=packet_info.source_ip,
                        timestamp=packet_info.timestamp,
                        description=desc,
                        suggested_severity="MEDIUM",
                        destination_ip=packet_info.destination_ip,
                        destination_port=packet_info.destination_port,
                        features={"packet_size": packet_info.size},
                    )
                )

            anomaly_events.extend(anomaly_detector.detect_anomalies(packet_info))

            if ml_detector:
                ml_detector.add_packet(packet_info)
                ml_evt = ml_detector.extract_and_predict(packet_info)
                if ml_evt:
                    anomaly_events.append(ml_evt)

            all_anomalies.extend(anomaly_events)
        except Exception as e:
            logger.warning(f"Pipeline packet error: {e}")
            continue

    written = write_anomalies(all_anomalies)
    save_pipeline_state(max_ts)

    return {
        "success": True,
        "message": f"Processed {len(packet_data_list)} packets, found {len(all_anomalies)} anomalies",
        "traffic_fetched": len(packet_data_list),
        "anomalies_written": written,
    }
