"""
Database client - persists alerts to the IDS Database service (MongoDB).
Configure via IDS_DATABASE_URL (e.g. http://localhost:3001). When not set, persistence is skipped.
"""
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

DATABASE_URL = os.environ.get("IDS_DATABASE_URL", "").rstrip("/")


def _alert_to_db_payload(alert) -> dict:
    """Map Backend Alert to Database (Mongoose) format."""
    return {
        "id": alert.id,
        "time": alert.timestamp.isoformat() if hasattr(alert.timestamp, "isoformat") else str(alert.timestamp),
        "timestamp": alert.timestamp.isoformat() if hasattr(alert.timestamp, "isoformat") else str(alert.timestamp),
        "severity": alert.level.name if hasattr(alert.level, "name") else str(alert.level),
        "type": alert.alert_type,
        "source": alert.source_ip,
        "destination": alert.destination_ip or "",
        "destinationPort": alert.destination_port,
        "description": alert.description,
        "status": alert.status.value if hasattr(alert.status, "value") else str(alert.status),
        "packets": 1,
        "anomaly": alert.metadata.get("anomaly_score", -1) if isinstance(alert.metadata, dict) else -1,
        "metadata": alert.metadata or {},
    }


def persist_alert(alert) -> bool:
    """
    Persist an alert to the Database service. Returns True on success, False on failure/skip.
    """
    if not DATABASE_URL:
        return False

    try:
        import requests
    except ImportError:
        logger.warning("requests required for database persistence")
        return False

    try:
        payload = _alert_to_db_payload(alert)
        r = requests.post(
            f"{DATABASE_URL}/alerts",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        if r.status_code in (200, 201):
            logger.debug(f"Alert {alert.id} persisted to database")
            return True
        logger.warning(f"Database persist failed: {r.status_code} {r.text[:200]}")
        return False
    except Exception as e:
        logger.warning(f"Database persist error: {e}")
        return False
