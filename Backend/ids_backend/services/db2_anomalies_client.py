"""
DB2 Anomalies Client - writes anomaly events to MongoDB Atlas (DB2).
Anomalies are unclassified; the classifier pipeline will read and update them.
"""
import os
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from detection.anomaly_classifier import AnomalyEvent

logger = logging.getLogger(__name__)

MONGODB_URI_DB2 = os.environ.get("MONGODB_URI_DB2", "")
DB2_DATABASE = os.environ.get("DB2_DATABASE", "")
DB2_COLLECTION = os.environ.get("DB2_COLLECTION", "anomalies")
DB2_STATE_COLLECTION = "pipeline_state"


def get_db2_client():
    """Return MongoDB client for DB2."""
    if not MONGODB_URI_DB2:
        raise ValueError("MONGODB_URI_DB2 not configured")
    try:
        from pymongo import MongoClient
        return MongoClient(MONGODB_URI_DB2)
    except ImportError:
        raise ValueError("pymongo required. pip install pymongo")


def _anomaly_to_doc(event: AnomalyEvent) -> Dict[str, Any]:
    """Convert AnomalyEvent to DB2 document."""
    ts = event.timestamp
    if hasattr(ts, "isoformat"):
        ts_str = ts.isoformat()
    else:
        ts_str = datetime.utcnow().isoformat()

    return {
        "anomaly_type": event.anomaly_type,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "destination_port": event.destination_port,
        "timestamp": ts_str,
        "description": event.description,
        "suggested_severity": event.suggested_severity,
        "features": event.features or {},
        "classified": False,
        "created_at": datetime.utcnow().isoformat(),
    }


def write_anomalies(events: List[AnomalyEvent]) -> int:
    """Write anomaly events to DB2. Returns count written."""
    if not MONGODB_URI_DB2 or not events:
        return 0

    try:
        client = get_db2_client()
        db = client[DB2_DATABASE] if DB2_DATABASE else client.get_default_database()
        coll = db[DB2_COLLECTION]
        docs = [_anomaly_to_doc(e) for e in events]
        result = coll.insert_many(docs)
        client.close()
        logger.info(f"Wrote {len(result.inserted_ids)} anomalies to DB2")
        return len(result.inserted_ids)
    except Exception as e:
        logger.error(f"DB2 write error: {e}")
        return 0


def save_pipeline_state(last_processed_at: datetime) -> None:
    """Save last processed timestamp for next run."""
    if not MONGODB_URI_DB2:
        return
    try:
        client = get_db2_client()
        db = client[DB2_DATABASE] if DB2_DATABASE else client.get_default_database()
        coll = db[DB2_STATE_COLLECTION]
        coll.update_one(
            {"_id": "anomaly_pipeline"},
            {"$set": {"last_processed_at": last_processed_at, "last_run_at": datetime.utcnow()}},
            upsert=True,
        )
        client.close()
    except Exception as e:
        logger.warning(f"Failed to save pipeline state: {e}")


def get_last_processed_at() -> Optional[datetime]:
    """Get last processed timestamp for incremental fetch."""
    if not MONGODB_URI_DB2:
        return None
    try:
        client = get_db2_client()
        db = client[DB2_DATABASE] if DB2_DATABASE else client.get_default_database()
        doc = db[DB2_STATE_COLLECTION].find_one({"_id": "anomaly_pipeline"})
        client.close()
        if doc and doc.get("last_processed_at"):
            return doc["last_processed_at"]
    except Exception as e:
        logger.warning(f"Failed to get pipeline state: {e}")
    return None
