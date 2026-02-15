"""
DB1 Traffic Client - reads raw traffic from MongoDB Atlas (DB1).
Supports VPC Flow Log style and common packet schemas.
"""
import os
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

MONGODB_URI_DB1 = os.environ.get("MONGODB_URI_DB1", "")
DB1_DATABASE = os.environ.get("DB1_DATABASE", "")
DB1_COLLECTION = os.environ.get("DB1_COLLECTION", "traffic")
DB1_BATCH_SIZE = int(os.environ.get("DB1_BATCH_SIZE", "500"))


def _doc_to_packet_data(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Convert DB1 document to packet_data format for PacketInfo."""
    src = doc.get("srcaddr") or doc.get("src_ip") or doc.get("source") or "0.0.0.0"
    dst = doc.get("dstaddr") or doc.get("dst_ip") or doc.get("destination") or "0.0.0.0"
    src_port = _safe_int(doc.get("srcport") or doc.get("src_port") or doc.get("source_port"), 0)
    dst_port = _safe_int(doc.get("dstport") or doc.get("dst_port") or doc.get("destination_port"), 0)
    protocol_num = doc.get("protocol")
    if isinstance(protocol_num, int):
        protocol = {6: "tcp", 17: "udp", 1: "icmp"}.get(protocol_num, "tcp")
    else:
        protocol = str(protocol_num or "tcp").lower()
    packets = _safe_int(doc.get("packets"), 1)
    bytes_val = _safe_int(doc.get("bytes") or doc.get("bytes_val") or doc.get("size"), 100)

    ts = doc.get("timestamp") or doc.get("time") or doc.get("start") or doc.get("createdAt")
    if ts is None and "_id" in doc and hasattr(doc["_id"], "generation_time"):
        ts = doc["_id"].generation_time
    if ts is None:
        ts = datetime.utcnow()
    elif isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            ts = datetime.utcnow()
    elif not isinstance(ts, datetime):
        ts = datetime.utcnow()

    return {
        "src_ip": str(src),
        "dst_ip": str(dst),
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "payload": b"",
        "size": bytes_val,
        "flags": {},
        "timestamp": ts,
        "_ts": ts,
        "_packets": packets,
        "_db_id": str(doc.get("_id", "")),
    }


def _safe_int(v: Any, default: int) -> int:
    try:
        return int(v) if v not in (None, "-", "") else default
    except (ValueError, TypeError):
        return default


def get_db1_client():
    """Return MongoDB client for DB1. Raises if not configured."""
    if not MONGODB_URI_DB1:
        raise ValueError("MONGODB_URI_DB1 not configured")
    try:
        from pymongo import MongoClient
        return MongoClient(MONGODB_URI_DB1)
    except ImportError:
        raise ValueError("pymongo required. pip install pymongo")


def fetch_traffic_batch(
    since: Optional[datetime] = None,
    limit: int = DB1_BATCH_SIZE,
    collection: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Fetch traffic records from DB1. Returns list of packet_data dicts.
    Uses timestamp, time, or start field for ordering. Default since = 1 hour ago.
    """
    if not MONGODB_URI_DB1:
        return []

    try:
        client = get_db1_client()
        coll_name = collection or DB1_COLLECTION
        db = client[DB1_DATABASE] if DB1_DATABASE else client.get_default_database()
        coll = db[coll_name]

        if since is None:
            since = datetime.utcnow() - timedelta(hours=1)

        # Build query for documents with timestamp after since
        query = {
            "$or": [
                {"timestamp": {"$gt": since}},
                {"time": {"$gt": since}},
                {"start": {"$gt": since}},
                {"createdAt": {"$gt": since}},
            ]
        }
        cursor = coll.find(query).sort([("timestamp", 1), ("time", 1), ("start", 1), ("_id", 1)]).limit(limit)
        docs = list(cursor)
        client.close()

        return [_doc_to_packet_data(d) for d in docs]
    except Exception as e:
        logger.error(f"DB1 fetch error: {e}")
        return []
