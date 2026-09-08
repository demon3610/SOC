from datetime import timezone
from pymongo import MongoClient
from app.config import MONGO_URL, MONGO_DB_NAME

client = MongoClient(MONGO_URL, tz_aware=True, tzinfo=timezone.utc)
db = client[MONGO_DB_NAME]


def get_db():
    return db


def get_next_id(collection_name: str) -> int:
    counter = db.counters.find_one_and_update(
        {"_id": collection_name},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=True,
    )
    return counter["seq"]


def get_next_id_batch(collection_name: str, count: int) -> list[int]:
    """Reserve `count` sequential IDs in a single atomic counter update."""
    if count <= 0:
        return []
    counter = db.counters.find_one_and_update(
        {"_id": collection_name},
        {"$inc": {"seq": count}},
        upsert=True,
        return_document=True,
    )
    start = counter["seq"] - count
    return list(range(start + 1, counter["seq"] + 1))


NO_ID = {"_id": 0}


def get_events_collection(source: str):
    """Resolve the per-source events collection.

    Each source (website visitors, Windows agents, Linux agents) gets its own
    collection so one noisy source never slows queries against another.
    """
    return {
        "website": db.events_website,
        "windows": db.events_windows,
        "linux": db.events_linux,
    }.get(source, db.events_website)


def all_events_collections():
    """All per-source event collections, for cross-source queries."""
    return (db.events_website, db.events_windows, db.events_linux)


def agent_events_collections():
    """The two agent-sourced event collections (windows + linux)."""
    return (db.events_windows, db.events_linux)


EVENTS_SOURCES = ("website", "windows", "linux")

AGENT_CATEGORIES = ("security_event", "heartbeat", "lifecycle")

# Lives on events_windows / events_linux documents. The curated events surface
# (Live Events, threat intel, overview stats, events cleanup) shows only
# security_event documents plus all website documents (which carry no
# category); heartbeat/lifecycle raw agent entries are browsed through
# GET /agents/logs and the "raw agent logs" cleanup instead.
EVENTS_VIEW_COND = {
    "$or": [
        {"category": "security_event"},
        {"category": {"$exists": False}},
    ]
}

# Raw agent entries (lifecycle + heartbeat) — everything that is NOT a
# security event, i.e. exactly what the "raw agent logs" cleanup targets.
RAW_AGENT_COND = {"category": {"$ne": "security_event"}}


def strip_mongo_id(doc: dict) -> dict:
    doc.pop("_id", None)
    return doc


def ensure_indexes():
    db.users.create_index("email", unique=True)
    db.api_keys.create_index("key_hash")
    db.agent_keys.create_index("key_hash", unique=True)
    db.agent_keys.create_index("key_prefix", unique=True)
    db.agent_keys.create_index("created_by")
    db.projects.create_index("owner_id")
    db.agent_keys.create_index("project_id")
    db.incidents.create_index("project_id")
    db.incidents.create_index("id")
    db.incident_evidence.create_index("incident_id")
    db.threat_suppressions.create_index([("project_id", 1), ("value", 1)])
    for source in EVENTS_SOURCES:
        db[f"events_{source}"].create_index("id")
    db.threat_indicators.create_index([("project_id", 1), ("source", 1)])
    db.threat_indicators.create_index([("project_id", 1), ("value", 1)], unique=True)
    # IOC allowlist: known-good infra (scanners, CI) that must never be
    # flagged as known threats. One entry per (project, indicator).
    db.ioc_allowlist.create_index([("project_id", 1), ("indicator", 1)], unique=True)
    # Multi-feed cache: an IP may legitimately appear in several feeds, so the
    # uniqueness is per (value, source_feed), not per value alone.
    try:
        db.threat_feed_cache.drop_index("value_1")
    except Exception:
        pass  # index never existed on fresh installs
    db.threat_feed_cache.create_index([("value", 1), ("source_feed", 1)], unique=True)
    db.audit_log.create_index([("project_id", 1), ("executed_at", -1)])
    db.audit_log.create_index([("entity_type", 1), ("incident_id", 1), ("timestamp", 1)])
    for source in EVENTS_SOURCES:
        db[f"events_{source}"].create_index(
            [("project_id", 1), ("timestamp", -1)]
        )
    for source in ("windows", "linux"):
        db[f"events_{source}"].create_index("agent_id")
