"""Known-malicious indicator store.

Feed IPs are pulled from a public blocklist (abuse.ch Feodo Tracker by
default, no API key) in a background daemon thread and cached BOTH in memory
(hot path for ingest-time flagging) and in Mongo (``threat_feed_cache``) so
the last good snapshot survives restarts. The parser also tolerates
CSV-shaped feeds such as the abuse.ch SSL Blacklist by scanning every comma-
and whitespace-separated token.

Manual per-project indicators (source=manual) live in the
``threat_indicators`` collection and are merged into the in-memory set so
they flag ingests immediately; a feed refresh replaces only the feed half and
never touches manual entries.
"""

import ipaddress
import logging
import threading
import time
import urllib.request
from datetime import datetime, timezone

from app.config import THREAT_FEED_URL, THREAT_FEED_REFRESH_HOURS

logger = logging.getLogger(__name__)

_feed: set[str] = set()
_manual: set[str] = set()
_lock = threading.Lock()
_last_sync: float | None = None
_last_error: str | None = None
_refresh_interval = max(int(THREAT_FEED_REFRESH_HOURS), 1) * 3600

FEED_SOURCE_NAME = THREAT_FEED_URL.split("//")[-1].split("/")[0] or THREAT_FEED_URL


def _parse_feed(text: str) -> set[str]:
    """Extract valid public IPs from plain lists or CSV feeds.

    Tolerates comments (#), blank lines, whitespace padding and CSV columns
    (e.g. sslbl rows like ``1700000000,1.2.3.4,5.6.7.8,443,SSL-IP-Blacklist``);
    only genuinely parseable, non-reserved IPs are kept.
    """
    ips: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.replace(",", " ").split()
        for token in tokens:
            try:
                addr = ipaddress.ip_address(token)
            except ValueError:
                continue
            if addr.is_global:
                ips.add(token)
    return ips


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _persist_snapshot(ips: set[str]) -> None:
    """Write the feed snapshot to Mongo (best effort — never raises).

    Upserts one doc per IP in ``threat_feed_cache`` (preserving first_seen),
    prunes IPs that left the feed, and records a meta doc with the sync time.
    """
    try:
        from app.database import db  # noqa: PLC0415 - lazy import, DB may be optional

        col = db.threat_feed_cache
        now = _now_iso()
        for ip in ips:
            col.update_one(
                {"value": ip},
                {"$set": {"last_seen": now}, "$setOnInsert": {"value": ip, "first_seen": now}},
                upsert=True,
            )
        col.delete_many({"value": {"$nin": list(ips)}})
        col.update_one(
            {"_id": "meta"},
            {"$set": {"url": THREAT_FEED_URL, "count": len(ips), "last_sync": now, "error": ""}},
            upsert=True,
        )
    except Exception as e:  # noqa: BLE001 - persistence must never crash the refresh
        logger.warning("Threat feed snapshot persist failed: %s", e)


def _load_manual_from_db() -> set[str]:
    """Load all persisted manual IP indicators into memory at startup."""
    loaded: set[str] = set()
    try:
        from app.database import db  # noqa: PLC0415

        for doc in db.threat_indicators.find({"source": "manual", "type": "ip"}):
            value = str(doc.get("value") or "").strip()
            if value:
                loaded.add(value)
    except Exception as e:  # noqa: BLE001
        logger.warning("Failed to load manual indicators: %s", e)
    return loaded


def refresh() -> None:
    """Fetch the feed and atomically swap the feed half of the in-memory set."""
    global _feed, _last_sync, _last_error
    try:
        with urllib.request.urlopen(THREAT_FEED_URL, timeout=30) as resp:  # noqa: S310 - https feed
            data = resp.read().decode("utf-8", errors="replace")
        ips = _parse_feed(data)
        with _lock:
            _feed = ips
            _last_sync = time.time()
            _last_error = None
        _persist_snapshot(ips)
        logger.info("Threat feed refreshed from %s: %d IPs loaded", THREAT_FEED_URL, len(ips))
    except Exception as e:  # noqa: BLE001 - feed outage must never crash the API
        _last_error = str(e)
        logger.warning("Threat feed refresh failed: %s", e)


def _loop() -> None:
    while True:
        refresh()
        time.sleep(_refresh_interval)


def start_refresh_loop() -> None:
    """First sync inline (so data exists before the API answers), then daemon loop."""
    refresh()
    thread = threading.Thread(target=_loop, daemon=True, name="threat-feed")
    thread.start()


def is_malicious(ip: str) -> bool:
    if not ip:
        return False
    with _lock:
        return ip in _feed or ip in _manual


def add_ip(ip: str) -> None:
    """Add a manual IP to the in-memory set (persisted by the caller)."""
    with _lock:
        _manual.add(ip)


def remove_ip(ip: str) -> None:
    """Drop a manual IP from the in-memory set (doc deleted by the caller)."""
    with _lock:
        _manual.discard(ip)


def get_feed_ips() -> set[str]:
    with _lock:
        return set(_feed)


def get_manual_ips() -> set[str]:
    with _lock:
        return set(_manual)


def get_count() -> int:
    with _lock:
        return len(_feed) + len(_manual)


def get_feed_count() -> int:
    with _lock:
        return len(_feed)


def get_last_sync() -> str | None:
    with _lock:
        return datetime.fromtimestamp(_last_sync, tz=timezone.utc).isoformat() if _last_sync else None


def get_last_error() -> str | None:
    with _lock:
        return _last_error
