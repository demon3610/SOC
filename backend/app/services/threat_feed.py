"""Known-malicious indicator store (multi-feed).

Pulls a small set of public blocklists (no API keys required) in a background
daemon thread and caches every loaded indicator BOTH in memory (hot path for
ingest-time flagging) and in Mongo (``threat_feed_cache``) so the last good
snapshot survives restarts. Each indicator is tagged with its provenance:

    {value, category, source_feed, loaded_at}

so the Threat Intelligence page can show where every entry came from instead
of one opaque IP pile. ``is_malicious(ip)`` stays the single lookup function
the risk engine and ingest pipeline already call — this is purely additive.

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

from app.config import THREAT_FEED_REFRESH_HOURS

logger = logging.getLogger(__name__)

# Legacy label for the aggregate feed source (old /threat/indicators payloads).
FEED_SOURCE_NAME = "feeds"

FEEDS = [
    {"name": "feodotracker", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "category": "c2"},
    {"name": "urlhaus", "url": "https://urlhaus.abuse.ch/downloads/text/", "category": "malware"},
    {"name": "spamhaus_drop", "url": "https://www.spamhaus.org/drop/drop.txt", "category": "hijacked_netblock"},
    {"name": "tor_exit_nodes", "url": "https://check.torproject.org/torbulkexitlist", "category": "tor_exit"},
]

# Feed entries that are CIDR netblocks (e.g. spamhaus DROP lines like
# "1.2.3.0/24 ; SBL12345") are stored verbatim; membership checks match any
# contained address.
_feeds: dict[str, set[str]] = {}          # source_feed -> set of values (IP or CIDR)
_feed_flat: set[str] = set()              # union of all feed values — hot lookup path
_networks: dict[str, list] = {}           # source_feed -> [ip_network]
_manual: set[str] = set()
_lock = threading.Lock()
_last_sync: float | None = None
_last_error: str | None = None
_feed_sync: dict[str, float] = {}         # source_feed -> last successful sync epoch
_feed_error: dict[str, str] = {}          # source_feed -> last error
_feed_counts: dict[str, int] = {}         # source_feed -> indicator count
_refresh_interval = max(int(THREAT_FEED_REFRESH_HOURS), 1) * 3600


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_feed(text: str) -> tuple[set[str], set[str]]:
    """Extract (plain IPs, CIDR networks) from plain lists or CSV feeds.

    Tolerates comments (#), blank lines, whitespace padding, CSV columns
    (e.g. sslbl rows like ``1700000000,1.2.3.4,5.6.7.8,443,SSL-IP-Blacklist``),
    ``ip:port`` lines (urlhaus) and ``1.2.3.0/24 ; comment`` netblock rows
    (spamhaus). Only genuinely parseable, non-reserved entries are kept.
    """
    ips: set[str] = set()
    networks: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        tokens = line.replace(",", " ").split()
        for token in tokens:
            if token in (";",):
                continue
            candidate = token.split(":")[0]  # strip ip:port suffix
            try:
                if "/" in candidate:
                    net = ipaddress.ip_network(candidate, strict=False)
                    if net.is_global:
                        networks.add(str(net))
                else:
                    addr = ipaddress.ip_address(candidate)
                    if addr.is_global:
                        ips.add(str(addr))
            except ValueError:
                continue
    return ips, networks


def _persist_snapshot() -> None:
    """Write the feed snapshot to Mongo (best effort — never raises)."""
    try:
        from app.database import db  # noqa: PLC0415 - lazy import, DB may be optional

        col = db.threat_feed_cache
        now = _now_iso()
        current: set[str] = set()
        for name, values in _feeds.items():
            for value in values:
                current.add(f"{name}:{value}")
                col.update_one(
                    {"value": value, "source_feed": name},
                    {
                        "$set": {"last_seen": now, "category": _category_of(name)},
                        "$setOnInsert": {"value": value, "source_feed": name, "first_seen": now, "loaded_at": now},
                    },
                    upsert=True,
                )
        col.delete_many({"source_feed": {"$nin": list(_feeds.keys())}})
        if current:
            col.delete_many({
                "source_feed": {"$in": list(_feeds.keys())},
                "$expr": {"$not": {"$in": [{"$concat": ["$source_feed", ":", "$value"]}, list(current)]}},
            })
        col.update_one(
            {"_id": "meta"},
            {
                "$set": {
                    "count": sum(len(v) for v in _feeds.values()),
                    "feeds": {n: {"count": c, "last_sync": _feed_sync.get(n), "error": _feed_error.get(n, "")} for n, c in _feed_counts.items()},
                    "last_sync": _now_iso(),
                    "error": _last_error or "",
                }
            },
            upsert=True,
        )
    except Exception as e:  # noqa: BLE001 - persistence must never crash the refresh
        logger.warning("Threat feed snapshot persist failed: %s", e)


def _category_of(name: str) -> str:
    for f in FEEDS:
        if f["name"] == name:
            return f["category"]
    return "feed"


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
    """Fetch every feed and atomically swap the feed half of the in-memory set."""
    global _last_sync, _last_error, _feed_flat
    any_success = False
    now_epoch = time.time()
    for feed in FEEDS:
        name = feed["name"]
        try:
            with urllib.request.urlopen(feed["url"], timeout=30) as resp:  # noqa: S310 - https feeds
                data = resp.read().decode("utf-8", errors="replace")
            ips, networks = _parse_feed(data)
            with _lock:
                _feeds[name] = ips | networks
                _networks[name] = [ipaddress.ip_network(n, strict=False) for n in networks]
                _feed_counts[name] = len(ips) + len(networks)
                _feed_sync[name] = now_epoch
                _feed_error[name] = ""
                _feed_flat = {v for values in _feeds.values() for v in values}
            any_success = True
            logger.info("Threat feed %s refreshed: %d entries", name, _feed_counts[name])
        except Exception as e:  # noqa: BLE001 - feed outage must never crash the API
            with _lock:
                _feed_error[name] = str(e)
            logger.warning("Threat feed %s refresh failed: %s", name, e)
    if any_success:
        with _lock:
            _last_sync = now_epoch
            _last_error = None
        _persist_snapshot()


def _loop() -> None:
    while True:
        refresh()
        time.sleep(_refresh_interval)


def start_refresh_loop() -> None:
    """First sync inline (so data exists before the API answers), then daemon loop."""
    refresh()
    thread = threading.Thread(target=_loop, daemon=True, name="threat-feed")
    thread.start()


def _matches_networks(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for nets in _networks.values():
        for net in nets:
            if addr in net:
                return True
    return False


def is_malicious(ip: str) -> bool:
    if not ip:
        return False
    with _lock:
        if ip in _manual or ip in _feed_flat:
            return True
        if _networks:
            return _matches_networks(ip)
        return False


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
        return {v for values in _feeds.values() for v in values}


def get_manual_ips() -> set[str]:
    with _lock:
        return set(_manual)


def get_count() -> int:
    with _lock:
        return sum(len(v) for v in _feeds.values()) + len(_manual)


def get_feed_count() -> int:
    with _lock:
        return sum(len(v) for v in _feeds.values())


def get_last_sync() -> str | None:
    with _lock:
        return datetime.fromtimestamp(_last_sync, tz=timezone.utc).isoformat() if _last_sync else None


def get_last_error() -> str | None:
    with _lock:
        return _last_error


def get_feed_items() -> list[dict]:
    """Every currently-loaded feed indicator with provenance.

    Returns [{value, category, source_feed, loaded_at}] sorted by feed then
    value. The browser-facing indicator list merges these with the project's
    manual indicators.
    """
    items: list[dict] = []
    with _lock:
        for feed in FEEDS:
            name = feed["name"]
            for value in sorted(_feeds.get(name, ())):
                items.append({
                    "value": value,
                    "category": feed["category"],
                    "source_feed": name,
                    "loaded_at": datetime.fromtimestamp(_feed_sync.get(name) or 0, tz=timezone.utc).isoformat(),
                })
    return items


def get_feed_status() -> list[dict]:
    """Per-feed status for the Threat Intelligence status bar."""
    status: list[dict] = []
    with _lock:
        for feed in FEEDS:
            name = feed["name"]
            status.append({
                "name": name,
                "count": _feed_counts.get(name, 0),
                "last_sync": datetime.fromtimestamp(_feed_sync[name], tz=timezone.utc).isoformat()
                if _feed_sync.get(name) else None,
                "error": _feed_error.get(name),
            })
    return status


def get_feed_names() -> list[str]:
    return [f["name"] for f in FEEDS]