"""Threat intelligence endpoints.

Known-bad matches (``threat_match`` flag set at ingest), per-project
indicator management (feed-derived + manually added, persisted in Mongo) and
feed refresh control. All project-scoped routes go through
``get_owned_project`` so a tampered project_id cannot read another user's
data.
"""

import re

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import get_current_user
from app.database import get_db, NO_ID, all_events_collections, EVENTS_VIEW_COND
from app.dependencies import get_owned_project
from app.services import threat_feed

router = APIRouter(dependencies=[Depends(get_current_user)])

MAX_MATCHES = 200


def _ts_iso(value) -> str:
    """Normalize a stored timestamp to an ISO string."""
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _indicator_hits(project_id: int, values: list[str], db) -> dict:
    """Per-indicator event stats for this project: {value: {count, first, last}}.

    Matches against the IPs already normalized at ingest time (enriched.ip /
    parsed.ip / raw.ip) — the same fields the risk engine and event filter
    read, so no re-extraction from raw messages happens here.
    """
    if not values:
        return {}
    pid_q = {"$in": [project_id, str(project_id)]}
    or_clause = [
        {"enriched.ip": {"$in": values}},
        {"parsed.ip": {"$in": values}},
        {"raw.ip": {"$in": values}},
    ]
    base = {"project_id": pid_q, "$and": [EVENTS_VIEW_COND, {"$or": or_clause}]}
    stats: dict = {}
    for col in all_events_collections():
        for e in col.find(base, NO_ID).sort("timestamp", -1).limit(5000):
            ts = e.get("timestamp")
            ts = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
            matched_here: set[str] = set()
            for field in ("enriched", "parsed", "raw"):
                v = ((e.get(field) or {}).get("ip")) or ""
                if v in values:
                    matched_here.add(v)
            for v in matched_here:
                entry = stats.setdefault(v, {"count": 0, "first": None, "last": None})
                entry["count"] += 1
                if entry["last"] is None or ts > entry["last"]:
                    entry["last"] = ts
                if entry["first"] is None or ts < entry["first"]:
                    entry["first"] = ts
    return stats


def _events_matching(project_id: int, db) -> list[dict]:
    """Events in this project that match the current indicator list.

    Returns raw event docs (view-filtered), newest first, capped per source.
    """
    feed_ips = sorted(threat_feed.get_feed_ips())
    manual = list(db.threat_indicators.find({"project_id": project_id, "source": "manual"}, NO_ID))
    manual_ips = sorted(v for v, t in ((m.get("value"), m.get("type")) for m in manual) if t == "ip")
    manual_domains = sorted(v for v, t in ((m.get("value"), m.get("type")) for m in manual) if t == "domain")

    all_ips = feed_ips + manual_ips
    or_clause = []
    if all_ips:
        or_clause += [
            {"enriched.ip": {"$in": all_ips}},
            {"parsed.ip": {"$in": all_ips}},
            {"raw.ip": {"$in": all_ips}},
        ]
    for domain in manual_domains:
        rx = re.compile(re.escape(domain), re.IGNORECASE)
        or_clause += [
            {"raw.url": rx},
            {"raw.hostname": rx},
            {"summary": rx},
            {"raw.message": rx},
        ]
    if not or_clause:
        return []

    q = {
        "project_id": {"$in": [project_id, str(project_id)]},
        "$and": [EVENTS_VIEW_COND, {"$or": or_clause}],
    }
    docs: list[dict] = []
    for col in all_events_collections():
        docs.extend(col.find(q, NO_ID).sort("timestamp", -1).limit(MAX_MATCHES))
    docs.sort(key=lambda d: str(d.get("timestamp", "")), reverse=True)
    return docs[:MAX_MATCHES]


def _match_indicator(event: dict, manual: list[dict]) -> dict | None:
    """Pick which indicator explains a matched event (manual preferred)."""
    ip = ""
    for field in ("enriched", "parsed", "raw"):
        ip = (event.get(field) or {}).get("ip") or ""
        if ip:
            break
    if ip and threat_feed.is_malicious(ip):
        for m in manual:
            if m.get("type") == "ip" and str(m.get("value")) == ip:
                return {"value": ip, "type": "ip", "category": m.get("category", "manual"), "source": "manual"}
        return {"value": ip, "type": "ip", "category": "feed", "source": "feed"}
    hay = " ".join(
        str(v) for v in (
            (event.get("raw") or {}).get("url", ""),
            (event.get("raw") or {}).get("hostname", ""),
            event.get("summary", ""),
            (event.get("raw") or {}).get("message", ""),
        ) if v
    ).lower()
    for m in manual:
        if m.get("type") != "domain":
            continue
        if str(m.get("value")) in hay:
            return {"value": m["value"], "type": "domain", "category": m.get("category", "manual"), "source": "manual"}
    return None


def _match_to_dict(e: dict, matched: dict) -> dict:
    ts = e.get("timestamp")
    return {
        "id": e.get("id"),
        "timestamp": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
        "source": e.get("source", "unknown"),
        "event_type": e.get("event_type", "generic"),
        "summary": e.get("summary", ""),
        "ip": (e.get("enriched") or {}).get("ip", ""),
        "risk_score": (e.get("enriched") or {}).get("risk_score", 0),
        "matched": matched,
    }


@router.get("/projects/{project_id}/threat-intel/flagged")
def list_flagged_events(
    project_id: int,
    limit: int = Query(50, ge=1, le=200),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Recent events that matched a known-malicious indicator (threat_match)."""
    query = {
        "project_id": {"$in": [project_id, str(project_id)]},
        "enriched.threat_match": True,
        "$and": [EVENTS_VIEW_COND],
    }
    docs = []
    for col in all_events_collections():
        docs.extend(col.find(query, NO_ID).sort("timestamp", -1).limit(limit))
    docs.sort(key=lambda d: str(d.get("timestamp", "")), reverse=True)
    docs = docs[:limit]
    result = []
    for e in docs:
        enriched = e.get("enriched", {}) or {}
        result.append({
            "id": e.get("id"),
            "timestamp": e.get("timestamp"),
            "source": e.get("source", "unknown"),
            "event_type": e.get("event_type", "generic"),
            "summary": e.get("summary") or (e.get("raw", {}) or {}).get("message", ""),
            "ip": enriched.get("ip", ""),
            "country": (enriched.get("geo", {}) or {}).get("country", ""),
            "city": (enriched.get("geo", {}) or {}).get("city", ""),
            "risk_score": enriched.get("risk_score", 0),
            "raw": e.get("raw", {}),
        })
    return {
        "events": result,
        "total": sum(col.count_documents(query) for col in all_events_collections()),
    }


@router.get("/projects/{project_id}/threat/indicators")
def list_indicators(
    project_id: int,
    source: str = Query("all", pattern="^(all|feed|manual)$"),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Known threat indicators for a project.

    ``manual``: the project's persisted manual indicators (always returned,
    even with zero event hits). ``feed``: feed IPs that actually hit this
    project's events. ``all``: both, merged by value (manual wins).
    """
    manual_docs = list(
        db.threat_indicators.find({"project_id": project_id, "source": "manual"}, NO_ID)
        .sort("added_at", -1)
    )
    manual_map = {str(d["value"]): d for d in manual_docs}

    if source == "manual":
        manual_only = manual_docs
        feed_only: list[dict] = []
    else:
        feed_ips = threat_feed.get_feed_ips()
        hits = _indicator_hits(project_id, sorted(feed_ips), db)
        feed_only = [
            {
                "id": f"feed:{ip}",
                "value": ip,
                "type": "ip",
                "category": "feed",
                "source": "feed",
                "first_seen": h["first"],
                "last_seen": h["last"],
                "hit_count": h["count"],
            }
            for ip, h in hits.items()
        ]

    result = []
    if source in ("all", "manual"):
        hits_manual = _indicator_hits(project_id, [str(d["value"]) for d in manual_docs], db)
        for d in manual_docs:
            h = hits_manual.get(str(d["value"]), {"count": 0, "first": None, "last": None})
            result.append({
                "id": d["id"],
                "value": d["value"],
                "type": d.get("type", "ip"),
                "category": d.get("category", "manual"),
                "source": "manual",
                "notes": d.get("notes", ""),
                "added_by": d.get("added_by"),
                "added_at": d.get("added_at"),
                "first_seen": h["first"],
                "last_seen": h["last"],
                "hit_count": h["count"],
            })
    if source in ("all", "feed"):
        seen = {r["value"] for r in result}
        for item in feed_only:
            if item["value"] not in seen:
                result.append(item)

    return {
        "indicators": result,
        "total": len(result),
        "feed": {
            "source": threat_feed.FEED_SOURCE_NAME,
            "last_sync": threat_feed.get_last_sync(),
            "count": threat_feed.get_feed_count(),
            "error": threat_feed.get_last_error(),
            "project_hits": len(feed_only),
        },
        "manual_total": len(manual_docs),
    }


@router.get("/projects/{project_id}/threat/correlation")
def ip_correlation(
    project_id: int,
    limit: int = Query(500, ge=1, le=1000),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """IP × event-type correlation matrix for this project.

    Groups events by (source IP, event_type), resolved through the same
    normalized fields the risk engine and event filter read (enriched.ip →
    parsed.ip → raw.ip), so no second IP-extraction convention is introduced.
    "unknown" rows are excluded outright — a single dominant unknown bucket
    can never drown out real address data.
    """
    ip_expr = {
        "$ifNull": [
            "$enriched.ip",
            {"$ifNull": ["$parsed.ip", {"$ifNull": ["$raw.ip", "unknown"]}]},
        ]
    }
    pipeline = [
        {
            "$match": {
                "project_id": {"$in": [project_id, str(project_id)]},
                "$and": [EVENTS_VIEW_COND],
            }
        },
        {
            "$project": {
                "_ip": ip_expr,
                "event_type": {"$ifNull": ["$event_type", "generic"]},
                "timestamp": 1,
                "enriched.risk_score": 1,
            }
        },
        {"$match": {"_ip": {"$nin": ["unknown", ""]}}},
        {
            "$group": {
                "_id": {"ip": "$_ip", "event_type": "$event_type"},
                "count": {"$sum": 1},
                "avg_risk": {"$avg": "$enriched.risk_score"},
                "last_seen": {"$max": "$timestamp"},
            }
        },
        {"$sort": {"count": -1}},
        {"$limit": limit},
    ]

    rows: list[dict] = []
    for col in all_events_collections():
        for doc in col.aggregate(pipeline):
            rows.append({
                "ip": doc["_id"]["ip"],
                "event_type": doc["_id"]["event_type"],
                "count": doc["count"],
                "avg_risk": round(float(doc.get("avg_risk") or 0), 1),
                "last_seen": _ts_iso(doc["last_seen"]) if doc.get("last_seen") else "",
            })
    rows.sort(key=lambda r: r["count"], reverse=True)
    return rows[:limit]


@router.get("/projects/{project_id}/threat/matches")
def list_matches(
    project_id: int,
    limit: int = Query(MAX_MATCHES, ge=1, le=MAX_MATCHES),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Actual events in this project matching the current indicator list."""
    docs = _events_matching(project_id, db)[:limit]
    manual = list(db.threat_indicators.find({"project_id": project_id, "source": "manual"}, NO_ID))
    result = []
    for e in docs:
        matched = _match_indicator(e, manual)
        if matched:
            result.append(_match_to_dict(e, matched))
    return {"events": result, "total": len(result)}


@router.post("/projects/{project_id}/threat/refresh")
def refresh_feed(
    project_id: int,
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Re-pull the threat feed now (feed is global; manual indicators survive)."""
    threat_feed.refresh()
    return {
        "source": threat_feed.FEED_SOURCE_NAME,
        "last_sync": threat_feed.get_last_sync(),
        "count": threat_feed.get_feed_count(),
        "error": threat_feed.get_last_error(),
    }
