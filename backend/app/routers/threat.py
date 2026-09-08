"""Threat intelligence endpoints.

Known-bad matches (``threat_match`` flag set at ingest), per-project
indicator management (feed-derived + manually added, persisted in Mongo) and
feed refresh control. All project-scoped routes go through
``get_owned_project`` so a tampered project_id cannot read another user's
data.

Analyst-facing surfaces (MITRE tactics, attack timeline, correlated
narratives, top risk hosts, browsable multi-feed indicator list, false
positive feedback) live alongside the legacy match/indicator views.
"""

import ipaddress
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.auth import get_current_user
from app.database import get_db, NO_ID, all_events_collections, agent_events_collections, EVENTS_VIEW_COND
from app.dependencies import get_owned_project
from app.services import threat_feed
from app.services.elastic import _es_up, es, ELASTICSEARCH_INDEX

router = APIRouter(dependencies=[Depends(get_current_user)])

MAX_MATCHES = 200


class FeedbackBody(BaseModel):
    is_false_positive: bool = True


def _ts_iso(value) -> str:
    """Normalize a stored timestamp to an ISO string."""
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _parse_ts(v):
    if isinstance(v, datetime):
        return v
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except Exception:
            return None
    return None


def _window_start(window: str) -> datetime:
    """Start of the aggregation window for 24h / 7d / 30d."""
    now = datetime.now(timezone.utc)
    if window.endswith("d"):
        return now - timedelta(days=int(window[:-1]))
    return now - timedelta(hours=int(window[:-1]))


def _view_events_in_window(project_id: int, db, start: datetime, collections=None, projection=None):
    """Security-view events for a project since `start` (Python-side ts filter).

    Mirrors the overview router's approach: Mongo narrows by project + view
    condition, the caller filters by parsed timestamp so both ISO strings and
    datetime docs behave identically.
    """
    pid_q = {"$in": [project_id, str(project_id)]}
    cols = collections or all_events_collections()
    out = []
    for col in cols:
        for e in col.find({"project_id": pid_q, "$and": [EVENTS_VIEW_COND]}, projection or NO_ID):
            ts = _parse_ts(e.get("timestamp"))
            if ts and ts >= start:
                out.append((e, ts))
    return out


def _suppressed_values(project_id: int, db) -> set[str]:
    """Indicator values this project has marked as false positives."""
    return {
        str(d.get("value"))
        for d in db.threat_suppressions.find({"project_id": project_id, "is_false_positive": True}, {"value": 1})
    }


def _value_hits_ip(value: str, ip: str) -> bool:
    """Exact IP match or CIDR containment (feed entries may be netblocks)."""
    if value == ip:
        return True
    try:
        if "/" in value:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(value, strict=False)
    except ValueError:
        pass
    return False


def _indicator_hits(project_id: int, values: list[str], db) -> dict:
    """Per-indicator event stats for this project: {value: {count, first, last}}.

    Matches against the IPs already normalized at ingest time (enriched.ip /
    parsed.ip / raw.ip) — the same fields the risk engine and event filter
    read, so no re-extraction from raw messages happens here.
    """
    if not values:
        return {}
    suppressed = _suppressed_values(project_id, db)
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
                if v in values and v not in suppressed:
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
    suppressed = _suppressed_values(project_id, db)
    if suppressed:
        query["enriched.ip"] = {"$nin": list(suppressed)}
    docs = []
    for col in all_events_collections():
        docs.extend(col.find(query, NO_ID).sort("timestamp", -1).limit(limit))
    docs.sort(key=lambda d: str(d.get("timestamp", "")), reverse=True)
    docs = docs[:limit]
    result = []
    for e in docs:
        enriched = e.get("enriched", {}) or {}
        ip = enriched.get("ip", "")
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
        suppressed = _suppressed_values(project_id, db)
        feed_ips = [v for v in threat_feed.get_feed_ips() if v not in suppressed]
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
    """Actual events in this project matching the current indicator list.

    Events whose indicator was suppressed via the feedback endpoint are
    excluded (project-scoped; the global feed is untouched).
    """
    docs = _events_matching(project_id, db)[:limit]
    manual = list(db.threat_indicators.find({"project_id": project_id, "source": "manual"}, NO_ID))
    suppressed = _suppressed_values(project_id, db)
    result = []
    for e in docs:
        matched = _match_indicator(e, manual)
        if matched and matched.get("value") not in suppressed:
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
        "source": ", ".join(threat_feed.get_feed_names()),
        "last_sync": threat_feed.get_last_sync(),
        "count": threat_feed.get_feed_count(),
        "error": threat_feed.get_last_error(),
    }


# ---------------------------------------------------------------------------
# Analyst surfaces (Parts A–G): tactics, timeline, narratives, top hosts,
# browsable indicators, false-positive feedback
# ---------------------------------------------------------------------------


@router.get("/projects/{project_id}/threat-intel/tactics")
def threat_tactics(
    project_id: int,
    window: str = Query("24h", pattern="^(24h|7d|30d)$"),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """MITRE ATT&CK tactic counts for the window (replaces the severity donut).

    Aggregate by ``mitre.tactic`` across agent events — Credential Access vs
    Persistence vs Defense Evasion, with the concrete techniques behind each
    and a couple of example summaries. Events without a mapping are skipped.
    """
    start = _window_start(window)
    tactic_agg: dict[str, dict] = {}
    for e, _ in _view_events_in_window(project_id, db, start, agent_events_collections()):
        m = e.get("mitre") or {}
        tactic = m.get("tactic")
        technique = m.get("technique")
        if not tactic:
            continue
        bucket = tactic_agg.setdefault(tactic, {"count": 0, "techniques": Counter(), "examples": []})
        bucket["count"] += 1
        if technique:
            bucket["techniques"][technique] += 1
        if len(bucket["examples"]) < 3:
            bucket["examples"].append(e.get("summary") or (e.get("raw") or {}).get("message", "")[:160])
    return {
        "window": window,
        "tactics": [
            {
                "tactic": tactic,
                "count": agg["count"],
                "techniques": [{"technique": t, "count": c} for t, c in agg["techniques"].most_common()],
                "examples": agg["examples"],
            }
            for tactic, agg in sorted(tactic_agg.items(), key=lambda kv: kv[1]["count"], reverse=True)
        ],
    }


@router.get("/projects/{project_id}/threat-intel/timeline")
def threat_timeline(
    project_id: int,
    window: str = Query("24h", pattern="^(24h|7d|30d)$"),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Event volume + risk over time, hourly (24h) or daily (7d/30d).

    Prefers Elasticsearch's date_histogram (fast, already running) and falls
    back to a Mongo scan + Python bucketing when ES is down so the chart is
    never empty. Buckets are returned oldest-first.
    """
    start = _window_start(window)
    hourly = window == "24h"
    interval = "hour" if hourly else "day"
    pid_str = str(project_id)

    if _es_up():
        try:
            body = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"project_id": pid_str}},
                            {"range": {"timestamp": {"gte": start.isoformat()}}},
                        ]
                    }
                },
                "size": 0,
                "aggs": {
                    "hist": {
                        "date_histogram": {"field": "timestamp", "calendar_interval": interval},
                        "aggs": {
                            "avg_risk": {"avg": {"field": "enriched.risk_score"}},
                            "max_risk": {"max": {"field": "enriched.risk_score"}},
                        },
                    }
                },
            }
            resp = es.search(index=ELASTICSEARCH_INDEX, body=body)
            buckets = [
                {
                    "bucket_start": b["key_as_string"],
                    "event_count": b["doc_count"],
                    "avg_risk_score": round(float(b.get("avg_risk", {}).get("value") or 0), 1),
                    "max_risk_score": round(float(b.get("max_risk", {}).get("value") or 0), 1),
                }
                for b in resp["aggregations"]["hist"]["buckets"]
            ]
            return {"window": window, "source": "elasticsearch", "buckets": buckets}
        except Exception:
            pass  # fall through to Mongo — never show an empty timeline

    fmt = "%Y-%m-%dT%H:00:00+00:00" if hourly else "%Y-%m-%dT00:00:00+00:00"
    buckets: dict[str, dict] = {}
    for e, ts in _view_events_in_window(project_id, db, start, agent_events_collections()):
        key = ts.strftime(fmt)
        bucket = buckets.setdefault(key, {"bucket_start": key, "event_count": 0, "risk_sum": 0.0, "avg_risk_score": 0, "max_risk_score": 0})
        risk = float((e.get("enriched") or {}).get("risk_score") or 0)
        bucket["event_count"] += 1
        bucket["risk_sum"] += risk
        bucket["max_risk_score"] = max(bucket["max_risk_score"], risk)
    for key, bucket in buckets.items():
        if bucket["event_count"]:
            bucket["avg_risk_score"] = round(bucket["risk_sum"] / bucket["event_count"], 1)
        else:
            bucket["avg_risk_score"] = 0
        bucket.pop("risk_sum", None)
    return {
        "window": window,
        "source": "mongo",
        "buckets": [buckets[k] for k in sorted(buckets.keys())],
    }


@router.get("/projects/{project_id}/threat-intel/narratives")
def threat_narratives(
    project_id: int,
    hours: int = Query(24, ge=1, le=168),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Rule-based correlated attack narratives (kill-chain view).

    Groups recent security events by hostname; where 3+ events from the same
    host fall within a sliding 2h window AND show escalation (2+ distinct
    MITRE tactics, or a high/critical severity, or risk >= 70), the run is
    returned as one ordered chain the UI can render as a story.
    """
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    CHAIN_GAP = timedelta(hours=2)
    by_host: dict[str, list] = {}
    for e, ts in _view_events_in_window(project_id, db, start, agent_events_collections()):
        host = e.get("hostname") or (e.get("raw") or {}).get("hostname") or ""
        if not host:
            continue
        m = e.get("mitre") or {}
        by_host.setdefault(host, []).append({
            "ts": ts,
            "tactic": m.get("tactic"),
            "technique": m.get("technique"),
            "summary": e.get("summary") or (e.get("raw") or {}).get("message", ""),
            "event_type": e.get("event_type", "info"),
            "risk_score": float((e.get("enriched") or {}).get("risk_score") or 0),
            "id": e.get("id"),
        })

    narratives = []
    for host, steps in by_host.items():
        steps.sort(key=lambda s: s["ts"])
        run: list[dict] = []
        for step in steps:
            if run and step["ts"] - run[-1]["ts"] > CHAIN_GAP:
                if _is_chain(run):
                    narratives.append(_chain_to_dict(host, run))
                run = []
            run.append(step)
        if _is_chain(run):
            narratives.append(_chain_to_dict(host, run))

    narratives.sort(key=lambda n: n["start_time"], reverse=True)
    return {"hours": hours, "narratives": narratives}


def _is_chain(steps: list[dict]) -> bool:
    """3+ steps from one host with escalating or notable tactics."""
    if len(steps) < 3:
        return False
    tactics = {s["tactic"] for s in steps if s["tactic"]}
    if len(tactics) >= 2:
        return True
    if any(s["event_type"] in ("high", "critical") for s in steps):
        return True
    return any(s["risk_score"] >= 70 for s in steps)


def _chain_to_dict(host: str, run: list[dict]) -> dict:
    return {
        "hostname": host,
        "start_time": run[0]["ts"].isoformat(),
        "end_time": run[-1]["ts"].isoformat(),
        "event_count": len(run),
        "chain": [
            {
                "time": s["ts"].isoformat(),
                "tactic": s["tactic"],
                "technique": s["technique"],
                "summary": s["summary"],
                "event_type": s["event_type"],
                "event_id": s["id"],
            }
            for s in run
        ],
    }


@router.get("/projects/{project_id}/threat-intel/top-hosts")
def threat_top_hosts(
    project_id: int,
    window: str = Query("24h", pattern="^(24h|7d|30d)$"),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Ranked per-host risk accumulation for the window (works today, no IP).

    SUM(risk_score) + COUNT + last-seen grouped by hostname across agent
    events — hostname is populated by every agent entry, so this is the
    page's primary "where do I look first" triage list even before IP
    enrichment lands.
    """
    start = _window_start(window)
    hosts: dict[str, dict] = {}
    for e, ts in _view_events_in_window(project_id, db, start, agent_events_collections()):
        host = e.get("hostname") or (e.get("raw") or {}).get("hostname") or ""
        if not host:
            continue
        entry = hosts.setdefault(host, {"risk_total": 0, "event_count": 0, "last_seen": None})
        entry["risk_total"] += float((e.get("enriched") or {}).get("risk_score") or 0)
        entry["event_count"] += 1
        if entry["last_seen"] is None or ts > _parse_ts(entry["last_seen"]):
            entry["last_seen"] = ts.isoformat()
    ranked = [
        {
            "hostname": host,
            "risk_total": round(v["risk_total"], 1),
            "event_count": v["event_count"],
            "last_seen": v["last_seen"],
        }
        for host, v in hosts.items()
    ]
    ranked.sort(key=lambda h: h["risk_total"], reverse=True)
    return {"window": window, "hosts": ranked[:100]}


@router.get("/projects/{project_id}/threat-intel/indicators")
def list_feed_indicators(
    project_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    source_feed: str | None = Query(None),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Browsable list of every currently-loaded indicator with provenance.

    Global feed entries (Part D, tagged with source_feed) plus this project's
    manual indicators (source_feed="manual"), filterable by source_feed and
    paginated. Unlike /threat/indicators this shows ALL loaded indicators, not
    just the ones that hit this project's events.
    """
    items: list[dict] = []
    for item in threat_feed.get_feed_items():
        items.append({
            "value": item["value"],
            "category": item["category"],
            "source_feed": item["source_feed"],
            "loaded_at": item["loaded_at"],
        })
    for d in db.threat_indicators.find({"project_id": project_id, "source": "manual"}, NO_ID).sort("added_at", -1):
        items.append({
            "value": str(d.get("value", "")),
            "category": d.get("category", "manual"),
            "source_feed": "manual",
            "loaded_at": d.get("added_at"),
        })
    if source_feed:
        items = [i for i in items if i["source_feed"] == source_feed]
    items.sort(key=lambda i: (i["loaded_at"] or ""), reverse=True)
    total = len(items)
    start = (page - 1) * page_size
    return {
        "indicators": items[start:start + page_size],
        "total": total,
        "page": page,
        "page_size": page_size,
        "source_feed": source_feed,
        "feeds": threat_feed.get_feed_status(),
        "last_sync": threat_feed.get_last_sync(),
        "error": threat_feed.get_last_error(),
    }


@router.post("/projects/{project_id}/threat-intel/matches/{match_id}/feedback")
def match_feedback(
    project_id: int,
    match_id: str,
    body: FeedbackBody,
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Mark a matched indicator as a false positive for THIS project.

    The indicator value (resolved from the event that produced the match) is
    stored in the project-scoped suppression list; future matches against it
    are excluded from Known Threat IPs, Matched Events and flagged events for
    this project only. The global feed and other projects are untouched.
    """
    event = None
    for col in all_events_collections():
        event = col.find_one({"id": match_id}, NO_ID)
        if event:
            break
    if not event:
        raise HTTPException(status_code=404, detail="Match not found")
    matched = _match_indicator(event, list(db.threat_indicators.find({"project_id": project_id, "source": "manual"}, NO_ID)))
    if not matched:
        raise HTTPException(status_code=404, detail="No indicator match found for this event")
    value = matched["value"]
    db.threat_suppressions.update_one(
        {"project_id": project_id, "value": value},
        {"$set": {"is_false_positive": body.is_false_positive, "updated_at": datetime.now(timezone.utc).isoformat()},
         "$setOnInsert": {"created_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True,
    )
    return {"status": "ok", "value": value, "suppressed": body.is_false_positive}
