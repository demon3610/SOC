from collections import Counter
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from app.database import get_db, NO_ID, all_events_collections, agent_events_collections, EVENTS_VIEW_COND
from app.auth import get_current_user
from app.services.elastic import _es_up

router = APIRouter(dependencies=[Depends(get_current_user)])


def _check_project(project_id: int, user, db):
    project = db.projects.find_one({"id": project_id}, NO_ID)
    if not project or project["owner_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Project not found")


def _parse_ts(v):
    if isinstance(v, datetime):
        return v
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except Exception:
            return None
    return None


@router.get("/projects/{project_id}/overview", summary="Dashboard overview stats for a project")
def project_overview(
    project_id: int,
    hours: int = Query(24),
    user=Depends(get_current_user),
    db=Depends(get_db),
):
    _check_project(project_id, user, db)
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    pid_q = {"$in": [project_id, str(project_id)]}

    events = []
    for col in all_events_collections():
        events.extend(col.find(
            {"project_id": pid_q, "$and": [EVENTS_VIEW_COND]},
            {"timestamp": 1, "event_type": 1, "source": 1, "enriched.ip": 1, "summary": 1, "raw.hostname": 1},
        ))

    in_range = []
    for e in events:
        ts = _parse_ts(e.get("timestamp"))
        if ts and ts >= start:
            in_range.append((e, ts))
    in_range.sort(key=lambda x: x[1], reverse=True)

    event_count = len(in_range)
    alert_count = sum(1 for e, _ in in_range if e.get("event_type") in ("critical", "high"))

    top_ips = Counter()
    top_types = Counter()
    for e, _ in in_range:
        ip = (e.get("enriched") or {}).get("ip")
        if ip:
            top_ips[ip] += 1
        top_types[e.get("event_type", "unknown")] += 1

    if hours <= 48:
        fmt = "%Y-%m-%d %H:00"
    else:
        fmt = "%Y-%m-%d"
    buckets = {}
    for _, ts in in_range:
        key = ts.strftime(fmt)
        buckets[key] = buckets.get(key, 0) + 1
    chart = [{"date": k, "count": buckets[k]} for k in sorted(buckets.keys())]

    last_event_ts = max((ts for _, ts in in_range), default=None)
    last_heartbeat = None
    for col in agent_events_collections():
        hb = col.find_one(
            {"category": "heartbeat"}, {"timestamp": 1},
            sort=[("timestamp", -1)],
        )
        if hb and (last_heartbeat is None or str(hb.get("timestamp", "")) > str(last_heartbeat.get("timestamp", ""))):
            last_heartbeat = hb
    last_heartbeat_ts = _parse_ts(last_heartbeat.get("timestamp")) if last_heartbeat else None

    es_up = bool(_es_up())
    if event_count > 0 and es_up:
        health = "healthy"
    elif event_count > 0:
        health = "degraded"
    else:
        health = "no_data"

    agents = []
    for k in db.agent_keys.find({"project_id": pid_q}, {"_id": 0, "key_hash": 0}):
        last = _parse_ts(k.get("last_seen_at"))
        agents.append({
            "id": k.get("id"),
            "label": k.get("label"),
            "hostname": k.get("hostname"),
            "os_type": k.get("os_type"),
            "ip_address": k.get("ip_address"),
            "status": k.get("status"),
            "last_seen_at": last.isoformat() if last else None,
        })

    open_incidents = db.incidents.count_documents({"project_id": project_id, "status": {"$ne": "resolved"}})

    return {
        "hours": hours,
        "events_in_range": event_count,
        "alerts_in_range": alert_count,
        "open_incidents": open_incidents,
        "ingest_health": {
            "status": health,
            "elasticsearch_up": es_up,
            "last_event_at": last_event_ts.isoformat() if last_event_ts else None,
            "last_heartbeat_at": last_heartbeat_ts.isoformat() if last_heartbeat_ts else None,
        },
        "top_source_ips": [{"ip": ip, "count": c} for ip, c in top_ips.most_common(5)],
        "top_event_types": [{"event_type": t, "count": c} for t, c in top_types.most_common(5)],
        "severity_distribution": {t: c for t, c in top_types.items()},
        "chart": chart,
        "agents": agents,
        "total_events": len(events),
    }
