import io
import json
import zipfile
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field

from app.auth import get_current_user
from app.database import (
    EVENTS_VIEW_COND,
    NO_ID,
    agent_events_collections,
    all_events_collections,
    get_db,
    get_next_id,
    get_next_id_batch,
)
from app.dependencies import get_owned_incident, get_owned_project
from app.models.incident import IncidentCreate, IncidentResponse, IncidentUpdate
from app.services.audit import list_incident_activity, log_incident_action
from app.services.incident_metrics import (
    event_hostname,
    evidence_metrics,
    linked_entities,
    mitigation_suggestions,
    mitre_tags_from_evidence,
    parse_snapshot,
    primary_ip_from_evidence,
    technique_suggestions,
)
from app.services.pdf_report import render_incident_pdf

router = APIRouter(dependencies=[Depends(get_current_user)])

INCIDENT_STATUSES = ("open", "investigating", "contained", "resolved", "false_positive")
INCIDENT_SEVERITIES = ("critical", "high", "medium", "low")
CLOSING_STATUSES = ("resolved", "false_positive")
_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_EVIDENCE_SOURCES = ("live_events", "correlated_chain", "manual")

# Chain-attach guards: per-collection scan cap + max attached docs per call
# so a wide window on a busy host can't stall the worker or flood evidence.
CHAIN_ATTACH_SCAN_CAP = 2000
CHAIN_ATTACH_MAX = 500


class MitigationAddBody(BaseModel):
    text: str = Field(min_length=1, max_length=500)
    suggested: bool = False


class MitigationToggleBody(BaseModel):
    done: bool


class ChainEvidenceBody(BaseModel):
    hostname: str
    start_time: str
    end_time: str


class BulkReportBody(BaseModel):
    incident_ids: list[int]


class ResolveBody(BaseModel):
    resolution_note: str = Field(min_length=1, max_length=2000)


class BulkUpdateBody(BaseModel):
    incident_ids: list[int] = Field(min_length=1, max_length=100)
    status: str | None = None
    assigned_to: int | None = None
    resolution_note: str | None = None


def _auto_title(title: str | None, context) -> str:
    """Sane default title when the analyst leaves it blank/garbage.

    ``"<Technique> on <host>"`` (e.g. "Brute force attempt on WIN-DESKTOP-1"),
    falling back to the event summary, then a generic label. Titles of 3+
    characters pass through untouched.
    """
    title = (title or "").strip()
    if len(title) >= 3:
        return title
    ctx = context or {}
    if not isinstance(ctx, dict):
        ctx = ctx.model_dump() if hasattr(ctx, "model_dump") else {}
    host = (ctx.get("hostname") or "").strip()
    technique = (ctx.get("technique") or "").strip()
    if technique:
        # "T1110 - Brute Force" -> "Brute force"; bare "T1110" stays as-is.
        name = technique.split("-", 1)[-1].strip() if "-" in technique else technique.strip()
        name = name[0].upper() + name[1:] if name else technique
        if host:
            return f"{name} on {host}"
        return name
    summary = (ctx.get("event_summary") or "").strip()
    if summary:
        return (summary[:80] + "…") if len(summary) > 80 else summary
    if host:
        return f"Investigation on {host}"
    return "Untitled investigation"


def _evidence_docs(db, incident_id: int) -> list[dict]:
    return list(db.incident_evidence.find({"incident_id": incident_id}, {"_id": 0}).sort("added_at", -1))


def _mitigation_list(incident: dict) -> list:
    mitigation = incident.get("mitigation")
    if isinstance(mitigation, list):
        return mitigation
    return []  # legacy free-text mitigation is replaced by the checklist model


def _dto(incident: dict, evidence: list[dict]) -> IncidentResponse:
    """Incident response with derived fields (mitre tags, primary IP, links)."""
    linked = linked_entities(evidence)
    created = incident.get("created_at")
    updated = incident.get("updated_at")
    return IncidentResponse(
        id=incident["id"], project_id=incident["project_id"], title=incident["title"],
        description=incident.get("description"), mitigation=_mitigation_list(incident),
        severity=incident["severity"], status=incident["status"], assigned_to=incident.get("assigned_to"),
        created_at=created, updated_at=updated,
        evidence_count=len(evidence), notes=incident.get("notes", []),
        tags=incident.get("tags", []),
        resolved_at=incident.get("resolved_at"),
        resolution_note=incident.get("resolution_note"),
        **evidence_metrics(evidence),
        **linked,
        mitre_tags=mitre_tags_from_evidence(evidence),
        primary_ip=primary_ip_from_evidence(evidence),
    )


def _incident_of_project(db, project_id: int, incident_id: int) -> dict:
    """Owned-incident lookup keyed by both ids (404 without leaking)."""
    inc = db.incidents.find_one({"id": incident_id, "project_id": project_id}, NO_ID)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


def _parse_dt(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid timestamp: {value}") from None


def _user_name(user) -> str:
    return user.get("name") or user.get("email") or user.get("username") or f"User #{user['id']}"


def _report_bytes(db, incident: dict, user) -> tuple[bytes, str]:
    """Render one report (PDF bytes + preferred filename)."""
    evidence = _evidence_docs(db, incident["id"])
    activity = list_incident_activity(db, incident["id"])

    # Resolve author / completed-by ids to names for the human-readable
    # sections (activity rows already carry user_name from the audit helper).
    users = {u["id"]: (u.get("name") or u.get("email") or "") for u in db.users.find({}, NO_ID)}
    incident_view = dict(incident)
    notes = []
    for n in incident_view.get("notes") or []:
        notes.append({**n, "author": users.get(n.get("added_by")) or f"User #{n.get('added_by')}"})
    incident_view["notes"] = notes
    mitigation = []
    for item in _mitigation_list(incident_view):
        completed_by = item.get("completed_by")
        mitigation.append({
            **item,
            "completed_by_name": users.get(completed_by) if completed_by is not None else None,
        })
    incident_view["mitigation"] = mitigation

    pdf = render_incident_pdf(
        incident_view,
        evidence,
        activity,
        generated_by=_user_name(user),
    )
    return pdf, f"incident-report-{incident['id']}.pdf"


@router.get("/projects/{project_id}/incidents", summary="List a project's incidents")
def list_incidents(
    project=Depends(get_owned_project), db=Depends(get_db),
    status: str | None = Query(None),
    severity: str | None = Query(None),
    assigned_to: int | None = Query(None),
    technique_id: str | None = Query(None),
    host: str | None = Query(None),
    tag: str | None = Query(None),
    sort: str = Query("severity", pattern="^(severity|created_at|updated_at|aging)$"),
):
    """List with filters (status, severity, assignee, technique, host, tag).

    Default sort is severity-rank first (most urgent first), then most
    recently updated. ``aging`` sorts oldest unresolved first (SLA risk).
    """
    project_id = project["id"]
    q: dict = {"project_id": project_id}
    if status:
        q["status"] = status
    if severity:
        q["severity"] = severity
    if assigned_to is not None:
        q["assigned_to"] = assigned_to
    if tag:
        q["tags"] = tag
    incidents = list(db.incidents.find(q, NO_ID))
    result = []
    for inc in incidents:
        evidence = _evidence_docs(db, inc["id"])
        dto = _dto(inc, evidence)
        if technique_id:
            tid = technique_id.strip().upper()
            if not any(t == tid or t.startswith(tid) for t in dto.technique_ids):
                continue
        if host and host not in dto.hosts:
            continue
        result.append(dto)
    if sort == "created_at":
        result.sort(key=lambda d: str(d.created_at), reverse=True)
    elif sort == "updated_at":
        result.sort(key=lambda d: str(d.updated_at), reverse=True)
    elif sort == "aging":
        result.sort(key=lambda d: str(d.created_at))
    else:
        result.sort(
            key=lambda d: (_SEV_RANK.get(d.severity, 0), str(d.updated_at)),
            reverse=True,
        )
    return result


@router.post("/projects/{project_id}/incidents", summary="Create an incident from an event")
def create_incident(body: IncidentCreate, user=Depends(get_current_user),
                    project=Depends(get_owned_project), db=Depends(get_db)):
    project_id = project["id"]
    if body.severity not in INCIDENT_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"Invalid severity; expected one of {', '.join(INCIDENT_SEVERITIES)}")
    now = datetime.now(timezone.utc)
    title = _auto_title(body.title, body.context)
    incident = {
        "id": get_next_id("incidents"),
        "project_id": project_id,
        "title": title,
        "description": body.description,
        "severity": body.severity,
        "status": "open",
        "assigned_to": None,
        "tags": [],
        "mitigation": [],
        "resolved_at": None,
        "resolution_note": None,
        "created_at": now,
        "updated_at": now,
    }
    db.incidents.insert_one(incident)
    log_incident_action(db, user, project_id, incident["id"], "created", f'"{title}"')
    return _dto(incident, [])


@router.get("/incidents/{incident_id}", summary="Get one incident")
def get_incident(incident=Depends(get_owned_incident), db=Depends(get_db)):
    incident_id = incident["id"]
    evidence = _evidence_docs(db, incident_id)
    return _dto(incident, evidence)


@router.patch("/incidents/{incident_id}", summary="Update an incident (status/severity/assignee/tags)")
def update_incident(body: IncidentUpdate, user=Depends(get_current_user),
                    incident=Depends(get_owned_incident), db=Depends(get_db)):
    incident_id = incident["id"]
    update = {k: v for k, v in body.model_dump(exclude_none=True).items() if v is not None}
    if "status" in update and update["status"] not in INCIDENT_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status; expected one of {', '.join(INCIDENT_STATUSES)}")
    if "severity" in update and update["severity"] not in INCIDENT_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"Invalid severity; expected one of {', '.join(INCIDENT_SEVERITIES)}")
    if "title" in update:
        update["title"] = (update["title"] or "").strip()
        if len(update["title"]) < 3:
            raise HTTPException(status_code=400, detail="Title must be at least 3 characters")
    if "tags" in update:
        update["tags"] = sorted({str(t).strip() for t in (update["tags"] or []) if str(t).strip()})
    if "assigned_to" in update and update["assigned_to"] is not None:
        if db.users.find_one({"id": update["assigned_to"]}, {"id": 1}) is None:
            raise HTTPException(status_code=400, detail=f"Assignee user #{update['assigned_to']} does not exist")

    # Closing an incident requires a resolution note — no silent closes.
    if update.get("status") in CLOSING_STATUSES and incident.get("status") not in CLOSING_STATUSES:
        note = (update.get("resolution_note") or incident.get("resolution_note") or "").strip()
        if not note:
            raise HTTPException(status_code=400, detail="A resolution note is required to resolve or dismiss an incident")
        update["resolution_note"] = note
        update["resolved_at"] = datetime.now(timezone.utc)
    if update.get("status") not in CLOSING_STATUSES and "status" in update:
        update["resolved_at"] = None
        update["resolution_note"] = None

    update["updated_at"] = datetime.now(timezone.utc)

    for field, action in (
        ("status", "status_changed"),
        ("severity", "severity_changed"),
        ("assigned_to", "assignee_changed"),
        ("title", "title_changed"),
        ("tags", "tags_changed"),
    ):
        if field in update and update[field] != incident.get(field):
            old = incident.get(field)
            log_incident_action(
                db, user, incident["project_id"], incident_id, action,
                f"{old if old not in (None, '') else 'unset'} → {update[field] if update[field] not in (None, '') else 'unset'}",
                from_value="" if old is None else str(old),
                to_value="" if update[field] is None else str(update[field]),
            )
    if "resolution_note" in update and update["resolution_note"] != incident.get("resolution_note"):
        log_incident_action(
            db, user, incident["project_id"], incident_id, "resolution_noted",
            (update["resolution_note"] or "")[:200],
        )

    db.incidents.update_one({"id": incident_id}, {"$set": update})
    incident = db.incidents.find_one({"id": incident_id}, NO_ID)
    evidence = _evidence_docs(db, incident_id)
    return _dto(incident, evidence)


@router.post("/incidents/{incident_id}/resolve", summary="Resolve/close an incident (resolution note required)")
def resolve_incident(body: ResolveBody, user=Depends(get_current_user),
                     incident=Depends(get_owned_incident), db=Depends(get_db)):
    """Dedicated close flow: sets status + resolved_at behind a required note."""
    incident_id = incident["id"]
    note = (body.resolution_note or "").strip()
    if not note:
        raise HTTPException(status_code=400, detail="resolution_note is required")
    now = datetime.now(timezone.utc)
    db.incidents.update_one(
        {"id": incident_id},
        {"$set": {
            "status": "resolved", "resolution_note": note,
            "resolved_at": now, "updated_at": now,
        }},
    )
    log_incident_action(
        db, user, incident["project_id"], incident_id, "status_changed",
        f"{incident.get('status') or 'unset'} → resolved",
        from_value=str(incident.get("status") or ""),
        to_value="resolved",
    )
    log_incident_action(db, user, incident["project_id"], incident_id, "resolution_noted", note[:200])
    refreshed = db.incidents.find_one({"id": incident_id}, NO_ID)
    return _dto(refreshed, _evidence_docs(db, incident_id))


@router.get("/incidents/{incident_id}/related", summary="Related incidents sharing hosts, IPs, users or techniques")
def related_incidents(incident=Depends(get_owned_incident), db=Depends(get_db)):
    """Cheapest useful correlation: other incidents in the project with any
    linked entity (host, IP, user, technique) in common."""
    incident_id = incident["id"]
    project_id = incident["project_id"]
    mine = linked_entities(_evidence_docs(db, incident_id))
    mine_sets = {k: set(v) for k, v in mine.items()}
    related = []
    for other in db.incidents.find({"project_id": project_id, "id": {"$ne": incident_id}}, NO_ID):
        theirs = linked_entities(_evidence_docs(db, other["id"]))
        shared: dict[str, list[str]] = {}
        for key in ("hosts", "ips", "users", "technique_ids"):
            overlap = sorted(mine_sets[key] & set(theirs.get(key, [])))
            if overlap:
                shared[key] = overlap
        if not shared:
            continue
        related.append({
            "id": other["id"],
            "title": other.get("title", ""),
            "severity": other.get("severity", "medium"),
            "status": other.get("status", "open"),
            "shared": shared,
            "shared_count": sum(len(v) for v in shared.values()),
        })
    related.sort(key=lambda r: (r["shared_count"], r["id"]), reverse=True)
    return {"incident_id": incident_id, "related": related[:20], "total": len(related)}


@router.post("/projects/{project_id}/incidents/bulk", summary="Bulk assign / change status on incidents")
def bulk_update_incidents(body: BulkUpdateBody, user=Depends(get_current_user),
                          project=Depends(get_owned_project), db=Depends(get_db)):
    """Triage many low-priority items at once. Every incident gets its own
    activity entries; unknown/foreign ids reject the whole request."""
    project_id = project["id"]
    if body.status is not None and body.status not in INCIDENT_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status; expected one of {', '.join(INCIDENT_STATUSES)}")
    if body.status is None and body.assigned_to is None:
        raise HTTPException(status_code=400, detail="Nothing to update: provide status and/or assigned_to")
    if body.assigned_to is not None and db.users.find_one({"id": body.assigned_to}, {"id": 1}) is None:
        raise HTTPException(status_code=400, detail=f"Assignee user #{body.assigned_to} does not exist")
    if body.status in CLOSING_STATUSES and not (body.resolution_note or "").strip():
        raise HTTPException(status_code=400, detail="A resolution_note is required to bulk-close incidents")
    ids = sorted(set(body.incident_ids))
    found = {d["id"]: d for d in db.incidents.find({"project_id": project_id, "id": {"$in": ids}}, NO_ID)}
    missing = [i for i in ids if i not in found]
    if missing:
        raise HTTPException(status_code=400, detail=f"Incidents not in this project: {missing}")
    now = datetime.now(timezone.utc)
    updated = 0
    for iid in ids:
        inc = found[iid]
        update: dict = {"updated_at": now}
        if body.status is not None and body.status != inc.get("status"):
            update["status"] = body.status
            if body.status in CLOSING_STATUSES:
                update["resolution_note"] = (body.resolution_note or "").strip()
                update["resolved_at"] = now
            elif "status" in update:
                update["resolved_at"] = None
                update["resolution_note"] = None
            log_incident_action(
                db, user, project_id, iid, "status_changed",
                f"{inc.get('status') or 'unset'} → {body.status} (bulk)",
                from_value=str(inc.get("status") or ""), to_value=body.status,
            )
        if body.assigned_to is not None and body.assigned_to != inc.get("assigned_to"):
            update["assigned_to"] = body.assigned_to
            log_incident_action(
                db, user, project_id, iid, "assignee_changed",
                f"{inc.get('assigned_to') if inc.get('assigned_to') is not None else 'unassigned'} → {body.assigned_to} (bulk)",
                from_value="" if inc.get("assigned_to") is None else str(inc.get("assigned_to")),
                to_value=str(body.assigned_to),
            )
        if len(update) > 1:
            db.incidents.update_one({"id": iid}, {"$set": update})
            updated += 1
    return {"status": "ok", "updated": updated, "total": len(ids)}


@router.post("/incidents/{incident_id}/notes", summary="Add a note to an incident")
def add_note(body: dict, user=Depends(get_current_user), incident=Depends(get_owned_incident), db=Depends(get_db)):
    incident_id = incident["id"]
    text = str(body.get("text") or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="Note text is required")
    if len(text) > 2000:
        raise HTTPException(status_code=400, detail="Note text too long (max 2000 characters)")
    reply_to = body.get("reply_to")
    if reply_to is not None:
        try:
            reply_to = int(reply_to)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid reply_to note id")
        existing = [n.get("id") for n in incident.get("notes") or []]
        if reply_to not in existing:
            raise HTTPException(status_code=400, detail="Replied-to note not found on this incident")
    note = {
        "id": get_next_id("incident_notes"),
        "text": text,
        "added_by": user["id"],
        "added_at": datetime.now(timezone.utc),
        "reply_to": reply_to,
    }
    db.incidents.update_one(
        {"id": incident_id},
        {"$push": {"notes": note}, "$set": {"updated_at": datetime.now(timezone.utc)}},
    )
    log_incident_action(
        db, user, incident["project_id"], incident_id,
        "note_added", text[:200] + ("…" if len(text) > 200 else ""),
    )
    return note


@router.get("/incidents/{incident_id}/evidence", summary="List evidence snapshots for an incident")
def list_evidence(incident=Depends(get_owned_incident), db=Depends(get_db)):
    incident_id = incident["id"]
    return list(db.incident_evidence.find({"incident_id": incident_id}, {"_id": 0}).sort("added_at", -1))


@router.post("/incidents/{incident_id}/evidence", summary="Attach an event snapshot to an incident")
def add_evidence(body: dict, user=Depends(get_current_user), incident=Depends(get_owned_incident), db=Depends(get_db)):
    incident_id = incident["id"]
    source_event_id = body.get("source_event_id")
    if not source_event_id:
        raise HTTPException(status_code=400, detail="source_event_id is required")
    source = str(body.get("source") or "live_events")
    if source not in _EVIDENCE_SOURCES:
        raise HTTPException(status_code=400, detail=f"Invalid source; expected one of {', '.join(_EVIDENCE_SOURCES)}")
    # Resolve the event server-side inside this project: the client snapshot
    # is never trusted (cross-tenant forgery, oversized docs). Website events
    # (no category) and int/str project_id variants all resolve here.
    pid_q = {"$in": [incident["project_id"], str(incident["project_id"])]}
    event_doc = None
    for col in all_events_collections():
        event_doc = col.find_one({"id": source_event_id, "project_id": pid_q}, NO_ID)
        if event_doc:
            break
    if event_doc is None:
        raise HTTPException(status_code=404, detail="Event not found in this project")
    ev = {
        "id": get_next_id("incident_evidence"),
        "incident_id": incident_id,
        "event_snapshot": json.dumps(event_doc, default=str),
        "source_event_id": source_event_id,
        "source": source,
        "added_by": user["id"],
        "added_at": datetime.now(timezone.utc),
    }
    db.incident_evidence.insert_one(ev)
    db.incidents.update_one({"id": incident_id}, {"$set": {"updated_at": datetime.now(timezone.utc)}})
    snap = parse_snapshot(ev)
    host = event_hostname(snap)
    detail = str(body.get("source_event_id", ""))
    if host:
        detail += f" on {host}"
    log_incident_action(db, user, incident["project_id"], incident_id, "evidence_attached", detail)
    return {k: v for k, v in ev.items() if k != "_id"}


@router.post("/incidents/{incident_id}/evidence/chain", summary="Attach an entire correlated chain as evidence")
def attach_chain_evidence(body: ChainEvidenceBody, user=Depends(get_current_user),
                          incident=Depends(get_owned_incident), db=Depends(get_db)):
    """Re-query the narrative's events (hostname × time window) and attach ALL
    of them in one batch, with a single activity entry for the bulk action."""
    incident_id = incident["id"]
    start = _parse_dt(body.start_time)
    end = _parse_dt(body.end_time)
    if end < start:
        raise HTTPException(status_code=400, detail="end_time must not precede start_time")
    if (end - start) > timedelta(hours=72):
        raise HTTPException(status_code=400, detail="Chain window too wide (max 72h)")

    host = (body.hostname or "").strip()
    if not host:
        raise HTTPException(status_code=400, detail="hostname is required")

    pid_q = {"$in": [incident["project_id"], str(incident["project_id"])]}
    matches = []
    for col in agent_events_collections():
        # Bound the scan per collection; timestamps stay mixed-format
        # strings so the window clips in Python, but Mongo does the coarse
        # narrowing first.
        for e in col.find(
            {"project_id": pid_q, "$and": [EVENTS_VIEW_COND, {"$or": [
                {"hostname": host},
                {"raw.hostname": host},
            ]}]},
            NO_ID,
        ).sort([("timestamp", -1), ("_id", -1)]).limit(CHAIN_ATTACH_SCAN_CAP):
            ts = e.get("timestamp")
            if hasattr(ts, "isoformat"):
                ts_dt = ts
            else:
                try:
                    ts_dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                except ValueError:
                    continue
            if start <= ts_dt <= end:
                matches.append((e, ts_dt))
                if len(matches) >= CHAIN_ATTACH_MAX:
                    break
        if len(matches) >= CHAIN_ATTACH_MAX:
            break

    if not matches:
        raise HTTPException(status_code=404, detail=f"No events found for chain on {host}")

    matches.sort(key=lambda m: m[1])
    now = datetime.now(timezone.utc)
    ids = get_next_id_batch("incident_evidence", len(matches))
    docs = [
        {
            "id": ids[i],
            "incident_id": incident_id,
            "event_snapshot": json.dumps(e, default=str),
            "source_event_id": e.get("id") or str(ids[i]),
            "source": "correlated_chain",
            "added_by": user["id"],
            "added_at": now,
            "chain": {"hostname": host, "start_time": str(start), "end_time": str(end)},
        }
        for i, (e, _) in enumerate(matches)
    ]
    db.incident_evidence.insert_many(docs)
    db.incidents.update_one({"id": incident_id}, {"$set": {"updated_at": now}})
    log_incident_action(
        db, user, incident["project_id"], incident_id,
        "evidence_attached",
        f"{len(docs)} events from chain on {host}",
    )
    return {"attached": len(docs), "evidence": [{k: v for k, v in d.items() if k != "_id"} for d in docs]}


@router.get("/incidents/{incident_id}/activity", summary="Chronological activity log for an incident")
def incident_activity(incident=Depends(get_owned_incident), db=Depends(get_db)):
    return list_incident_activity(db, incident["id"])


# ---------------------------------------------------------------------------
# PDF reports (Part A) — single and bulk-as-zip, both behind ownership checks
# ---------------------------------------------------------------------------

@router.post("/projects/{project_id}/incidents/reports/bulk",
             summary="Generate a zip of PDF reports for selected incidents")
def bulk_incident_reports(body: BulkReportBody, user=Depends(get_current_user),
                          project=Depends(get_owned_project), db=Depends(get_db)):
    """One PDF per incident id, bundled as a zip.

    Every id is validated against this project before any PDF is generated —
    a foreign id anywhere in the list rejects the WHOLE request rather than
    silently succeeding for the rest.
    """
    project_id = project["id"]
    ids = body.incident_ids
    if not ids:
        raise HTTPException(status_code=400, detail="incident_ids must not be empty")
    if len(ids) > 100:
        raise HTTPException(status_code=400, detail="Too many incidents (max 100 per bulk export)")

    incidents = []
    for incident_id in sorted(set(ids)):
        inc = db.incidents.find_one({"id": incident_id, "project_id": project_id}, NO_ID)
        if not inc:
            raise HTTPException(
                status_code=400,
                detail=f"Incident {incident_id} does not belong to this project — request rejected",
            )
        incidents.append(inc)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for inc in incidents:
            pdf, filename = _report_bytes(db, inc, user)
            zf.writestr(filename, pdf)
    buf.seek(0)
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="incident-reports-{project_id}.zip"'},
    )


@router.post("/projects/{project_id}/incidents/{incident_id}/report",
             summary="Generate a single-incident PDF report")
def single_incident_report(incident_id: int, user=Depends(get_current_user),
                           project=Depends(get_owned_project), db=Depends(get_db)):
    inc = _incident_of_project(db, project["id"], incident_id)
    pdf, filename = _report_bytes(db, inc, user)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Mitigation checklist (Part B)
# ---------------------------------------------------------------------------

@router.get("/projects/{project_id}/incidents/{incident_id}/mitigation/suggestions",
            summary="One-click mitigation suggestions derived from attached evidence")
def mitigation_suggestions_endpoint(incident_id: int, project=Depends(get_owned_project), db=Depends(get_db),
                                    technique_id: str | None = Query(None)):
    _incident_of_project(db, project["id"], incident_id)
    evidence = _evidence_docs(db, incident_id)
    groups = mitigation_suggestions(evidence)
    if technique_id:
        items = technique_suggestions(technique_id)
        if items:
            groups = [{"technique": technique_id.strip().upper(), "items": items}] + [
                g for g in groups if g.get("tactic", "") != technique_id
            ]
    return {"suggestions": groups}


@router.post("/projects/{project_id}/incidents/{incident_id}/mitigation",
             summary="Append a new unchecked mitigation item")
def add_mitigation_item(incident_id: int, body: MitigationAddBody, user=Depends(get_current_user),
                        project=Depends(get_owned_project), db=Depends(get_db)):
    inc = _incident_of_project(db, project["id"], incident_id)
    text = body.text.strip()
    item = {
        "id": uuid4().hex[:12],
        "text": text,
        "done": False,
        "suggested": bool(body.suggested),
        "completed_by": None,
        "completed_at": None,
        "created_at": datetime.now(timezone.utc),
    }
    db.incidents.update_one(
        {"id": incident_id, "project_id": project["id"]},
        {"$push": {"mitigation": item}, "$set": {"updated_at": datetime.now(timezone.utc)}},
    )
    log_incident_action(db, user, project["id"], incident_id, "mitigation_added", text[:200])
    return item


@router.patch("/projects/{project_id}/incidents/{incident_id}/mitigation/{item_id}",
              summary="Toggle a mitigation item's done state")
def toggle_mitigation_item(incident_id: int, item_id: str, body: MitigationToggleBody,
                           user=Depends(get_current_user), project=Depends(get_owned_project),
                           db=Depends(get_db)):
    inc = _incident_of_project(db, project["id"], incident_id)
    mitigation = _mitigation_list(inc)
    item = next((i for i in mitigation if i.get("id") == item_id), None)
    if not item:
        raise HTTPException(status_code=404, detail="Mitigation item not found")
    now = datetime.now(timezone.utc)
    item["done"] = body.done
    item["completed_by"] = user["id"] if body.done else None
    item["completed_at"] = now if body.done else None
    db.incidents.update_one(
        {"id": incident_id, "project_id": project["id"]},
        {"$set": {"mitigation": mitigation, "updated_at": now}},
    )
    log_incident_action(
        db, user, project["id"], incident_id,
        "mitigation_toggled",
        f'"{str(item["text"])[:80]}" \u2192 {"done" if body.done else "not done"}',
    )
    return item


# ---------------------------------------------------------------------------
# Legacy GET alias for the detail-page export (same renderer as POST /report)
# ---------------------------------------------------------------------------

@router.get("/incidents/{incident_id}/export/pdf", summary="Export an incident report as PDF (legacy alias)")
def export_incident_pdf(user=Depends(get_current_user), incident=Depends(get_owned_incident), db=Depends(get_db)):
    pdf, filename = _report_bytes(db, incident, user)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
