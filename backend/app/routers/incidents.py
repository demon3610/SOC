import io
import json
import zipfile
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from app.auth import get_current_user
from app.database import (
    EVENTS_VIEW_COND,
    NO_ID,
    agent_events_collections,
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
    mitigation_suggestions,
    mitre_tags_from_evidence,
    parse_snapshot,
    primary_ip_from_evidence,
)
from app.services.pdf_report import render_incident_pdf

router = APIRouter(dependencies=[Depends(get_current_user)])


class MitigationAddBody(BaseModel):
    text: str = Field(min_length=1, max_length=500)


class MitigationToggleBody(BaseModel):
    done: bool


class ChainEvidenceBody(BaseModel):
    hostname: str
    start_time: str
    end_time: str


class BulkReportBody(BaseModel):
    incident_ids: list[int]


def _evidence_docs(db, incident_id: int) -> list[dict]:
    return list(db.incident_evidence.find({"incident_id": incident_id}, {"_id": 0}).sort("added_at", -1))


def _mitigation_list(incident: dict) -> list:
    mitigation = incident.get("mitigation")
    if isinstance(mitigation, list):
        return mitigation
    return []  # legacy free-text mitigation is replaced by the checklist model


def _dto(incident: dict, evidence: list[dict]) -> IncidentResponse:
    """Incident response with Part-E derived fields (mitre tags, primary IP)."""
    return IncidentResponse(
        id=incident["id"], project_id=incident["project_id"], title=incident["title"],
        description=incident.get("description"), mitigation=_mitigation_list(incident),
        severity=incident["severity"], status=incident["status"], assigned_to=incident.get("assigned_to"),
        created_at=incident["created_at"], updated_at=incident["updated_at"],
        evidence_count=len(evidence), notes=incident.get("notes", []),
        **evidence_metrics(evidence),
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
def list_incidents(project=Depends(get_owned_project), db=Depends(get_db)):
    project_id = project["id"]
    incidents = list(db.incidents.find({"project_id": project_id}, NO_ID).sort("created_at", -1))
    result = []
    for inc in incidents:
        evidence = _evidence_docs(db, inc["id"])
        result.append(_dto(inc, evidence))
    return result


@router.post("/projects/{project_id}/incidents", summary="Create an incident from an event")
def create_incident(body: IncidentCreate, user=Depends(get_current_user),
                    project=Depends(get_owned_project), db=Depends(get_db)):
    project_id = project["id"]
    now = datetime.now(timezone.utc)
    incident = {
        "id": get_next_id("incidents"),
        "project_id": project_id,
        "title": body.title,
        "description": body.description,
        "severity": body.severity,
        "status": "open",
        "assigned_to": None,
        "mitigation": [],
        "created_at": now,
        "updated_at": now,
    }
    db.incidents.insert_one(incident)
    log_incident_action(db, user, project_id, incident["id"], "created", f'"{body.title}"')
    return _dto(incident, [])


@router.get("/incidents/{incident_id}", summary="Get one incident")
def get_incident(incident=Depends(get_owned_incident), db=Depends(get_db)):
    incident_id = incident["id"]
    evidence = _evidence_docs(db, incident_id)
    return _dto(incident, evidence)


@router.patch("/incidents/{incident_id}", summary="Update an incident (status/severity/assignee)")
def update_incident(body: IncidentUpdate, user=Depends(get_current_user),
                    incident=Depends(get_owned_incident), db=Depends(get_db)):
    incident_id = incident["id"]
    update = {k: v for k, v in body.model_dump(exclude_none=True).items() if v is not None}
    update["updated_at"] = datetime.now(timezone.utc)

    for field, label in (("status", "status"), ("severity", "severity")):
        if field in update and update[field] != incident.get(field):
            log_incident_action(
                db, user, incident["project_id"], incident_id,
                f"{label}_changed",
                f"{incident.get(field) or 'unset'} \u2192 {update[field]}",
            )

    db.incidents.update_one({"id": incident_id}, {"$set": update})
    incident = db.incidents.find_one({"id": incident_id}, NO_ID)
    evidence = _evidence_docs(db, incident_id)
    return _dto(incident, evidence)


@router.post("/incidents/{incident_id}/notes", summary="Add a note to an incident")
def add_note(body: dict, user=Depends(get_current_user), incident=Depends(get_owned_incident), db=Depends(get_db)):
    incident_id = incident["id"]
    text = str(body.get("text") or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="Note text is required")
    note = {
        "id": get_next_id("incident_notes"),
        "text": text,
        "added_by": user["id"],
        "added_at": datetime.now(timezone.utc),
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
    ev = {
        "id": get_next_id("incident_evidence"),
        "incident_id": incident_id,
        "event_snapshot": body["event_snapshot"],
        "source_event_id": body["source_event_id"],
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

    host = (body.hostname or "").strip()
    if not host:
        raise HTTPException(status_code=400, detail="hostname is required")

    pid_q = {"$in": [incident["project_id"], str(incident["project_id"])]}
    matches = []
    for col in agent_events_collections():
        for e in col.find(
            {"project_id": pid_q, "$and": [EVENTS_VIEW_COND, {"$or": [
                {"hostname": host},
                {"raw.hostname": host},
            ]}]},
            NO_ID,
        ):
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
def mitigation_suggestions_endpoint(incident_id: int, project=Depends(get_owned_project), db=Depends(get_db)):
    _incident_of_project(db, project["id"], incident_id)
    evidence = _evidence_docs(db, incident_id)
    return {"suggestions": mitigation_suggestions(evidence)}


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
