from fastapi import APIRouter, Depends, HTTPException, Response
from datetime import datetime, timezone
from app.database import get_db, get_next_id, NO_ID
from app.auth import get_current_user
from app.models.incident import IncidentCreate, IncidentUpdate, IncidentResponse
from app.services.incident_metrics import evidence_metrics
from app.services.incident_report import build_incident_pdf

router = APIRouter(dependencies=[Depends(get_current_user)])


def _check_project(project_id: int, user, db):
    project = db.projects.find_one({"id": project_id}, NO_ID)
    if not project or project["owner_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Project not found")


def _evidence_docs(db, incident_id: int) -> list[dict]:
    return list(db.incident_evidence.find({"incident_id": incident_id}, {"_id": 0}).sort("added_at", -1))


@router.get("/projects/{project_id}/incidents", summary="List a project's incidents")
def list_incidents(project_id: int, user=Depends(get_current_user), db=Depends(get_db)):
    _check_project(project_id, user, db)
    incidents = list(db.incidents.find({"project_id": project_id}, NO_ID).sort("created_at", -1))
    result = []
    for inc in incidents:
        evidence = _evidence_docs(db, inc["id"])
        result.append(IncidentResponse(
            id=inc["id"], project_id=inc["project_id"], title=inc["title"],
            description=inc.get("description"), mitigation=inc.get("mitigation"),
            severity=inc["severity"], status=inc["status"], assigned_to=inc.get("assigned_to"),
            created_at=inc["created_at"], updated_at=inc["updated_at"],
            evidence_count=len(evidence), notes=inc.get("notes", []),
            **evidence_metrics(evidence),
        ))
    return result


@router.post("/projects/{project_id}/incidents", summary="Create an incident from an event")
def create_incident(project_id: int, body: IncidentCreate, user=Depends(get_current_user), db=Depends(get_db)):
    _check_project(project_id, user, db)
    now = datetime.now(timezone.utc)
    incident = {
        "id": get_next_id("incidents"),
        "project_id": project_id,
        "title": body.title,
        "description": body.description,
        "severity": body.severity,
        "status": "open",
        "assigned_to": None,
        "created_at": now,
        "updated_at": now,
    }
    db.incidents.insert_one(incident)
    return IncidentResponse(
        id=incident["id"], project_id=incident["project_id"], title=incident["title"],
        description=incident["description"], mitigation=incident.get("mitigation"),
        severity=incident["severity"], status=incident["status"], assigned_to=incident["assigned_to"],
        created_at=incident["created_at"], updated_at=incident["updated_at"],
        evidence_count=0, notes=incident.get("notes", []),
    )


@router.get("/incidents/{incident_id}", summary="Get one incident")
def get_incident(incident_id: int, user=Depends(get_current_user), db=Depends(get_db)):
    incident = db.incidents.find_one({"id": incident_id}, NO_ID)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    project = db.projects.find_one({"id": incident["project_id"]}, NO_ID)
    if project["owner_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")
    evidence = _evidence_docs(db, incident_id)
    return IncidentResponse(
        id=incident["id"], project_id=incident["project_id"], title=incident["title"],
        description=incident.get("description"), mitigation=incident.get("mitigation"),
        severity=incident["severity"], status=incident["status"], assigned_to=incident.get("assigned_to"),
        created_at=incident["created_at"], updated_at=incident["updated_at"],
        evidence_count=len(evidence), notes=incident.get("notes", []),
        **evidence_metrics(evidence),
    )


@router.patch("/incidents/{incident_id}", summary="Update an incident (status/severity/assignee)")
def update_incident(incident_id: int, body: IncidentUpdate, user=Depends(get_current_user), db=Depends(get_db)):
    incident = db.incidents.find_one({"id": incident_id}, NO_ID)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    project = db.projects.find_one({"id": incident["project_id"]}, NO_ID)
    if project["owner_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")
    update = {k: v for k, v in body.model_dump(exclude_none=True).items() if v is not None}
    update["updated_at"] = datetime.now(timezone.utc)
    db.incidents.update_one({"id": incident_id}, {"$set": update})
    incident = db.incidents.find_one({"id": incident_id}, NO_ID)
    evidence = _evidence_docs(db, incident_id)
    return IncidentResponse(
        id=incident["id"], project_id=incident["project_id"], title=incident["title"],
        description=incident.get("description"), mitigation=incident.get("mitigation"),
        severity=incident["severity"], status=incident["status"], assigned_to=incident.get("assigned_to"),
        created_at=incident["created_at"], updated_at=incident["updated_at"],
        evidence_count=len(evidence), notes=incident.get("notes", []),
        **evidence_metrics(evidence),
    )


@router.post("/incidents/{incident_id}/notes", summary="Add a note to an incident")
def add_note(incident_id: int, body: dict, user=Depends(get_current_user), db=Depends(get_db)):
    incident = db.incidents.find_one({"id": incident_id}, NO_ID)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    project = db.projects.find_one({"id": incident["project_id"]}, NO_ID)
    if project["owner_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")
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
    return note


@router.get("/incidents/{incident_id}/evidence", summary="List evidence snapshots for an incident")
def list_evidence(incident_id: int, user=Depends(get_current_user), db=Depends(get_db)):
    incident = db.incidents.find_one({"id": incident_id}, NO_ID)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    project = db.projects.find_one({"id": incident["project_id"]}, NO_ID)
    if project["owner_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")
    evidence = list(db.incident_evidence.find({"incident_id": incident_id}, {"_id": 0}).sort("added_at", -1))
    return evidence


@router.post("/incidents/{incident_id}/evidence", summary="Attach an event snapshot to an incident")
def add_evidence(incident_id: int, body: dict, user=Depends(get_current_user), db=Depends(get_db)):
    incident = db.incidents.find_one({"id": incident_id}, NO_ID)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    project = db.projects.find_one({"id": incident["project_id"]}, NO_ID)
    if project["owner_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")
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
    ev.pop("_id", None)
    return ev


@router.get("/incidents/{incident_id}/export/pdf", summary="Export an incident report as PDF")
def export_incident_pdf(incident_id: int, user=Depends(get_current_user), db=Depends(get_db)):
    incident = db.incidents.find_one({"id": incident_id}, NO_ID)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    project = db.projects.find_one({"id": incident["project_id"]}, NO_ID)
    if project["owner_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")
    evidence = _evidence_docs(db, incident_id)
    metrics = evidence_metrics(evidence)
    generated_by = user.get("name") or user.get("email") or f"User #{user['id']}"
    buf = build_incident_pdf(incident, evidence, metrics, generated_by)
    return Response(
        content=buf.getvalue(),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="incident-{incident_id}-report.pdf"',
        },
    )

