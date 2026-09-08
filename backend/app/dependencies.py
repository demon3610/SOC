from fastapi import Depends, HTTPException
from app.database import get_db, NO_ID
from app.auth import get_current_user


def get_owned_project(
    project_id: int,
    user=Depends(get_current_user),
    db=Depends(get_db),
):
    """Resolve a project only if it belongs to the current user (404 otherwise).

    This is the single ownership gate for project-scoped routes. Every query
    keyed off the URL ``project_id`` must pass through here (or an equivalent
    inline check) BEFORE touching any events_* / api_keys / agent_keys
    collection — otherwise a tampered project_id in the URL would let one
    user read or delete another user's data.
    """
    project = db.projects.find_one({"id": project_id}, NO_ID)
    if not project or project["owner_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def get_owned_incident(
    incident_id: int,
    user=Depends(get_current_user),
    db=Depends(get_db),
):
    """Resolve an incident only if its parent project belongs to the current
    user (404 otherwise — same non-disclosing semantics as get_owned_project).

    Ownership is transitive: the incident is looked up, then its project's
    owner is verified, so a guessed incident id from another tenant yields
    404, never the incident.
    """
    incident = db.incidents.find_one({"id": incident_id}, NO_ID)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    project = db.projects.find_one({"id": incident["project_id"]}, {"owner_id": 1})
    if not project or project["owner_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


def get_owned_api_key(
    key_id: int,
    user=Depends(get_current_user),
    db=Depends(get_db),
):
    """Resolve a website API key only if its parent project belongs to the
    current user (404 otherwise — transitive ownership via the project)."""
    key = db.api_keys.find_one({"id": key_id}, NO_ID)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    project = db.projects.find_one({"id": key["project_id"]}, {"owner_id": 1})
    if not project or project["owner_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Key not found")
    return key
