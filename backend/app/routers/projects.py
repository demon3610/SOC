import hashlib
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Header, HTTPException
from app.database import get_db, get_next_id, NO_ID, all_events_collections
from app.auth import get_current_user
from app.models.project import ProjectCreate, ProjectUpdate, ProjectResponse
from app.config import PUBLIC_BACKEND_URL
from app.services.prompt_templates import build_ai_agent_prompt, build_website_setup_prompt
from app.services.elastic import delete_events_by_query, delete_agent_logs_by_query
from app.dependencies import get_owned_project

router = APIRouter(dependencies=[Depends(get_current_user)])


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _iso(value) -> str | None:
    return value.isoformat() if isinstance(value, datetime) else (str(value) if value else None)


@router.get("/projects/{project_id}/sources",
            summary="Every key/agent feeding this project (owned-project scoped)")
def project_sources(project_id: int, _project=Depends(get_owned_project), db=Depends(get_db)):
    """List the exact keys + agents tied to THIS project.

    Both api_keys and agent_keys are resolved only after the ownership check
    (get_owned_project), so a tampered project_id in the URL cannot leak
    another project's key list. Agent keys map to windows/linux by os_type;
    website keys have no hostname and report last_used_at as last_seen.
    """
    sources = []
    for key in db.api_keys.find({"project_id": project_id}, {"_id": 0, "key_hash": 0}):
        sources.append({
            "id": key["id"],
            "label": key.get("label", ""),
            "type": "website",
            "hostname": None,
            "os_type": None,
            "last_seen_at": _iso(key.get("last_used_at")),
            "status": "revoked" if key.get("revoked") else "active",
        })
    for key in db.agent_keys.find({"project_id": project_id}, {"_id": 0, "key_hash": 0}):
        os_type = str(key.get("os_type", "")).lower()
        is_windows = "windows" in os_type or "win32" in os_type or os_type.startswith("win")
        sources.append({
            "id": key["id"],
            "label": key.get("label", ""),
            "type": "windows" if is_windows else "linux",
            "hostname": key.get("hostname"),
            "os_type": key.get("os_type"),
            "last_seen_at": _iso(key.get("last_seen_at")),
            "status": key.get("status", "pending"),
        })
    sources.sort(key=lambda s: (s["type"], s["id"]))
    return {"sources": sources}


@router.get("/projects", summary="List the current user's projects")
def list_projects(user=Depends(get_current_user), db=Depends(get_db)):
    projects = list(db.projects.find({"owner_id": user["id"]}, NO_ID))
    result = []
    for p in projects:
        keys = list(db.api_keys.find({"project_id": p["id"]}, {"_id": 0, "key_hash": 0}))
        agent_keys = list(db.agent_keys.find({"project_id": p["id"]}, {"_id": 0, "key_hash": 0}))
        last_event = max(
            [k.get("last_used_at") for k in keys if k.get("last_used_at")]
            + [k.get("last_seen_at") for k in agent_keys if k.get("last_seen_at")],
            default=None,
        )
        result.append(ProjectResponse(
            id=p["id"], owner_id=p["owner_id"], name=p["name"],
            type=p["type"], description=p.get("description"),
            created_at=p["created_at"], last_event_time=last_event,
        ))
    return result


@router.post("/projects", summary="Create a project")
def create_project(body: ProjectCreate, user=Depends(get_current_user), db=Depends(get_db)):
    project = {
        "id": get_next_id("projects"),
        "owner_id": user["id"],
        "name": body.name,
        "type": body.type,
        "description": body.description,
        "created_at": datetime.now(timezone.utc),
    }
    db.projects.insert_one(project)
    return ProjectResponse(
        id=project["id"], owner_id=project["owner_id"], name=project["name"],
        type=project["type"], description=project["description"], created_at=project["created_at"],
    )


@router.get("/projects/{project_id}", summary="Get one project")
def get_project(project_id: int, user=Depends(get_current_user), db=Depends(get_db)):
    project = db.projects.find_one({"id": project_id}, NO_ID)
    if not project or project["owner_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Project not found")
    keys = list(db.api_keys.find({"project_id": project_id}, {"_id": 0, "key_hash": 0}))
    agent_keys = list(db.agent_keys.find({"project_id": project_id}, {"_id": 0, "key_hash": 0}))
    last_event = max(
        [k.get("last_used_at") for k in keys if k.get("last_used_at")]
        + [k.get("last_seen_at") for k in agent_keys if k.get("last_seen_at")],
        default=None,
    )
    return ProjectResponse(
        id=project["id"], owner_id=project["owner_id"], name=project["name"],
        type=project["type"], description=project.get("description"),
        created_at=project["created_at"], last_event_time=last_event,
    )


@router.delete("/projects/{project_id}", summary="Delete a project and all its data")
def delete_project(project_id: int, user=Depends(get_current_user), db=Depends(get_db)):
    """Removes the project plus its keys, events (all sources: website +
    windows + linux cover every agent entry incl. heartbeats/lifecycle)."""
    project = db.projects.find_one({"id": project_id}, {"id": 1})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    proj = db.projects.find_one({"id": project_id}, NO_ID)
    if proj["owner_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Project not found")
    pid_q = {"$in": [project_id, str(project_id)]}
    db.projects.delete_one({"id": project_id})
    db.api_keys.delete_many({"project_id": project_id})
    db.agent_keys.delete_many({"project_id": project_id})
    for col in all_events_collections():
        col.delete_many({"project_id": pid_q})
    # Keep ES consistent with Mongo (no-op when ES is down).
    delete_events_by_query(project_id)
    delete_agent_logs_by_query(project_id)
    incident_ids = [i["id"] for i in db.incidents.find({"project_id": project_id}, {"id": 1})]
    db.incident_evidence.delete_many({"incident_id": {"$in": incident_ids}})
    db.incidents.delete_many({"project_id": project_id})
    return {"message": "Project deleted"}


@router.get("/projects/{project_id}/integration-snippet", summary="Get website script tag + AI-agent prompt")
def integration_snippet(project_id: int, user=Depends(get_current_user), db=Depends(get_db)):
    """Returns the embeddable snippet for this project; keys are hashed at rest so the reveal happens at key creation."""
    project = db.projects.find_one({"id": project_id}, NO_ID)
    if not project or project["owner_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Project not found")
    key = db.api_keys.find_one({"project_id": project_id, "revoked": False}, NO_ID)
    if not key:
        raise HTTPException(status_code=400, detail="No active API key. Create one first.")
    # Keys are stored hashed (one-time reveal), so the persistent view uses the
    # same YOUR_API_KEY placeholder the script tag always has — the user pastes
    # in the key they saved at generation time. The key-creation response
    # carries the real key + fully-filled prompt.
    script_tag = (
        f'<script src="{PUBLIC_BACKEND_URL}/agents/usp.js" '
        f'data-soc-key="YOUR_API_KEY" data-soc-host="{PUBLIC_BACKEND_URL}"></script>'
    )
    return {
        "snippet": script_tag,
        "script_tag": script_tag,
        "ai_agent_prompt": build_ai_agent_prompt(PUBLIC_BACKEND_URL, "YOUR_API_KEY"),
    }


@router.get("/projects/{project_id}/website-setup-prompt", summary="Full filled-in website integration prompt for the IDE agent page")
def website_setup_prompt(
    project_id: int,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    user=Depends(get_current_user),
    db=Depends(get_db),
):
    """Return the complete Website Setup prompt with real values substituted.

    Keys are stored hashed (one-time reveal), so the plaintext key the prompt
    needs comes from the browser's copy saved when the key was generated. The
    supplied key is validated against the project's active website keys — the
    existing key is reused, never regenerated. If the key is unavailable or no
    key exists, a 409 tells the frontend to prompt for key generation.
    """
    project = db.projects.find_one({"id": project_id}, NO_ID)
    if not project or project["owner_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Project not found")
    key = db.api_keys.find_one(
        {"project_id": project_id, "revoked": False}, NO_ID,
        sort=[("created_at", -1)],
    )
    if not key:
        raise HTTPException(
            status_code=409,
            detail="No Website Integration API key exists for this project yet. Generate a Website Integration API key first.",
        )
    if not x_api_key or _hash_key(x_api_key) != key["key_hash"]:
        raise HTTPException(
            status_code=409,
            detail="The Website Integration API key is stored hashed and is only revealed once when generated. Generate a new key to fill the prompt in with real values.",
        )
    return {"prompt": build_website_setup_prompt(PUBLIC_BACKEND_URL, x_api_key)}

