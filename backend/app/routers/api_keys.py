import secrets
import hashlib
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from app.database import get_db, get_next_id, NO_ID
from app.auth import get_current_user
from app.models.api_key import ApiKeyCreate, ApiKeyResponse, ApiKeyCreated
from app.config import PUBLIC_BACKEND_URL
from app.services.prompt_templates import build_ai_agent_prompt

router = APIRouter(dependencies=[Depends(get_current_user)])


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _check_project(project_id: int, user, db):
    project = db.projects.find_one({"id": project_id}, NO_ID)
    if not project or project["owner_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.post("/projects/{project_id}/api-keys", summary="Create a website API key (one-time key reveal)")
def create_api_key(project_id: int, body: ApiKeyCreate, user=Depends(get_current_user), db=Depends(get_db)):
    """Create a key for the website snippet; the plaintext key is returned only once."""
    _check_project(project_id, user, db)
    raw_key = f"soc_{secrets.token_urlsafe(32)}"
    key_hash = _hash_key(raw_key)
    api_key = {
        "id": get_next_id("api_keys"),
        "project_id": project_id,
        "key_hash": key_hash,
        "label": body.label,
        "created_at": datetime.now(timezone.utc),
        "last_used_at": None,
        "revoked": False,
    }
    db.api_keys.insert_one(api_key)
    # The plaintext key exists only in this response (stored as a hash), so the
    # reveal step gets the fully-filled script tag + AI-agent prompt right here.
    script_tag = (
        f'<script src="{PUBLIC_BACKEND_URL}/agents/usp.js" '
        f'data-soc-key="{raw_key}" data-soc-host="{PUBLIC_BACKEND_URL}"></script>'
    )
    created = ApiKeyCreated(id=api_key["id"], label=api_key["label"], key=raw_key, created_at=api_key["created_at"])
    return {
        **created.model_dump(),
        "script_tag": script_tag,
        "ai_agent_prompt": build_ai_agent_prompt(PUBLIC_BACKEND_URL, raw_key),
    }


@router.get("/projects/{project_id}/api-keys", summary="List a project's website API keys")
def list_api_keys(project_id: int, user=Depends(get_current_user), db=Depends(get_db)):
    _check_project(project_id, user, db)
    keys = list(db.api_keys.find({"project_id": project_id}, {"_id": 0, "key_hash": 0}).sort("created_at", -1))
    return keys


@router.delete("/api-keys/{key_id}", summary="Revoke a website API key")
def revoke_api_key(key_id: int, user=Depends(get_current_user), db=Depends(get_db)):
    key = db.api_keys.find_one({"id": key_id}, NO_ID)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    project = db.projects.find_one({"id": key["project_id"]}, NO_ID)
    if project["owner_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")
    db.api_keys.update_one({"id": key_id}, {"$set": {"revoked": True}})
    return {"message": "Key revoked"}
