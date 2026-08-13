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
