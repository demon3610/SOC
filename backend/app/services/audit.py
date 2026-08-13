from datetime import datetime, timezone
from app.database import get_db, get_next_id, NO_ID

AUDIT_LOG_COLLECTION = "audit_log"


def record_cleanup(db, user, project_id: int, source: str, hostname: str | None,
                   before: str, deleted_count: int, scope: str = "events"):
    """Append one immutable audit entry for an executed cleanup.

    The ``audit_log`` collection is write-only from the product's perspective:
    there is deliberately NO endpoint that can delete or edit these rows, and
    the cleanup code paths never touch it with delete_many/update — a cleanup
    of security logs is itself a security-sensitive action and must leave a
    durable, non-destructible record (user, filters, count, when).
    """
    db.audit_log.insert_one({
        "id": get_next_id(AUDIT_LOG_COLLECTION),
        "user_id": user["id"],
        "username": user.get("username", ""),
        "project_id": project_id,
        "scope": scope,
        "source": source,
        "hostname_filter": hostname or "",
        "before_timestamp": before,
        "deleted_count": deleted_count,
        "executed_at": datetime.now(timezone.utc),
    })


def list_cleanups(db, project_id: int, limit: int = 50, offset: int = 0) -> tuple[list[dict], int]:
    """Newest-first cleanup history for a project (read-only audit trail)."""
    q = {"project_id": project_id}
    total = db.audit_log.count_documents(q)
    docs = list(
        db.audit_log.find(q, NO_ID)
        .sort("executed_at", -1)
        .skip(offset)
        .limit(limit)
    )
    rows = []
    for d in docs:
        ts = d.get("executed_at")
        rows.append({
            "id": d.get("id"),
            "user_id": d.get("user_id"),
            "username": d.get("username", ""),
            "scope": d.get("scope", "events"),
            "source": d.get("source"),
            "hostname_filter": d.get("hostname_filter", ""),
            "before_timestamp": d.get("before_timestamp"),
            "deleted_count": d.get("deleted_count"),
            "executed_at": ts.isoformat() if isinstance(ts, datetime) else str(ts),
        })
    return rows, total
