"""Dynamic risk scoring.

risk_score combines the base severity with two dynamic signals:
  * threat-intel matches on the source IP (IOC feed)
  * burst/brute-force correlation — repeated failed logons from the same
    source within a short window push the score up

This keeps risk_score consistent with event_type instead of sitting at a
static placeholder value.
"""

from datetime import datetime, timedelta
from app.database import all_events_collections

SEVERITY_BASE_SCORE = {"critical": 90, "high": 70, "medium": 40, "low": 15, "info": 0}

_BURST_WINDOW_MINUTES = 10
_BURST_THRESHOLD_STRONG = 5
_BURST_THRESHOLD_MODERATE = 3

_THREAT_MATCH_BONUS = 30
_BURST_STRONG_BONUS = 40
_BURST_MODERATE_BONUS = 20


def _window_start_iso(ts):
    """ISO string for (timestamp - burst window); None if unparseable."""
    if isinstance(ts, datetime):
        return (ts - timedelta(minutes=_BURST_WINDOW_MINUTES)).isoformat()
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return (dt - timedelta(minutes=_BURST_WINDOW_MINUTES)).isoformat()
    except (TypeError, ValueError):
        return None


def compute_risk_score(event: dict, db) -> int:
    severity = event.get("event_type", "info")
    score = SEVERITY_BASE_SCORE.get(severity, 0)

    if (event.get("enriched") or {}).get("threat_match"):
        score = min(100, score + _THREAT_MATCH_BONUS)

    parsed = event.get("parsed") or {}
    ip_or_user = (event.get("enriched") or {}).get("ip") or parsed.get("user")
    event_id = parsed.get("event_id")
    action = parsed.get("action")
    is_auth_failure = str(event_id) == "4625" or action == "failed_login"

    if ip_or_user and is_auth_failure:
        window_start = _window_start_iso(event.get("timestamp"))
        if window_start:
            pid = event.get("project_id")
            if isinstance(pid, int):
                pid_candidates = [pid, str(pid)]
            else:
                try:
                    pid_candidates = [int(pid), str(pid)]
                except (TypeError, ValueError):
                    pid_candidates = [pid]
            identity_q = {}
            if event_id:
                identity_q["parsed.event_id"] = str(event_id)
            elif action:
                identity_q["parsed.action"] = action
            if not identity_q:
                return score
            recent = sum(
                col.count_documents({
                    "project_id": {"$in": pid_candidates},
                    **identity_q,
                    "$or": [
                        {"enriched.ip": ip_or_user},
                        {"parsed.user": ip_or_user},
                    ],
                    "timestamp": {"$gte": window_start},
                })
                for col in all_events_collections()
            )
            if recent >= _BURST_THRESHOLD_STRONG:
                score = min(100, score + _BURST_STRONG_BONUS)
            elif recent >= _BURST_THRESHOLD_MODERATE:
                score = min(100, score + _BURST_MODERATE_BONUS)

    return score
