"""Shared extraction of OS / IP / risk metrics from incident evidence.

Used by both the incident JSON responses (on-page display) and the PDF
report generator so both always show identical values.
"""

import json

OS_LABELS = {
    "windows": "Windows",
    "linux": "Linux",
    "website": "Web",
}

_EMPTY_IPS = {"", "unknown", "local", None}


def parse_snapshot(ev: dict) -> dict | None:
    try:
        snap = json.loads(ev.get("event_snapshot") or "{}")
        return snap if isinstance(snap, dict) else None
    except (ValueError, TypeError):
        return None


def event_os(snap: dict | None) -> str | None:
    if not snap:
        return None
    source = snap.get("source")
    return OS_LABELS.get(source) or (source or None)


def event_ip(snap: dict | None) -> str | None:
    if not snap:
        return None
    parsed = snap.get("parsed") or {}
    raw = snap.get("raw") or {}
    enriched = snap.get("enriched") or {}
    for candidate in (
        enriched.get("ip"),
        parsed.get("ip"),
        parsed.get("src_ip"),
        raw.get("ip"),
        raw.get("src_ip"),
    ):
        if candidate and candidate not in _EMPTY_IPS:
            return str(candidate)
    return None


def event_risk(snap: dict | None) -> int:
    if not snap:
        return 0
    score = (snap.get("enriched") or {}).get("risk_score")
    return int(score) if isinstance(score, (int, float)) else 0


def evidence_metrics(evidence_docs: list[dict]) -> dict:
    """Aggregate OS types, unique affected IPs, and risk scores from evidence."""
    os_types: list[str] = []
    ips: list[str] = []
    risks: list[int] = []
    for ev in evidence_docs:
        snap = parse_snapshot(ev)
        os_name = event_os(snap)
        if os_name and os_name not in os_types:
            os_types.append(os_name)
        ip = event_ip(snap)
        if ip and ip not in ips:
            ips.append(ip)
        risks.append(event_risk(snap))
    return {
        "os_types": os_types,
        "affected_ips": ips,
        "risk_score": max(risks) if risks else None,
        "risk_average": round(sum(risks) / len(risks), 1) if risks else None,
    }
