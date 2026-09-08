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


def event_mitre(snap: dict | None) -> dict | None:
    """The MITRE tactic/technique stamped on an event at ingest time (if any)."""
    if not snap:
        return None
    m = snap.get("mitre") or {}
    return m if isinstance(m, dict) and (m.get("tactic") or m.get("technique")) else None


def event_hostname(snap: dict | None) -> str | None:
    if not snap:
        return None
    host = snap.get("hostname") or (snap.get("raw") or {}).get("hostname") or ""
    return str(host) or None


def mitre_tags_from_evidence(evidence_docs: list[dict]) -> list[dict]:
    """Deduplicated [{tactic, technique}] derived from attached evidence.

    Deliberately not stored on the incident — tags stay in lockstep with
    whatever evidence is actually attached (add evidence → tag appears;
    the tag list is computed per request).
    """
    seen: set[tuple[str, str]] = set()
    tags: list[dict] = []
    for ev in evidence_docs:
        m = event_mitre(parse_snapshot(ev))
        if not m:
            continue
        tactic = str(m.get("tactic") or "Unknown")
        technique = str(m.get("technique") or "")
        key = (tactic, technique)
        if key in seen:
            continue
        seen.add(key)
        tags.append({"tactic": tactic, "technique": technique})
    return tags


def primary_ip_from_evidence(evidence_docs: list[dict]) -> str | None:
    """Most frequently occurring IP across attached evidence (None if none)."""
    counts: dict[str, int] = {}
    for ev in evidence_docs:
        ip = event_ip(parse_snapshot(ev))
        if ip:
            counts[ip] = counts.get(ip, 0) + 1
    if not counts:
        return None
    return max(counts.items(), key=lambda kv: (kv[1], kv[0]))[0]


# Static one-click mitigation suggestions keyed by MITRE tactic (Part B).
MITRE_SUGGESTIONS: dict[str, list[str]] = {
    "Credential Access": [
        "Force password reset for affected account",
        "Enable MFA if not already enabled",
    ],
    "Persistence": [
        "Remove unauthorized service/scheduled task",
        "Audit other services for similar persistence",
    ],
    "Defense Evasion": [
        "Review backup/alternate logs for the cleared window",
    ],
    "Initial Access": [
        "Block the source IP at the perimeter",
        "Review the exploited application for the vulnerable entry point",
    ],
    "Execution": [
        "Kill the offending process and verify it cannot restart",
        "Review scheduled tasks and run keys for persistence",
    ],
    "Privilege Escalation": [
        "Revoke the elevated privileges granted to the compromised account",
        "Audit group membership changes on the affected host",
    ],
    "Lateral Movement": [
        "Isolate the affected host from the network",
        "Audit RDP/SMB access to the host for other compromised accounts",
    ],
    "Collection": [
        "Rotate credentials that may have been exfiltrated",
        "Check for data staging locations on the affected host",
    ],
    "Exfiltration": [
        "Block outbound traffic to the exfiltration destination",
        "Rotate credentials that may have been exfiltrated",
    ],
    "Discovery": [
        "Restrict the account's access to network reconnaissance tools",
        "Audit recent logon events from the affected host",
    ],
}

# Tactics present in the current evidence (deduplicated, order stable).
def mitigation_suggestions(evidence_docs: list[dict]) -> list[dict]:
    """[{tactic, items: [...]}] suggested checklist entries for this incident."""
    tactics: list[str] = []
    for tag in mitre_tags_from_evidence(evidence_docs):
        tactic = tag["tactic"]
        if tactic in MITRE_SUGGESTIONS and tactic not in tactics:
            tactics.append(tactic)
    return [
        {"tactic": t, "items": MITRE_SUGGESTIONS[t]}
        for t in tactics
    ]


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
