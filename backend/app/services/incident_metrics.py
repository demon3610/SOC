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


_EMPTY_USERS = {"", "unknown", "-", "n/a", "none", "null"}


def event_user(snap: dict | None) -> str | None:
    """Authenticated/target user stamped by the log parser (if any)."""
    if not snap:
        return None
    user = ((snap.get("parsed") or {}).get("user")) or ((snap.get("raw") or {}).get("user")) or ""
    user = str(user).strip()
    return user if user and user.lower() not in _EMPTY_USERS else None


def linked_entities(evidence_docs: list[dict]) -> dict:
    """Hosts / IPs / users / technique ids derived from attached evidence.

    Deliberately computed per request (like mitre tags) so the linked-entity
    chips stay in lockstep with whatever evidence is actually attached.
    """
    hosts: list[str] = []
    ips: list[str] = []
    users: list[str] = []
    techniques: list[str] = []
    for ev in evidence_docs:
        snap = parse_snapshot(ev)
        for value, bucket in (
            (event_hostname(snap), hosts),
            (event_ip(snap), ips),
            (event_user(snap), users),
        ):
            if value and value not in bucket:
                bucket.append(value)
        m = event_mitre(snap)
        if m and m.get("technique"):
            tid = str(m["technique"]).split(" ")[0]
            if tid and tid not in techniques:
                techniques.append(tid)
    return {"hosts": hosts, "ips": ips, "users": users, "technique_ids": techniques}


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

# Static technique → checklist lookup (brief 1.2). Covers the techniques the
# platform actually emits (see services/mitre.py) plus common AD attacks.
TECHNIQUE_SUGGESTIONS: dict[str, list[str]] = {
    "T1110": [
        "Reset affected account credentials",
        "Enable/verify account lockout policy",
        "Check for successful logon following failed attempts",
    ],
    "T1078": [
        "Disable the abused valid account or force re-authentication",
        "Audit how the account credentials were obtained",
    ],
    "T1550": [
        "Invalidate alternate auth material (tickets/hashes) for the account",
        "Force password reset and review lateral movement",
    ],
    "T1136": [
        "Remove the unauthorized account",
        "Audit account creation events on the host",
    ],
    "T1098": [
        "Revert unauthorized account manipulation",
        "Audit group membership and permission changes",
    ],
    "T1070.001": [
        "Check log forwarding — was this host's log clearing masking other activity?",
        "Restore logs from central collector if available",
    ],
    "T1543.003": [
        "Review newly created services for persistence",
        "Verify service binary signatures",
        "Check service creation event 7045 on the host",
    ],
    "T1548.003": [
        "Review sudoers changes and recent sudo usage",
        "Verify the invoking user still requires sudo access",
    ],
    "T1003": [
        "Force password resets for potentially dumped credentials (Kerberoasting/DCSync fallout)",
        "Rotate the KRBTGT account twice to invalidate golden tickets",
    ],
    "T1558": [
        "Force password reset for the AS-REP roastable account",
        "Enable Kerberos pre-authentication if disabled",
    ],
}


def technique_suggestions(technique_id: str) -> list[str]:
    """Checklist items for one technique id (prefix match, e.g. T1070 → T1070.001)."""
    tid = (technique_id or "").strip().upper()
    if not tid:
        return []
    if tid in TECHNIQUE_SUGGESTIONS:
        return TECHNIQUE_SUGGESTIONS[tid]
    for key, items in TECHNIQUE_SUGGESTIONS.items():
        if key.startswith(tid) or tid.startswith(key):
            return items
    return []


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
