"""Severity classification.

Never trusts the OS's own Level/Error/Warning label — that describes operational
status, not security risk. Windows severity comes from the allow-list table
(event_filter), Linux from the parsed action. The OS's Level value is still kept
for analysts in ``parsed.level``; it just never drives ``event_type`` again.
"""

from app.services.event_filter import ALLOWED_LINUX_ACTIONS, base_severity


def classify_severity(log_name: str, event_id, action: str | None, parsed: dict | None = None) -> str:
    sev = base_severity(log_name or "", event_id)
    if sev != "info":
        return sev
    if action:
        return ALLOWED_LINUX_ACTIONS.get(action, "info")
    if parsed and parsed.get("severity") in ("critical", "high", "medium"):
        # journald PRIORITY mapped into the existing severity system — the
        # OS label is trusted here only because it is a well-defined 0-7
        # syslog scale (see parse_journal_entry), and it never overrides an
        # allow-listed action.
        return parsed["severity"]
    return "info"