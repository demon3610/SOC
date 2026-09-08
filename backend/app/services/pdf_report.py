"""Incident report → PDF via WeasyPrint (HTML/CSS → PDF).

One Jinja2 template renders the whole report so styling/layout changes are
edits to HTML/CSS, not hand-positioned drawing calls. Native GTK/Pango is
required on Windows; the bootstrap below points ctypes at the extracted
runtime when it lives under a known location (it never fails startup — the
render call will surface the real error if the runtime is missing).

Report sections, in order (the report is an external artifact — the Activity
Log that lives in the web UI is intentionally NOT exported):
  1. Letterhead + header — "Incident Report — {title}", never the incident
     number (that's a filesystem concern for filenames only)
  2. Summary — severity/status pills, created/updated, MITRE tags if present
  3. Description
  4. Evidence Timeline — full detail per event: metadata row, summary, and a
     pretty-printed "Raw Event Data" block; correlated-chain events are
     grouped under their own subheading
  5. Notes
  6. Mitigation — plain numbered remediation points (no checkbox glyphs)
"""

import json
import os
from datetime import datetime

from jinja2 import Template

HTML = None
_WEASYPRINT_ERROR = ""

# Well-known install locations for the GTK3 runtime WeasyPrint loads on
# Windows. The loop below is harmless when none exist (the render call will
# surface the real missing-runtime error) and never blocks startup.
_GTK_BIN_CANDIDATES = (
    r"C:\Program Files\GTK3-Runtime Win64\bin",
    r"C:\Program Files (x86)\GTK3-Runtime Win32\bin",
)

for _dir in _GTK_BIN_CANDIDATES:
    if _dir and os.path.isdir(_dir):
        try:
            os.add_dll_directory(_dir)
        except OSError:
            pass

try:
    from weasyprint import HTML  # noqa: E402
except (ImportError, OSError) as _err:
    HTML = None
    _WEASYPRINT_ERROR = str(_err)

from app.services.incident_metrics import (
    event_hostname,
    event_risk,
    mitre_tags_from_evidence,
    parse_snapshot,
)

# Brand tokens mirrored from frontend/src/index.css (the real --soc-accent
# value, not a guessed indigo).
_BRAND = "#2563EB"
_MUTED = "#64748B"
_BORDER = "#E2E8F0"
_TEXT = "#0F172A"

_SEVERITY_PILLS = {
    "critical": ("#DC2626", "#FEE2E2"),
    "high": ("#EA580C", "#FFEDD5"),
    "medium": ("#D97706", "#FEF3C7"),
    "low": ("#2563EB", "#DBEAFE"),
}
_SOURCE_PILLS = {
    "windows": ("#2563EB", "#DBEAFE"),
    "linux": ("#7C3AED", "#EDE9FE"),
    "website": ("#0EA5E9", "#E0F2FE"),
}


def _sev_pill(sev: str | None) -> str:
    if sev and sev.lower() in _SEVERITY_PILLS:
        return f"sev-{sev.lower()}"
    return "sev-info"


def _src_pill(src: str | None) -> str:
    if src and src.lower() in _SOURCE_PILLS:
        return f"src-{src.lower()}"
    return "src-info"


def _pill_css(pills: dict[str, tuple[str, str]], prefix: str) -> str:
    rules = []
    for name, (fg, bg) in pills.items():
        rules.append(
            f".pill.{prefix}-{name} {{ background: {bg}; color: {fg}; }}"
        )
    return "\n  ".join(rules)


_TEMPLATE = Template("""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  @page {
    size: A4;
    margin: 20mm 18mm 22mm 18mm;
    @bottom-left { content: "SOC Platform \\00b7 Incident Report"; font-family: "Segoe UI", "Helvetica", "Arial", sans-serif; font-size: 7.5pt; color: {{ muted }}; }
    @bottom-right { content: "Page " counter(page) " of " counter(pages); font-family: "Segoe UI", "Helvetica", "Arial", sans-serif; font-size: 7.5pt; color: {{ muted }}; }
  }
  body { font-family: "Segoe UI", "Helvetica", "Arial", sans-serif; color: {{ text }}; font-size: 10.5pt; line-height: 1.4; }

  .letterhead { display: flex; align-items: center; gap: 8px; padding-bottom: 10px; border-bottom: 2pt solid {{ brand }}; margin-bottom: 20px; }
  .logo { width: 22px; height: 22px; border-radius: 6px; background: {{ brand }}; color: #FFFFFF; font-weight: 700; font-size: 12pt; line-height: 22px; text-align: center; }
  .wordmark { font-size: 12pt; font-weight: 700; color: {{ text }}; letter-spacing: 0.2pt; }

  h1 { font-size: 21pt; font-weight: 700; line-height: 1.2; margin: 0 0 4px 0; color: {{ text }}; }
  .sub { color: {{ muted }}; font-size: 8.5pt; margin: 0 0 22px 0; }

  h2 { font-size: 13.5pt; font-weight: 700; color: {{ text }}; margin: 26px 0 12px 0; padding-left: 9px; border-left: 3pt solid {{ brand }}; }

  table.kv { width: 100%; border-collapse: collapse; margin-top: 4px; }
  table.kv td { border: 0.5pt solid {{ border }}; padding: 7px 10px; vertical-align: middle; }
  table.kv td.k { font-weight: 600; width: 30%; background: #F8FAFC; color: #334155; font-size: 9.5pt; }
  table.kv td.v { font-size: 10.5pt; }

  .pill { display: inline-block; border-radius: 999px; padding: 2px 10px; font-size: 8.5pt; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4pt; }
  {{ pill_css }}

  .chips { margin: 10px 0 0 0; }
  .chip { display: inline-block; border: 0.5pt solid #C7D2FE; background: #EEF2FF; color: #3730A3; border-radius: 999px; padding: 2px 9px; font-size: 8.5pt; margin: 0 4px 4px 0; }

  .desc { white-space: pre-wrap; margin: 4px 0 0 0; }

  .chain-head { font-size: 9.5pt; font-weight: 700; color: {{ brand }}; margin: 4px 0 8px 0; }
  .ev { border: 0.6pt solid {{ border }}; border-radius: 6px; padding: 10px 12px; margin: 0 0 10px 0; page-break-inside: avoid; }
  .ev .meta { font-size: 8.5pt; color: #475569; margin: 0 0 6px 0; }
  .ev .meta .sep { color: {{ border }}; margin: 0 5px; }
  .ev .sum { margin: 0 0 8px 0; }
  .raw-label { font-size: 8pt; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5pt; color: {{ muted }}; margin: 0 0 4px 0; }
  pre.raw { font-family: "Consolas", "Courier New", monospace; font-size: 7.8pt; line-height: 1.35; background: #F8FAFC; border: 0.5pt solid {{ border }}; border-radius: 4px; padding: 8px 10px; white-space: pre-wrap; word-wrap: break-word; margin: 0; }

  .mit { margin: 4px 0 0 0; }
  .mit .mit-item { margin: 0 0 10px 0; }
  .mit .no { font-weight: 700; color: {{ brand }}; margin-right: 6px; }
  .mit .done-note { display: block; font-size: 8pt; color: {{ muted }}; margin-top: 1px; }

  .note { margin: 0 0 8px 0; }
  .note .who { color: {{ muted }}; font-size: 8.5pt; }

  .empty { color: {{ muted }}; font-style: italic; padding: 10px 0; }
</style>
</head>
<body>
  <div class="letterhead">
    <span class="logo">S</span>
    <span class="wordmark">SOC Platform</span>
  </div>

  <h1>Incident Report — {{ incident.title or 'Untitled incident' }}</h1>
  <p class="sub">Generated {{ generated_at }}{% if generated_by %} · by {{ generated_by }}{% endif %}</p>

  <h2>Summary</h2>
  <table class="kv">
    <tr><td class="k">Severity</td><td class="v"><span class="pill {{ severity_class }}">{{ severity }}</span></td></tr>
    <tr><td class="k">Status</td><td class="v"><span class="pill sev-info">{{ status }}</span></td></tr>
    <tr><td class="k">Created</td><td class="v">{{ created_at }}</td></tr>
    <tr><td class="k">Last updated</td><td class="v">{{ updated_at }}</td></tr>
  </table>

  {% if mitre_tags %}
  <div class="chips">
    {% for tag in mitre_tags %}<span class="chip">{{ tag.tactic }}{% if tag.technique %} · {{ tag.technique }}{% endif %}</span>{% endfor %}
  </div>
  {% endif %}

  <h2>Description</h2>
  <p class="desc">{{ incident.description or "No description provided." }}</p>

  <h2>Evidence Timeline ({{ evidence_count }})</h2>
  {% if evidence %}
    {% for block in evidence %}
      {% if block.type == "head" %}
      <p class="chain-head">Correlated Chain — {{ block.text }}</p>
      {% else %}
      <div class="ev">
        <p class="meta">
          {{ block.timestamp }}
          <span class="sep">·</span>
          <span class="pill {{ block.src_class }}">{{ block.source }}</span>
          <span class="sep">·</span>
          Host: {{ block.hostname or 'Not captured' }}
          {% if block.severity %}
          <span class="sep">·</span>
          <span class="pill {{ block.sev_class }}">{{ block.severity }}</span>
          {% endif %}
          {% if block.risk %}
          <span class="sep">·</span>
          Risk: {{ block.risk }}
          {% endif %}
        </p>
        {% if block.summary %}<p class="sum">{{ block.summary }}</p>{% endif %}
        <p class="raw-label">Raw Event Data</p>
        <pre class="raw">{{ block.raw_json }}</pre>
      </div>
      {% endif %}
    {% endfor %}
  {% else %}
    <p class="empty">No evidence attached.</p>
  {% endif %}

  <h2>Notes ({{ notes|length }})</h2>
  {% if notes %}
    {% for n in notes %}
    <div class="note">
      <span>{{ n.text }}</span><br>
      <span class="who">{{ n.author }} · {{ n.timestamp }}</span>
    </div>
    {% endfor %}
  {% else %}
    <p class="empty">No notes.</p>
  {% endif %}

  <h2>Mitigation</h2>
  {% if mitigation %}
    <div class="mit">
      {% for item in mitigation %}
      <p class="mit-item">
        <span class="no">{{ loop.index }}.</span>{{ item.text }}
        {% if item.completed_by or item.completed_at %}
        <span class="done-note">Completed{% if item.completed_by %} by {{ item.completed_by }}{% endif %}{% if item.completed_at %} on {{ item.completed_at }}{% endif %}</span>
        {% endif %}
      </p>
      {% endfor %}
    </div>
  {% else %}
    <p class="empty">No mitigation items recorded yet.</p>
  {% endif %}
</body>
</html>
""", autoescape=True)


def _fmt(ts) -> str:
    if not ts:
        return "—"
    if isinstance(ts, datetime):
        return ts.strftime("%b %d, %Y %H:%M UTC")
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%b %d, %Y %H:%M UTC")
        except ValueError:
            return ts
    return str(ts)


def _snapshot_ts(snap: dict | None, ev: dict) -> datetime | None:
    """Event timestamp as a datetime, falling back to attachment time."""
    raw = (snap or {}).get("timestamp")
    if isinstance(raw, datetime):
        return raw
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            pass
    added = ev.get("added_at")
    return added if isinstance(added, datetime) else None


def _raw_json(snap: dict | None) -> str:
    if not snap:
        return ""
    raw = snap.get("raw")
    if isinstance(raw, dict) and raw:
        return json.dumps(raw, indent=2, default=str)
    if raw:
        return str(raw)
    return json.dumps(snap, indent=2, default=str)


def _evidence_timeline(evidence_docs: list[dict]) -> list[dict]:
    """Chronological evidence blocks; correlated-chain groups get a subheading."""
    rows = []
    for ev in evidence_docs:
        snap = parse_snapshot(ev)
        ts = _snapshot_ts(snap, ev)
        rows.append({
            "_ts": ts or datetime.min,
            "timestamp": _fmt(ts) if ts else _fmt(ev.get("added_at")),
            "source": (snap or {}).get("source", "unknown"),
            "src_class": _src_pill((snap or {}).get("source")),
            "hostname": event_hostname(snap),
            "severity": str((snap or {}).get("event_type") or "").strip(),
            "sev_class": _sev_pill((snap or {}).get("event_type")),
            "risk": event_risk(snap),
            "summary": (snap or {}).get("summary") or (snap or {}).get("raw", {}).get("message", ""),
            "raw_json": _raw_json(snap),
            "chain": ev.get("chain"),
        })
    rows.sort(key=lambda r: r["_ts"])

    blocks = []
    prev_chain = None
    for r in rows:
        chain = r.pop("chain", None)
        key = tuple(chain.values()) if chain else None
        if chain and key != prev_chain:
            blocks.append({
                "type": "head",
                "text": f"{chain['hostname']}, {_fmt_dt(chain['start_time'])} \u2013 {_fmt_dt(chain['end_time'])}",
            })
        prev_chain = key
        r["type"] = "card"
        blocks.append(r)
    return blocks


def _fmt_dt(value) -> str:
    """Format a datetime or ISO string for the chain subheading."""
    if isinstance(value, datetime):
        return _fmt(value)
    try:
        return _fmt(datetime.fromisoformat(str(value)))
    except ValueError:
        return str(value)


def render_incident_pdf(incident: dict, evidence: list, activity_log: list,
                        generated_by: str | None = None) -> bytes:
    """Render one incident report to PDF bytes (WeasyPrint).

    `activity_log` is intentionally not rendered: the Activity Log is a web-UI
    feature; an exported report is meant to be handed to people outside the
    tool. The parameter is kept so the caller's pipeline stays unchanged.
    """
    mitre_tags = mitre_tags_from_evidence(evidence)
    mitigation = incident.get("mitigation") or []
    if not isinstance(mitigation, list):
        mitigation = []
    severity = str(incident.get("severity") or "info").lower()
    notes = [
        {
            "text": str(n.get("text", "")),
            "author": n.get("author") or f"User #{n.get('added_by', '')}",
            "timestamp": _fmt(n.get("added_at")),
        }
        for n in (incident.get("notes") or [])
    ]
    html = _TEMPLATE.render(
        brand=_BRAND,
        muted=_MUTED,
        border=_BORDER,
        text=_TEXT,
        pill_css=_pill_css(_SEVERITY_PILLS, "sev") + "\n  .pill.src-info, .pill.sev-info { background: #F1F5F9; color: #64748B; }\n  " + _pill_css(_SOURCE_PILLS, "src"),
        incident=incident,
        severity=severity,
        severity_class=_sev_pill(severity),
        status=str(incident.get("status", "")).capitalize(),
        created_at=_fmt(incident.get("created_at")),
        updated_at=_fmt(incident.get("updated_at")),
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
        generated_by=generated_by,
        mitre_tags=mitre_tags,
        evidence=_evidence_timeline(evidence),
        evidence_count=len(evidence),
        mitigation=[
            {
                "text": str(i.get("text", "")),
                "completed_by": i.get("completed_by_name") or i.get("completed_by"),
                "completed_at": _fmt(i.get("completed_at")) if i.get("completed_at") else "",
            }
            for i in mitigation
        ],
        notes=notes,
    )
    return HTML(string=html).write_pdf()