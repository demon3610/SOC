"""Server-side PDF report generation for incidents (ReportLab).

Layout follows the on-page incident structure so the exported report never
carries browser print artifacts (URL, timestamp, page counters in margins
are composed here as designed content / footer instead).
"""

from io import BytesIO
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.pdfgen import canvas as pdfcanvas

from app.services.incident_metrics import event_ip, event_os, event_risk, parse_snapshot

MARGIN = 18 * mm
BRAND = "#1D4ED8"
BORDER = "#CBD5E1"
MUTED = "#64748B"
TEXT = "#0F172A"

_styles = getSampleStyleSheet()
H1 = ParagraphStyle("RptH1", parent=_styles["Title"], fontSize=20, leading=24, textColor=TEXT, spaceAfter=2)
BRAND_P = ParagraphStyle("RptBrand", parent=_styles["Normal"], fontSize=9, textColor=BRAND, spaceAfter=10)
H2 = ParagraphStyle("RptH2", parent=_styles["Heading2"], fontSize=12, leading=15, textColor=BRAND, spaceBefore=10, spaceAfter=4)
BODY = ParagraphStyle("RptBody", parent=_styles["BodyText"], fontSize=9.5, leading=13, textColor=TEXT)
META = ParagraphStyle("RptMeta", parent=_styles["BodyText"], fontSize=9, leading=12, textColor=MUTED)
SMALL = ParagraphStyle("RptSmall", parent=_styles["BodyText"], fontSize=8.5, leading=11.5, textColor=TEXT)
MONO = ParagraphStyle("RptMono", parent=_styles["Code"], fontSize=7.5, leading=9.5, textColor="#334155", wordWrap="CJK")
CELL = ParagraphStyle("RptCell", parent=_styles["BodyText"], fontSize=9, leading=11, textColor=TEXT)


def _risk_label(score):
    return f"{score} — high" if score is not None and score >= 70 else (
        f"{score} — medium" if score is not None and score >= 40 else (
            f"{score} — low" if score is not None else "Not captured"
        )
    )


def _key_value_rows(incident: dict, metrics: dict) -> list[list]:
    def _fmt(ts):
        if not ts:
            return "—"
        if isinstance(ts, datetime):
            return ts.strftime("%Y-%m-%d %H:%M UTC")
        return str(ts)

    ips = ", ".join(metrics["affected_ips"]) if metrics["affected_ips"] else "Not captured"
    oses = ", ".join(metrics["os_types"]) if metrics["os_types"] else "Not captured"
    return [
        ["Severity", str(incident.get("severity", "")).capitalize()],
        ["Status", str(incident.get("status", "")).capitalize()],
        ["Risk score", _risk_label(metrics["risk_score"])],
        ["Operating system(s)", oses],
        ["Affected IP(s)", ips],
        ["Created", _fmt(incident.get("created_at"))],
        ["Last updated", _fmt(incident.get("updated_at"))],
    ]


def _evidence_paragraphs(evidence_docs: list[dict]) -> list:
    story = []
    for idx, ev in enumerate(evidence_docs, start=1):
        snap = parse_snapshot(ev)
        parts = [f'<b>Evidence {idx}.</b> <b>{ev.get("source_event_id", "")}</b>']
        ts = ev.get("added_at")
        if isinstance(ts, datetime):
            parts.append(ts.strftime("%Y-%m-%d %H:%M UTC"))
        os_name = event_os(snap)
        ip = event_ip(snap)
        risk = event_risk(snap)
        labels = [f'Source: <b>{snap.get("source", "unknown") if snap else "unknown"}</b>']
        if os_name:
            labels.append(f"OS: {os_name}")
        labels.append(f"IP: {ip or 'Not captured'}")
        labels.append(f"Risk: {risk}")
        story.append(Paragraph(" · ".join(parts), BODY))
        story.append(Paragraph(" · ".join(labels), META))
        summary = (snap or {}).get("summary") or (snap or {}).get("raw", {}).get("message") or ""
        if summary:
            story.append(Paragraph(_escape(summary), SMALL))
        if snap and snap.get("parsed"):
            detail = " · ".join(f"{k}={v}" for k, v in snap["parsed"].items() if v not in (None, ""))[:260]
            if detail:
                story.append(Paragraph(_escape(detail), MONO))
        story.append(Spacer(1, 6))
    return story


def _escape(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class _NumberedCanvas(pdfcanvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []
        self._export_ts = ""

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        page_count = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._footer(page_count)
            super().showPage()
        super().save()

    def _footer(self, page_count: int):
        self.saveState()
        self.setStrokeColor(colors.HexColor(BORDER))
        self.setLineWidth(0.5)
        self.line(MARGIN, 13 * mm, A4[0] - MARGIN, 13 * mm)
        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor(MUTED))
        self.drawString(MARGIN, 9.5 * mm, f"Generated on {self._export_ts} · SOC Platform")
        self.drawRightString(A4[0] - MARGIN, 9.5 * mm, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


def build_incident_pdf(incident: dict, evidence_docs: list[dict], metrics: dict,
                       generated_by: str | None, now: datetime | None = None) -> BytesIO:
    now = now or datetime.now()
    export_ts = now.strftime("%Y-%m-%d %H:%M UTC")
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN, bottomMargin=20 * mm,
        title=f"Incident {incident.get('id', '')} Report",
        author="SOC Platform",
    )

    story = []
    story.append(Paragraph("SOC Platform", BRAND_P))
    story.append(Paragraph(f"<b>Incident #{incident.get('id', '')}</b> — {_escape(incident.get('title') or 'Untitled incident')}", H1))
    story.append(Paragraph(
        f"Export generated on {export_ts} · Generated by {_escape(generated_by or 'SOC user')}", META))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Summary", H2))
    table = Table(_key_value_rows(incident, metrics), colWidths=[38 * mm, A4[0] - 2 * MARGIN - 38 * mm])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#F1F5F9")]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor(BORDER)),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(table)

    story.append(Paragraph("Description", H2))
    desc = incident.get("description")
    story.append(Paragraph(_escape(desc) if desc and str(desc).strip() else "No description provided.", BODY))

    story.append(Paragraph(f"Evidence Timeline ({len(evidence_docs)})", H2))
    if evidence_docs:
        story.extend(_evidence_paragraphs(evidence_docs))
    else:
        story.append(Paragraph("No evidence attached.", BODY))

    story.append(Paragraph("Mitigation", H2))
    mitigation = incident.get("mitigation")
    story.append(Paragraph(
        _escape(mitigation) if mitigation and str(mitigation).strip() else "No mitigation recorded yet.", BODY))

    notes = incident.get("notes") or []
    story.append(Paragraph(f"Notes ({len(notes)})", H2))
    if notes:
        for n in notes:
            added = n.get("added_at")
            stamp = added.strftime("%Y-%m-%d %H:%M UTC") if isinstance(added, datetime) else ""
            story.append(KeepTogether([
                Paragraph(f"{_escape(str(n.get('text', '')))}", SMALL),
                Paragraph(f"<font color='#64748B'>{stamp}</font>", META),
                Spacer(1, 4),
            ]))
    else:
        story.append(Paragraph("No notes.", BODY))

    canvas = _NumberedCanvas
    def _canvas_factory(filename, **kw):
        c = _NumberedCanvas(filename, **kw)
        c._export_ts = export_ts
        return c
    doc.build(story, canvasmaker=_canvas_factory)
    buf.seek(0)
    return buf