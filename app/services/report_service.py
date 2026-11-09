"""
Incident reports in PDF and DOCX.

Both formats are built from the same content (ReportContent), so they always
say the same thing: a cover block with the key facts, the summary, the AI
triage and the analyst's decision, alerts, indicators of compromise, next
steps and the timeline.

Everything that came from an alert (titles, descriptions, IOC values, the
AI's reasoning) may have been written by an attacker. ReportLab Paragraphs
parse markup, so all of it is escaped before it reaches a Paragraph.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import BytesIO
from xml.sax.saxutils import escape  # ReportLab Paragraphs parse markup: alert text must be escaped

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas as pdf_canvas
from reportlab.platypus import (
    CondPageBreak,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.config import get_settings
from app.models import Incident

VERDICT_LABELS = {"true_positive": "Real attack", "false_positive": "False alarm",
                  "needs_investigation": "Needs an analyst"}

# One palette for both formats
INK = "#0f172a"          # headings, header bar
TEXT = "#1e293b"
MUTED = "#64748b"
RULE = "#e2e8f0"
SHADE = "#f1f5f9"
ACCENT = "#1d4ed8"
WARNING = "#a16207"
SEVERITY_COLORS = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207", "low": "#1d4ed8"}
STATUS_COLORS = {"new": "#475569", "investigating": "#7c3aed", "contained": "#c2410c",
                 "resolved": "#15803d", "closed": "#334155"}
VERDICT_COLORS = {"true_positive": "#b91c1c", "false_positive": "#15803d", "needs_investigation": "#a16207"}


def ai_triage_lines(incident: Incident) -> list[tuple[str, str]] | None:
    """The AI suggestion as (label, text) rows, or None if there is none."""
    t = incident.triage
    if not t or t.status != "done":
        return None
    decision = f"{t.decision} by {t.decided_by}" if t.decision else "not yet decided by an analyst"
    rows = [
        ("Suggestion", f"{VERDICT_LABELS.get(t.verdict, t.verdict)}, {t.severity} severity"
                       + (f", {round(t.confidence * 100)}% confident" if t.confidence is not None else "")),
        ("Model", f"{t.model} ({t.mode} mode)"),
        ("Analyst decision", decision),
        ("Reasoning", t.reasoning or ""),
    ]
    if t.next_steps:
        rows.append(("Next steps", "; ".join(t.next_steps)))
    if t.evidence:
        rows.append(("Records cited", ", ".join(t.evidence)))
    if t.injection_suspected:
        rows.append(("Warning", "Possible prompt injection: the alert contains text addressed to the AI"))
    for override in t.overrides or []:
        rows.append(("Guard", override))
    return rows


# ── Content shared by both formats ──────────────────────────────────

def _when(value) -> str:
    return value.strftime("%d %b %Y, %H:%M UTC") if value else "—"


def _enrichment_summary(ioc) -> str:
    if not ioc.enrichment_data:
        return "Not enriched"
    try:
        data = json.loads(ioc.enrichment_data)
    except (ValueError, TypeError):
        return "Unreadable enrichment data"
    parts = []
    if isinstance(data.get("virustotal"), dict):
        parts.append(f"VirusTotal: {data['virustotal'].get('malicious', 0)} engines flag it")
    if isinstance(data.get("abuseipdb"), dict):
        parts.append(f"AbuseIPDB: {data['abuseipdb'].get('abuse_confidence_score', 0)}% abuse confidence")
    if isinstance(data.get("geolocation"), dict) and data["geolocation"].get("country"):
        parts.append(str(data["geolocation"]["country"]))
    return " · ".join(parts) if parts else "Enriched, no findings"


@dataclass
class ReportContent:
    incident_id: int
    title: str
    severity: str
    status: str
    summary: str
    facts: list[tuple[str, str]]
    generated: str
    version: str
    triage: dict | None = None
    alerts: list[tuple[str, str, str]] = field(default_factory=list)        # source, title, received
    iocs: list[tuple[str, str, str, str]] = field(default_factory=list)     # type, value, verdict, enrichment
    next_steps: list[str] = field(default_factory=list)
    timeline: list[tuple[str, str, str]] = field(default_factory=list)      # time, actor, event


def build_content(incident: Incident) -> ReportContent:
    t = incident.triage
    triage = None
    if t and t.status == "done":
        triage = {
            "verdict": t.verdict,
            "label": VERDICT_LABELS.get(t.verdict, t.verdict or ""),
            "severity": t.severity or "",
            "confidence": f"{round(t.confidence * 100)}%" if t.confidence is not None else "—",
            "model": f"{t.model} · {t.mode} mode",
            "decision": f"{t.decision.capitalize()} by {t.decided_by}" if t.decision else "Awaiting an analyst's decision",
            "reasoning": t.reasoning or "",
            "evidence": ", ".join(t.evidence or []) or "None",
            "injection": bool(t.injection_suspected),
            "guards": list(t.overrides or []),
        }
    malicious = sum(1 for ioc in incident.iocs if ioc.is_malicious)
    facts = [
        ("Severity", incident.severity.value.capitalize()),
        ("Status", incident.status.value.capitalize()),
        ("Opened", _when(incident.created_at)),
        ("Last updated", _when(incident.updated_at or incident.created_at)),
        ("Alerts", str(len(incident.alerts))),
        ("Indicators", f"{len(incident.iocs)} ({malicious} malicious)"),
        ("AI suggestion", f"{triage['label']} ({triage['confidence']})" if triage else "Not triaged"),
        ("Analyst decision", (t.decision.capitalize() if t.decision else "Pending") if triage else "—"),
    ]
    return ReportContent(
        incident_id=incident.id,
        title=incident.title,
        severity=incident.severity.value,
        status=incident.status.value,
        summary=incident.description or "No description was recorded for this incident.",
        facts=facts,
        generated=datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC"),
        version=get_settings().APP_VERSION,
        triage=triage,
        alerts=[(a.source.upper(), a.title, _when(a.created_at)) for a in incident.alerts],
        iocs=[(ioc.type.value.upper(), ioc.value, "Malicious" if ioc.is_malicious else "Not flagged",
               _enrichment_summary(ioc)) for ioc in incident.iocs],
        next_steps=list(t.next_steps or []) if triage else [],
        timeline=[(a.created_at.strftime("%d %b %H:%M"), a.performed_by or "system", a.description)
                  for a in incident.actions],
    )


# ── PDF ─────────────────────────────────────────────────────────────

def _styles() -> dict:
    def style(name, **kw):
        base = {"fontName": "Helvetica", "fontSize": 9.5, "leading": 13.5, "textColor": colors.HexColor(TEXT)}
        return ParagraphStyle(name, **{**base, **kw})
    bold = "Helvetica-Bold"
    return {
        "body": style("body"),
        "small": style("small", fontSize=8.5, leading=11.5),
        "muted": style("muted", fontSize=8, leading=10.5, textColor=colors.HexColor(MUTED)),
        "label": style("label", fontName=bold, fontSize=7, leading=9, textColor=colors.HexColor(MUTED)),
        "value": style("value", fontName=bold, fontSize=10, leading=13),
        "kicker": style("kicker", fontName=bold, fontSize=8, leading=10, textColor=colors.HexColor(ACCENT)),
        "title": style("title", fontName=bold, fontSize=19, leading=24, textColor=colors.HexColor(INK)),
        "h2": style("h2", fontName=bold, fontSize=12, leading=16, textColor=colors.HexColor(INK)),
        "cell": style("cell", fontSize=8.5, leading=11),
        "mono": style("mono", fontName="Courier", fontSize=8, leading=10.5),
        "head": style("head", fontName=bold, fontSize=7.5, leading=10, textColor=colors.HexColor(MUTED)),
    }


def _pill(text: str, color: str, s) -> Table:
    label = text.upper()
    pill = Table([[Paragraph(f'<font color="white"><b>{escape(label)}</b></font>', s["small"])]],
                 colWidths=[stringWidth(label, "Helvetica-Bold", 8.5) + 15])
    pill.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(color)),
        ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("ROUNDEDCORNERS", [3, 3, 3, 3]),
    ]))
    return pill


def _section(number: int, title: str, s) -> Table:
    """A numbered section heading with a rule under it."""
    heading = Table([[Paragraph(f'<font color="{ACCENT}">{number:02d}</font>&nbsp;&nbsp;{escape(title)}', s["h2"])]],
                    colWidths=["100%"])
    heading.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 0.8, colors.HexColor(INK)),
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 14), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return heading


def _data_table(header: list[str], rows: list[list], widths: list[float], s) -> Table:
    data = [[Paragraph(escape(h.upper()), s["head"]) for h in header]] + rows
    table = Table(data, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(SHADE)),
        ("LINEBELOW", (0, 0), (-1, 0), 0.6, colors.HexColor(MUTED)),
        ("LINEBELOW", (0, 1), (-1, -1), 0.4, colors.HexColor(RULE)),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


class _ReportCanvas(pdf_canvas.Canvas):
    """Draws the header bar and a 'page X of Y' footer once the page count is known."""

    def __init__(self, *args, content: ReportContent, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved, self._content = [], content

    def showPage(self):  # noqa: N802 - ReportLab API
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved)
        for state in self._saved:
            self.__dict__.update(state)
            self._decorate(total)
            super().showPage()
        super().save()

    def _decorate(self, total: int):
        width, height = A4
        c = self._content
        self.setFillColor(colors.HexColor(INK))
        self.rect(0, height - 16 * mm, width, 16 * mm, stroke=0, fill=1)
        self.setFillColor(colors.HexColor(SEVERITY_COLORS.get(c.severity, ACCENT)))
        self.rect(0, height - 17.2 * mm, width, 1.2 * mm, stroke=0, fill=1)
        self.setFillColor(colors.white)
        self.setFont("Helvetica-Bold", 11)
        self.drawString(18 * mm, height - 10 * mm, "SOAR-Lite")
        self.setFont("Helvetica", 8.5)
        self.drawString(41 * mm, height - 10 * mm, "Security Incident Report")
        self.drawRightString(width - 18 * mm, height - 10 * mm, f"INC-{c.incident_id:05d}  ·  CONFIDENTIAL")
        self.setStrokeColor(colors.HexColor(RULE))
        self.setLineWidth(0.5)
        self.line(18 * mm, 14 * mm, width - 18 * mm, 14 * mm)
        self.setFillColor(colors.HexColor(MUTED))
        self.setFont("Helvetica", 7.5)
        self.drawString(18 * mm, 9.5 * mm, f"Generated {c.generated} by SOAR-Lite v{c.version}. Internal use only.")
        self.drawRightString(width - 18 * mm, 9.5 * mm, f"Page {self._pageNumber} of {total}")


def _pdf_elements(c: ReportContent, s) -> list:
    width = A4[0] - 36 * mm
    out = [Spacer(1, 4 * mm), Paragraph(f"INCIDENT INC-{c.incident_id:05d}", s["kicker"]), Spacer(1, 2 * mm),
           Paragraph(escape(c.title), s["title"]), Spacer(1, 3 * mm)]

    pills = [_pill(f"{c.severity} severity", SEVERITY_COLORS.get(c.severity, ACCENT), s),
             _pill(c.status, STATUS_COLORS.get(c.status, MUTED), s)]
    if c.triage:
        pills.append(_pill(f"AI: {c.triage['label']}", VERDICT_COLORS.get(c.triage["verdict"], MUTED), s))
    row = Table([pills], colWidths=[p._colWidths[0] + 6 for p in pills], hAlign="LEFT")
    row.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 6)]))
    out += [row, Spacer(1, 5 * mm)]

    # Key facts: 4 columns × 2 rows, label above value
    cells = [[Paragraph(escape(label.upper()), s["label"]), Paragraph(escape(value), s["value"])] for label, value in c.facts]
    facts = Table([cells[:4], cells[4:8]], colWidths=[width / 4] * 4)
    facts.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(SHADE)),
        ("LINEBELOW", (0, 0), (-1, 0), 1, colors.white),
        ("LINEAFTER", (0, 0), (-2, -1), 1, colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 9), ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    out.append(facts)

    n = 1
    out += [_section(n, "Summary", s), Spacer(1, 2 * mm), Paragraph(escape(c.summary), s["body"])]

    if c.triage:
        n += 1
        t = c.triage
        color = VERDICT_COLORS.get(t["verdict"], MUTED)
        lines = [
            Paragraph(f'<font color="{color}"><b>{escape(t["label"])}</b></font>'
                      f' · {escape(t["severity"])} severity · {escape(t["confidence"])} confidence', s["value"]),
            Spacer(1, 2 * mm), Paragraph(escape(t["reasoning"]), s["body"]), Spacer(1, 2 * mm),
            Paragraph(f"<b>Records cited:</b> {escape(t['evidence'])}", s["small"]),
            Paragraph(f"<b>Model:</b> {escape(t['model'])}", s["small"]),
            Paragraph(f"<b>Analyst decision:</b> {escape(t['decision'])}", s["small"]),
        ]
        for guard in t["guards"]:
            lines.append(Paragraph(f'<font color="{ACCENT}"><b>Guard:</b></font> {escape(guard)}', s["small"]))
        if t["injection"]:
            lines.append(Paragraph(f'<font color="{WARNING}"><b>Warning:</b> text in this alert tries to instruct the AI '
                                   "(possible prompt injection). Treat it as a sign the sender is malicious.</font>",
                                   s["small"]))
        box = Table([[lines]], colWidths=[width])
        box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fafafa")),
            ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor(RULE)),
            ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor(color)),
            ("LEFTPADDING", (0, 0), (-1, -1), 11), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ]))
        out.append(KeepTogether([
            _section(n, "AI triage", s), Spacer(1, 2 * mm),
            Paragraph("A suggestion from a language model. It changes nothing on its own; "
                      "the analyst's decision is recorded with it.", s["muted"]),
            Spacer(1, 2 * mm), box]))

    if c.alerts:
        n += 1
        rows = [[Paragraph(escape(v), s["cell"]) for v in alert] for alert in c.alerts]
        out += [CondPageBreak(40 * mm), _section(n, "Alerts", s), Spacer(1, 2 * mm),
                _data_table(["Source", "Alert", "Received"], rows, [0.21 * width, 0.55 * width, 0.24 * width], s)]

    if c.iocs:
        n += 1
        rows = []
        for kind, value, verdict, enrichment in c.iocs:
            color = SEVERITY_COLORS["critical"] if verdict == "Malicious" else MUTED
            rows.append([Paragraph(escape(kind), s["cell"]), Paragraph(escape(value), s["mono"]),
                         Paragraph(f'<font color="{color}"><b>{escape(verdict)}</b></font>', s["cell"]),
                         Paragraph(escape(enrichment), s["cell"])])
        out += [CondPageBreak(40 * mm), _section(n, "Indicators of compromise", s), Spacer(1, 2 * mm),
                _data_table(["Type", "Value", "Verdict", "Enrichment"], rows,
                            [0.11 * width, 0.4 * width, 0.14 * width, 0.35 * width], s)]

    if c.next_steps:
        n += 1
        steps = [[Paragraph(f'<font color="{ACCENT}"><b>{i}</b></font>', s["body"]), Paragraph(escape(step), s["body"])]
                 for i, step in enumerate(c.next_steps, 1)]
        table = Table(steps, colWidths=[8 * mm, width - 8 * mm])
        table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                   ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
        out += [CondPageBreak(35 * mm), _section(n, "Recommended next steps", s), Spacer(1, 2 * mm),
                Paragraph("Suggested by the AI triage; check each one before acting.", s["muted"]), Spacer(1, 2 * mm), table]

    if c.timeline:
        n += 1
        rows = [[Paragraph(escape(v), s["cell"]) for v in entry] for entry in c.timeline]
        out += [CondPageBreak(40 * mm), _section(n, "Timeline", s), Spacer(1, 2 * mm),
                _data_table(["Time (UTC)", "By", "Event"], rows, [0.17 * width, 0.17 * width, 0.66 * width], s)]
    return out


# ── DOCX ────────────────────────────────────────────────────────────

def _rgb(hex_color: str) -> RGBColor:
    return RGBColor.from_string(hex_color.lstrip("#").upper())


def _shade(element_pr, hex_color: str):
    shading = OxmlElement("w:shd")
    shading.set(qn("w:val"), "clear")
    shading.set(qn("w:color"), "auto")
    shading.set(qn("w:fill"), hex_color.lstrip("#"))
    element_pr.append(shading)


def _borders(table, inside: str | None = RULE, outside: str | None = None, left: tuple[str, int] | None = None):
    """Light horizontal rules only; optionally a thick coloured left edge for a call-out box."""
    borders = OxmlElement("w:tblBorders")
    for edge, color in (("top", outside), ("left", None), ("bottom", outside), ("right", None),
                        ("insideH", inside), ("insideV", None)):
        element = OxmlElement(f"w:{edge}")
        if edge == "left" and left:
            color, size = left
        else:
            size = 4
        if color:
            element.set(qn("w:val"), "single")
            element.set(qn("w:sz"), str(size))
            element.set(qn("w:color"), color.lstrip("#"))
        else:
            element.set(qn("w:val"), "nil")
        borders.append(element)
    table._tbl.tblPr.append(borders)


def _field(run, instruction: str):
    """A Word field such as PAGE or NUMPAGES."""
    begin, text, end = OxmlElement("w:fldChar"), OxmlElement("w:instrText"), OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    text.set(qn("xml:space"), "preserve")
    text.text = instruction
    end.set(qn("w:fldCharType"), "end")
    for element in (begin, text, end):
        run._r.append(element)


def _text(paragraph, text: str, size: float | None = None, bold=False, color: str | None = None, font: str | None = None):
    run = paragraph.add_run(text)
    run.bold = bold
    if size:
        run.font.size = Pt(size)
    if color:
        run.font.color.rgb = _rgb(color)
    if font:
        run.font.name = font
    return run


def _docx_heading(doc, number: int, title: str):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(16)
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.keep_with_next = True
    _text(p, f"{number:02d}   ", 12, True, ACCENT)
    _text(p, title, 12, True, INK)
    border, line = OxmlElement("w:pBdr"), OxmlElement("w:bottom")
    for key, value in (("val", "single"), ("sz", "8"), ("space", "2"), ("color", INK.lstrip("#"))):
        line.set(qn(f"w:{key}"), value)
    border.append(line)
    p._p.get_or_add_pPr().append(border)


def _docx_table(doc, header: list[str], rows: list[list[str]], widths_cm: list[float],
                mono_col: int | None = None, highlight: dict | None = None):
    table = doc.add_table(rows=1 + len(rows), cols=len(header))
    table.alignment = WD_TABLE_ALIGNMENT.LEFT
    _borders(table, outside=MUTED)
    for i, title in enumerate(header):
        cell = table.rows[0].cells[i]
        _shade(cell._tc.get_or_add_tcPr(), SHADE)
        _text(cell.paragraphs[0], title.upper(), 7.5, True, MUTED)
    for r, values in enumerate(rows, start=1):
        for i, value in enumerate(values):
            color = (highlight or {}).get((r - 1, i))
            _text(table.rows[r].cells[i].paragraphs[0], value, 8.5, bool(color), color,
                  "Courier New" if i == mono_col else None)
    table.autofit = False
    for i, width in enumerate(widths_cm):
        table.columns[i].width = Cm(width)
        for cell in table.columns[i].cells:
            cell.width = Cm(width)


def _docx(c: ReportContent) -> Document:
    doc = Document()
    section = doc.sections[0]
    section.page_width, section.page_height = Cm(21), Cm(29.7)
    section.left_margin = section.right_margin = Cm(1.9)
    section.top_margin, section.bottom_margin = Cm(2.2), Cm(2)
    normal = doc.styles["Normal"]
    normal.font.name, normal.font.size = "Calibri", Pt(10)
    normal.font.color.rgb = _rgb(TEXT)
    normal.paragraph_format.space_after = Pt(4)
    normal.paragraph_format.line_spacing = 1.15
    small = doc.styles.add_style("Report margin", 1)   # paragraph style for header and footer
    small.base_style = normal
    small.font.size, small.font.color.rgb = Pt(7.5), _rgb(MUTED)
    small.paragraph_format.space_after = Pt(0)
    right_edge = Cm(17.2)

    header = section.header.paragraphs[0]
    header.style = small
    header.paragraph_format.tab_stops.add_tab_stop(right_edge, alignment=2)
    _text(header, "SOAR-Lite", 9, True, INK)
    _text(header, "   Security Incident Report", 8.5, False, MUTED)
    _text(header, f"\tINC-{c.incident_id:05d} · CONFIDENTIAL", 8.5, True, SEVERITY_COLORS.get(c.severity, ACCENT))

    footer = section.footer.paragraphs[0]
    footer.style = small
    footer.paragraph_format.tab_stops.add_tab_stop(right_edge, alignment=2)
    _text(footer, f"Generated {c.generated} by SOAR-Lite v{c.version}. Internal use only.\tPage ", 7.5, False, MUTED)
    _field(_text(footer, "", 7.5, False, MUTED), "PAGE")
    _text(footer, " of ", 7.5, False, MUTED)
    _field(_text(footer, "", 7.5, False, MUTED), "NUMPAGES")

    _text(doc.add_paragraph(), f"INCIDENT INC-{c.incident_id:05d}", 8, True, ACCENT)
    title = doc.add_paragraph()
    title.paragraph_format.space_after = Pt(4)
    _text(title, c.title, 18, True, INK)

    tags = doc.add_paragraph()
    tags.paragraph_format.space_after = Pt(10)
    pills = [(f" {c.severity.upper()} SEVERITY ", SEVERITY_COLORS.get(c.severity, ACCENT)),
             (f" {c.status.upper()} ", STATUS_COLORS.get(c.status, MUTED))]
    if c.triage:
        pills.append((f" AI: {c.triage['label'].upper()} ", VERDICT_COLORS.get(c.triage["verdict"], MUTED)))
    for text, color in pills:
        _shade(_text(tags, text, 8, True, "#ffffff")._r.get_or_add_rPr(), color)
        tags.add_run("   ")

    facts = doc.add_table(rows=2, cols=4)
    _borders(facts, inside="#ffffff")
    for index, (label, value) in enumerate(c.facts):
        cell = facts.rows[index // 4].cells[index % 4]
        _shade(cell._tc.get_or_add_tcPr(), SHADE)
        cell.width = Cm(4.3)
        _text(cell.paragraphs[0], label.upper(), 7, True, MUTED)
        _text(cell.add_paragraph(), value, 10, True, TEXT)

    n = 1
    _docx_heading(doc, n, "Summary")
    doc.add_paragraph(c.summary)

    if c.triage:
        n += 1
        t = c.triage
        color = VERDICT_COLORS.get(t["verdict"], MUTED)
        _docx_heading(doc, n, "AI triage")
        _text(doc.add_paragraph(), "A suggestion from a language model. It changes nothing on its own; "
                                   "the analyst's decision is recorded with it.", 8, False, MUTED)
        box = doc.add_table(rows=1, cols=1)
        _borders(box, inside=None, outside=RULE, left=(color, 24))
        cell = box.rows[0].cells[0]
        _shade(cell._tc.get_or_add_tcPr(), "#fafafa")
        first = cell.paragraphs[0]
        _text(first, t["label"], 11, True, color)
        _text(first, f"  ·  {t['severity']} severity  ·  {t['confidence']} confidence", 10, True, TEXT)
        cell.add_paragraph(t["reasoning"])
        for label, value in (("Records cited", t["evidence"]), ("Model", t["model"]), ("Analyst decision", t["decision"])):
            p = cell.add_paragraph()
            _text(p, f"{label}: ", 8.5, True)
            _text(p, value, 8.5)
        for guard in t["guards"]:
            p = cell.add_paragraph()
            _text(p, "Guard: ", 8.5, True, ACCENT)
            _text(p, guard, 8.5)
        if t["injection"]:
            _text(cell.add_paragraph(), "Warning: text in this alert tries to instruct the AI (possible prompt injection). "
                                        "Treat it as a sign the sender is malicious.", 8.5, True, WARNING)

    if c.alerts:
        n += 1
        _docx_heading(doc, n, "Alerts")
        _docx_table(doc, ["Source", "Alert", "Received"], [list(a) for a in c.alerts], [3.4, 9.6, 4.2])

    if c.iocs:
        n += 1
        _docx_heading(doc, n, "Indicators of compromise")
        flagged = {(i, 2): SEVERITY_COLORS["critical"] for i, ioc in enumerate(c.iocs) if ioc[2] == "Malicious"}
        _docx_table(doc, ["Type", "Value", "Verdict", "Enrichment"], [list(i) for i in c.iocs], [1.8, 7.0, 2.4, 6.0],
                    mono_col=1, highlight=flagged)

    if c.next_steps:
        n += 1
        _docx_heading(doc, n, "Recommended next steps")
        _text(doc.add_paragraph(), "Suggested by the AI triage; check each one before acting.", 8, False, MUTED)
        for i, step in enumerate(c.next_steps, 1):
            p = doc.add_paragraph()
            _text(p, f"{i}   ", 10, True, ACCENT)
            p.add_run(step)

    if c.timeline:
        n += 1
        _docx_heading(doc, n, "Timeline")
        _docx_table(doc, ["Time (UTC)", "By", "Event"], [list(t) for t in c.timeline], [2.8, 2.8, 11.6])
    return doc


class ReportService:
    """Generate incident reports in PDF and DOCX formats."""

    @staticmethod
    def generate_pdf_report(incident: Incident) -> BytesIO:
        content = build_content(incident)
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                                topMargin=24 * mm, bottomMargin=20 * mm,
                                title=f"INC-{content.incident_id:05d} incident report", author="SOAR-Lite")
        doc.build(_pdf_elements(content, _styles()),
                  canvasmaker=lambda *a, **k: _ReportCanvas(*a, content=content, **k))
        buffer.seek(0)
        return buffer

    @staticmethod
    def generate_docx_report(incident: Incident) -> BytesIO:
        buffer = BytesIO()
        _docx(build_content(incident)).save(buffer)
        buffer.seek(0)
        return buffer
