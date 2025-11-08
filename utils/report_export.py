# utils/report_export.py
from datetime import datetime
from typing import Any, Dict, List, Tuple

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

try:
    pdfmetrics.registerFont(TTFont("JetBrainsMono", "fonts/JetBrainsMono-Regular.ttf"))
    MONO_FACE = "JetBrainsMono"
except Exception:
    MONO_FACE = "Courier"

def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="TitleXL",
        parent=styles["Title"],
        fontSize=18,
        leading=22,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="H2",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        spaceBefore=10,
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="Mono",
        fontName=MONO_FACE,
        fontSize=9.5,
        leading=12,
    ))
    styles.add(ParagraphStyle(
        name="Body",
        parent=styles["BodyText"],
        fontSize=10.5,
        leading=14,
    ))
    styles.add(ParagraphStyle(
        name="SmallDim",
        parent=styles["BodyText"],
        fontSize=8.5,
        textColor=colors.grey,
    ))
    return styles

def _as_line_ranges(refs: List[Dict[str, Any]]) -> str:
    """
    refs[*].line_numbers might be [start, end] or empty.
    Return a compact string like '12–19; 33–38' or 'n/a'.
    """
    if not refs:
        return "n/a"
    chunks: List[str] = []
    for r in refs:
        ln = r.get("line_numbers") or []
        if isinstance(ln, (list, tuple)) and len(ln) == 2:
            chunks.append(f"{ln[0]}–{ln[1]}")
        elif isinstance(ln, (list, tuple)) and len(ln) == 1:
            chunks.append(f"{ln[0]}")
    return "; ".join(chunks) if chunks else "n/a"

def export_final_report_pdf(
    final_state: Dict[str, Any],
    outfile: str = "outputs/final_report.pdf",
    meta: Dict[str, str] = None
) -> str:
    """
    Build a clean PDF summarizing:
      • Title & metadata
      • Verified gap→evidence linkage (monospace block)
      • Per-gap line citations table
      • Full final report (formatted)
    Returns the output file path.
    """
    styles = _styles()
    doc = SimpleDocTemplate(
        outfile,
        pagesize=A4,
        leftMargin=18*mm,
        rightMargin=18*mm,
        topMargin=16*mm,
        bottomMargin=16*mm,
        title="Policy Gap Analysis – Evidence-Verified Report",
        author=(meta or {}).get("author", "Pipeline"),
        subject="Policy gap analysis with evidence validation",
    )

    story = []

    # --- Header ---
    title = (meta or {}).get("title", "Policy Gap Analysis – Evidence-Verified Report")
    story.append(Paragraph(title, styles["TitleXL"]))
    sub = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  Baseline: {final_state.get('baseline_policy','CIS')}  |  Target: {final_state.get('target_policy','Pan')}"
    story.append(Paragraph(sub, styles["SmallDim"]))
    story.append(Spacer(1, 6))

    if meta:
        who = []
        if meta.get("author"): who.append(f"Author: {meta['author']}")
        if meta.get("org"):    who.append(f"Org: {meta['org']}")
        if meta.get("run_id"): who.append(f"Run ID: {meta['run_id']}")
        if who:
            story.append(Paragraph(" • ".join(who), styles["SmallDim"]))
            story.append(Spacer(1, 6))

    # --- Gap→Evidence Linkage ---
    story.append(Paragraph("Gaps Verified Against Evidence", styles["H2"]))
    linkage = final_state.get("gaps_evidence_link") or "No gap→evidence linkage produced."
    # Render linkage as a mono paragraph (wrapped)
    for line in str(linkage).splitlines() or ["(empty)"]:
        story.append(Paragraph(line.replace(" ", "&nbsp;"), styles["Mono"]))
    story.append(Spacer(1, 10))

    # --- Per-gap line citations table ---
    gaps_struct = final_state.get("policy_gaps_structured", []) or []
    if gaps_struct:
        story.append(Paragraph("Per-Gap Line Citations", styles["H2"]))
        data = [["Gap", "Baseline Line Ranges", "Target Line Ranges"]]
        for g in gaps_struct:
            gap_txt = g.get("gap", "(gap)")
            refs = g.get("refs", {}) or {}
            pa = refs.get("policy_a", []) or []
            pb = refs.get("policy_b", []) or []
            data.append([gap_txt, _as_line_ranges(pa), _as_line_ranges(pb)])

        tbl = Table(data, colWidths=[85*mm, 45*mm, 45*mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#F5F5F5")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.black),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 9.5),
            ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.whitesmoke]),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 10))
    else:
        story.append(Paragraph("No structured per-gap citations found.", styles["Body"]))
        story.append(Spacer(1, 10))

    # --- Policy snippets (optional) ---
    snips = final_state.get("policy_snippets", {}) or {}
    if snips:
        story.append(Paragraph("Captured Policy Snippets (debug view)", styles["H2"]))
        for k, arr in snips.items():
            story.append(Paragraph(f"<b>{k}</b> — {len(arr)} snippet(s)", styles["Body"]))
        story.append(Spacer(1, 6))
        story.append(PageBreak())

    # --- Final narrative report ---
    story.append(Paragraph("Final Report", styles["H2"]))
    final_report = final_state.get("final_report", "No report produced.")
    for para in str(final_report).split("\n\n"):
        story.append(Paragraph(para.strip().replace("\n", "<br/>"), styles["Body"]))
        story.append(Spacer(1, 6))

    doc.build(story)
    return outfile
