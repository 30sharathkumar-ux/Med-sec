"""Generate the exact 2-page RAKSHA Project Brief PDF matching the user's final layout."""
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)

ROOT = Path(__file__).resolve().parent.parent.parent
OUT_PDF = ROOT / "brief" / "PROJECT_BRIEF.pdf"

NAVY = colors.HexColor("#102A43")
BLUE = colors.HexColor("#243B53")
ACCENT = colors.HexColor("#334E68")
SLATE = colors.HexColor("#334155")
MUTED = colors.HexColor("#627D98")
BG_LIGHT = colors.HexColor("#F0F4F8")
BG_CALLOUT = colors.HexColor("#E6EFF6")
BORDER = colors.HexColor("#CBD5E1")
WHITE = colors.white


def _draw_footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(15 * mm, 13 * mm, A4[0] - 15 * mm, 13 * mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(15 * mm, 9 * mm, "RAKSHA \u00b7 Yugaantar DevForge 2026 \u00b7 Track 3: Secret Wards")
    canvas.drawRightString(A4[0] - 15 * mm, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf():
    doc = SimpleDocTemplate(
        str(OUT_PDF),
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=13 * mm,
        bottomMargin=17 * mm,
        title="RAKSHA - Project Brief",
        author="POINT_BLANK",
    )

    styles = getSampleStyleSheet()
    s_title = ParagraphStyle("Title", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=18, leading=21, textColor=NAVY, spaceAfter=2)
    s_sub = ParagraphStyle("Sub", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=ACCENT, spaceAfter=2)
    s_meta = ParagraphStyle("Meta", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=7.8, leading=10, textColor=MUTED, spaceAfter=4)
    s_h2 = ParagraphStyle("H2", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=NAVY, spaceBefore=6, spaceAfter=3)
    s_body = ParagraphStyle("Body", parent=styles["Normal"], fontName="Helvetica", fontSize=8.2, leading=11, textColor=SLATE, spaceAfter=3.5)
    s_bullet = ParagraphStyle("Bullet", parent=s_body, leftIndent=8, firstLineIndent=-6, spaceAfter=2.5)
    s_cell = ParagraphStyle("Cell", parent=styles["Normal"], fontName="Helvetica", fontSize=7.4, leading=9.6, textColor=SLATE)
    s_cell_b = ParagraphStyle("CellB", parent=s_cell, fontName="Helvetica-Bold", textColor=NAVY)

    story = []

    # ==================== PAGE 1 ====================
    story.append(Paragraph("RAKSHA", s_title))
    story.append(Paragraph("OFFLINE MULTILINGUAL MEDICAL DATA PRIVACY FIREWALL", s_sub))
    story.append(Paragraph("Yugaantar DevForge 2026 \u00b7 Track 3: Secret Wards | Adversarial Re-identification Resistance with Clinical-Utility Preservation", s_meta))
    story.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=4))

    story.append(Paragraph("1. The Challenge", s_h2))
    story.append(Paragraph(
        "Secret Wards asks teams to build an <b>offline, CPU-only, LLM-free privacy firewall</b> for synthetic Indian hospital records from four hospital "
        "systems, spanning English, Hindi and Hinglish. The system must remove personal information, preserve medically useful values exactly, link "
        "the same patient across languages/files/hospitals without false merges, and prevent leaks in outputs, logs, temporary files and errors.", s_body
    ))
    story.append(Paragraph(
        "The hidden attacker may combine quasi-identifiers\u2014age, village, PIN, visit date, rare diagnosis and length of stay\u2014with outside population "
        "knowledge. Removing names alone is not sufficient.", s_body
    ))

    story.append(Paragraph("2. RAKSHA's Response to the Six Challenge Traps", s_h2))
    traps = [
        [Paragraph("<b>Track requirement</b>", ParagraphStyle("TH", parent=s_cell_b, textColor=WHITE)),
         Paragraph("<b>RAKSHA design response</b>", ParagraphStyle("TH", parent=s_cell_b, textColor=WHITE))],
        [Paragraph("<b>Language</b> \u2014 English, Hindi, Hinglish; aliases and transliteration", s_cell),
         Paragraph("Script-aware rules, Devanagari\u2013Latin normalization, name patterns and phonetic blocking.", s_cell)],
        [Paragraph("<b>Meaning</b> \u2014 relative vs complaint; doctor vs patient; dose vs identifier", s_cell),
         Paragraph("Context-sensitive clinical shields protect clinician credentials, diagnoses, medicines and dosage expressions.", s_cell)],
        [Paragraph("<b>Fragmented identity</b> \u2014 stable IDs without false merges", s_cell),
         Paragraph("Evidence-based cross-file linkage, keyed HMAC pseudonyms and null assignment when evidence is insufficient.", s_cell)],
        [Paragraph("<b>Re-identification</b> \u2014 quasi-identifiers and attacker knowledge", s_cell),
         Paragraph("Per-patient date shifts, age bands, district-level generalization and PIN-prefix masking reduce linkage clues.", s_cell)],
        [Paragraph("<b>Clinical integrity</b> \u2014 preserve medical values and stay intervals", s_cell),
         Paragraph("Practice-set medical checks; patient-level date shift is designed to preserve interval lengths.", s_cell)],
        [Paragraph("<b>Hidden leakage</b> \u2014 filenames, headers, keys, metadata, attachments", s_cell),
         Paragraph("Supported hidden surfaces are scanned/sanitized; unsafe inputs are quarantined.", s_cell)],
    ]
    t_traps = Table(traps, colWidths=[170, 338])
    t_traps.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, BG_LIGHT]),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(t_traps)

    story.append(Paragraph("3. Three-Layer Architecture", s_h2))
    arch = [
        [Paragraph("<b>SENTINEL</b>", ParagraphStyle("AH", parent=s_cell_b, textColor=WHITE)),
         Paragraph("<b>IDENTITY GUARD</b>", ParagraphStyle("AH", parent=s_cell_b, textColor=WHITE)),
         Paragraph("<b>VAULT</b>", ParagraphStyle("AH", parent=s_cell_b, textColor=WHITE))],
        [Paragraph("Ingestion, encoding/format checks, depth and payload guards, fail-closed quarantine.", s_cell),
         Paragraph("Multilingual PII/context detection, evidence extraction and conservative patient linkage.", s_cell),
         Paragraph("Domain-separated HMAC pseudonyms, date shifts, quasi-identifier generalization and reporting.", s_cell)],
    ]
    t_arch = Table(arch, colWidths=[169, 170, 169])
    t_arch.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("BACKGROUND", (0, 1), (-1, 1), BG_LIGHT),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
    ]))
    story.append(t_arch)
    story.append(Spacer(1, 3))
    story.append(Paragraph("<b>Output contract:</b> <font name='Courier'>sanitized/ + report.json + records.jsonl</font>. Unsupported/unsafe inputs are quarantined; ambiguous identity is <font name='Courier'>null</font>.", s_body))

    story.append(Paragraph("4. What Makes RAKSHA Different", s_h2))
    story.append(Paragraph(
        "RAKSHA treats privacy as a combined detection, identity and attacker-resistance problem\u2014not a name-redaction task. Its differentiators are "
        "multilingual/contextual extraction, conservative identity resolution, domain-separated keyed pseudonymization, hidden-channel hygiene and an "
        "explicit privacy\u2013utility balance.", s_body
    ))

    story.append(Paragraph("5. Practice-Set Validation Snapshot", s_h2))
    snap = [
        [Paragraph("<b>Metric</b>", ParagraphStyle("SH", parent=s_cell_b, textColor=WHITE)),
         Paragraph("<b>Reported result</b>", ParagraphStyle("SH", parent=s_cell_b, textColor=WHITE))],
        [Paragraph("PII leakage", s_cell), Paragraph("0 / 3,230 (0.0%)", s_cell)],
        [Paragraph("Canary leakage", s_cell), Paragraph("0 / 4", s_cell)],
        [Paragraph("Medical values preserved", s_cell), Paragraph("4,855 / 4,855 (100.0%)", s_cell)],
        [Paragraph("Identity linkage", s_cell), Paragraph("Precision 1.00 \u00b7 Recall 1.00 \u00b7 F0.5 1.00 \u00b7 0 wrong merges", s_cell)],
        [Paragraph("File accounting / raw copies", s_cell), Paragraph("192 sanitized + 8 quarantined = 200 \u00b7 0 raw copies", s_cell)],
        [Paragraph("Contract / pre-submit audit", s_cell), Paragraph("CONTRACT OK \u00b7 READY TO SUBMIT", s_cell)],
        [Paragraph("Tests / runtime / memory", s_cell), Paragraph("199 passed \u00b7 6.64 s \u00b7 31.0 MB peak RSS", s_cell)],
    ]
    t_snap = Table(snap, colWidths=[170, 338])
    t_snap.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, BG_LIGHT]),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(t_snap)
    story.append(Spacer(1, 3))
    callout = Table(
        [[Paragraph("<b>Scope: These are repository-reported results on the 200-file practice set, not hidden-dataset or official attacker scores.</b>", ParagraphStyle("C", parent=s_cell, textColor=NAVY))]],
        colWidths=[508],
    )
    callout.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BG_CALLOUT),
        ("BOX", (0, 0), (-1, -1), 0.5, ACCENT),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(callout)

    story.append(PageBreak())

    # ==================== PAGE 2 ====================
    story.append(Paragraph("RAKSHA | PROJECT BRIEF", ParagraphStyle("P2T", parent=s_title, fontSize=16, leading=19)))
    story.append(Paragraph("PRIVACY, UTILITY, SECURITY & EVALUATION ALIGNMENT", s_sub))
    story.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=5))

    story.append(Paragraph("6. Privacy\u2013Utility Trade-off", s_h2))
    story.append(Paragraph(
        "RAKSHA reduces the precision of selected quasi-identifiers while retaining clinical values. Reported transformations include five-year age "
        "bands, village-to-district generalization, three-digit PIN prefixes and per-patient date shifts. A consistent patient-level shift is intended to "
        "preserve encounter intervals and exact hospital length-of-stay durations.", s_body
    ))
    story.append(Paragraph(
        "This trades some demographic and geographic granularity for a smaller linkage surface. Over-generalization harms research utility, while "
        "retaining rare combinations can expose patients. The balance must be measured against the organizer's attacker and utility checks.", s_body
    ))

    story.append(Paragraph("7. Security Design", s_h2))
    story.append(Paragraph("\u2022 <b>Secret handling:</b> <font name='Courier'>RAKSHA_SECRET</font> is supplied through the environment and must not be committed, logged or written to output.", s_bullet))
    story.append(Paragraph("\u2022 <b>Purpose separation:</b> HMAC-SHA256 domains distinguish pseudonym, date-shift and filename-tag derivations.", s_bullet))
    story.append(Paragraph("\u2022 <b>Side-channel hygiene:</b> do not expose raw identifiers in logs, errors, reports or temporary artifacts.", s_bullet))
    story.append(Paragraph("\u2022 <b>Fail-safe behavior:</b> malformed or unsupported inputs are quarantined rather than copied as sanitized.", s_bullet))
    story.append(Paragraph("\u2022 <b>Runtime constraints:</b> offline, CPU-only and LLM-free; organizer limit is 2 CPUs, 4 GB RAM and 15 minutes.", s_bullet))

    story.append(Paragraph("8. Honest Limitations & Unverified Items", s_h2))
    story.append(Paragraph("\u2022 <b>Official attacker evaluation:</b> the organizer's <font name='Courier'>raksha_eval</font> runner is not bundled in the repository. Exact official A1\u2013A7 attack probabilities and B\u00b3 F1 are <b>not evaluated locally</b>.", s_bullet))
    story.append(Paragraph("\u2022 <b>Adaptive k-anonymity:</b> helper/risk-analysis code exists, but record-level adaptive age widening/PIN suppression is <b>not actively enforced</b> in the current sanitized export.", s_bullet))
    story.append(Paragraph("\u2022 <b>Generalization:</b> unseen regional names, unfamiliar identifiers and new file structures may reduce recall or linkage quality on hidden datasets.", s_bullet))
    story.append(Paragraph("\u2022 <b>Practice versus hidden data:</b> practice-set results do not guarantee performance on the three hidden evaluation datasets.", s_bullet))

    story.append(Paragraph("9. Alignment with the Scoring Rubric", s_h2))
    rubric = [
        [Paragraph("<b>Scoring category</b>", ParagraphStyle("RH", parent=s_cell_b, textColor=WHITE)),
         Paragraph("<b>Weight</b>", ParagraphStyle("RH", parent=s_cell_b, textColor=WHITE)),
         Paragraph("<b>RAKSHA focus</b>", ParagraphStyle("RH", parent=s_cell_b, textColor=WHITE))],
        [Paragraph("Privacy against attacks", s_cell), Paragraph("25", s_cell), Paragraph("Reduce direct and quasi-identifier linkage; official attack scores pending.", s_cell)],
        [Paragraph("Personal-data detection", s_cell), Paragraph("20", s_cell), Paragraph("Multilingual content and hidden-surface detection with context safeguards.", s_cell)],
        [Paragraph("Medical-data preservation", s_cell), Paragraph("20", s_cell), Paragraph("Preserve medicines, doses, vitals, labs, diagnoses and stay lengths.", s_cell)],
        [Paragraph("Patient identity consistency", s_cell), Paragraph("15", s_cell), Paragraph("Stable pseudonyms and conservative linkage; avoid false merges.", s_cell)],
        [Paragraph("Output quality & validity", s_cell), Paragraph("10", s_cell), Paragraph("Required outputs, valid formats, truthful reports and quarantine.", s_cell)],
        [Paragraph("Speed & reliability", s_cell), Paragraph("10", s_cell), Paragraph("Deterministic execution, runtime, memory and repeatability.", s_cell)],
    ]
    t_rubric = Table(rubric, colWidths=[125, 45, 338])
    t_rubric.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, BG_LIGHT]),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(t_rubric)

    story.append(Paragraph("10. Closing Position", s_h2))
    story.append(Paragraph(
        "RAKSHA is built around the central Secret Wards requirement: <b>protect patient privacy without compromising the accuracy, integrity or "
        "medical usefulness of healthcare data</b>. Its proposition is adversarial re-identification resistance with clinical-utility preservation, supported by "
        "practice-set checks and transparent disclosure of what remains unverified.", s_body
    ))
    story.append(Paragraph("<b>Repository:</b> github.com/30sharathkumar-ux/Med-sec<br/><b>Track:</b> Yugaantar DevForge 2026 \u00b7 Track 3: Secret Wards", s_body))

    doc.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)


if __name__ == "__main__":
    build_pdf()
    from pypdf import PdfReader
    reader = PdfReader(str(OUT_PDF))
    print(f"Generated {OUT_PDF} with {len(reader.pages)} page(s)")
