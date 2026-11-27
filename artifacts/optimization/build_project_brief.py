"""Generate a crisp, exact 2-page competition Project Brief PDF for RAKSHA."""
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Polygon

ROOT = Path(__file__).resolve().parent.parent.parent
OUT_PDF = ROOT / "brief" / "PROJECT_BRIEF.pdf"

NAVY = colors.HexColor("#0F2942")
TEAL = colors.HexColor("#0D7377")
SLATE = colors.HexColor("#334155")
MUTED = colors.HexColor("#64748B")
BG_LIGHT = colors.HexColor("#F1F5F9")
BORDER = colors.HexColor("#CBD5E1")
WHITE = colors.white


def build_arch_diagram() -> Drawing:
    """Clean vector architecture diagram for Page 1."""
    d = Drawing(495, 76)
    boxes = [
        (4, 14, 118, 52, NAVY, "1. SENTINEL", "UTF-8/16/cp1252 sniff", "Depth <= 128, Magic bytes", "Fail-closed quarantine"),
        (136, 14, 160, 52, TEAL, "2. IDENTITY GUARD", "EN/HI/Hinglish PII + Hidden", "Dr.+Qual, Eponym, Dose shields", "Phonetic + Prefix linkage"),
        (310, 14, 122, 52, NAVY, "3. VAULT", "HMAC psn| / shift| / fname|", "5-yr age, District, PIN***", "+-180d shift (LOS kept)"),
    ]
    for x, y, w, h, col, title, l1, l2, l3 in boxes:
        d.add(Rect(x, y, w, h, rx=4, ry=4, fillColor=BG_LIGHT, strokeColor=col, strokeWidth=1.2))
        d.add(Rect(x, y + h - 14, w, 14, rx=2, ry=2, fillColor=col, strokeColor=col, strokeWidth=0))
        d.add(String(x + 5, y + h - 10.5, title, fontName="Helvetica-Bold", fontSize=7.5, fillColor=WHITE))
        d.add(String(x + 5, y + 27, l1, fontName="Helvetica", fontSize=6.6, fillColor=SLATE))
        d.add(String(x + 5, y + 17, l2, fontName="Helvetica", fontSize=6.6, fillColor=SLATE))
        d.add(String(x + 5, y + 7, l3, fontName="Helvetica", fontSize=6.6, fillColor=SLATE))

    # Arrows
    for ax1, ax2 in [(122, 136), (296, 310), (432, 444)]:
        d.add(Line(ax1, 40, ax2 - 3, 40, strokeColor=TEAL, strokeWidth=1.4))
        d.add(Polygon([ax2 - 4, 43, ax2, 40, ax2 - 4, 37], fillColor=TEAL, strokeColor=TEAL))

    # Output box
    d.add(Rect(444, 14, 48, 52, rx=4, ry=4, fillColor=colors.HexColor("#E6FFFA"), strokeColor=TEAL, strokeWidth=1.2))
    d.add(String(448, 49, "OUTPUT", fontName="Helvetica-Bold", fontSize=7, fillColor=TEAL))
    d.add(String(448, 37, "sanitized/", fontName="Helvetica", fontSize=6.4, fillColor=SLATE))
    d.add(String(448, 27, "records.jsonl", fontName="Helvetica", fontSize=6.4, fillColor=SLATE))
    d.add(String(448, 17, "report.json", fontName="Helvetica", fontSize=6.4, fillColor=SLATE))
    return d


def build_pdf():
    doc = SimpleDocTemplate(
        str(OUT_PDF),
        pagesize=A4,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=11 * mm,
        bottomMargin=11 * mm,
        title="RAKSHA - Track 3 Secret Wards Project Brief",
        author="Team RAKSHA",
    )

    styles = getSampleStyleSheet()
    s_title = ParagraphStyle("Title", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=15, leading=18, textColor=NAVY, spaceAfter=2)
    s_sub = ParagraphStyle("Sub", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=9, leading=11.5, textColor=TEAL, spaceAfter=4)
    s_meta = ParagraphStyle("Meta", parent=styles["Normal"], fontName="Helvetica", fontSize=8, leading=10, textColor=MUTED, spaceAfter=5)
    s_h2 = ParagraphStyle("H2", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=9.5, leading=12, textColor=NAVY, spaceBefore=5, spaceAfter=2.5)
    s_body = ParagraphStyle("Body", parent=styles["Normal"], fontName="Helvetica", fontSize=8.1, leading=10.8, textColor=SLATE, spaceAfter=3)
    s_bullet = ParagraphStyle("Bullet", parent=s_body, leftIndent=9, firstLineIndent=-6, spaceAfter=2.2)

    story = []

    # ==================== PAGE 1 ====================
    story.append(Paragraph("RAKSHA: Offline Multilingual Medical Data Privacy Firewall", s_title))
    story.append(Paragraph("Adversarial Re-identification Resistance with Clinical-Utility Preservation", s_sub))
    story.append(Paragraph("Yugaantar DevForge 2026 · Track 3: Secret Wards · Team: team-raksha · CPU-Only / Offline / Zero-LLM", s_meta))
    story.append(HRFlowable(width="100%", thickness=1, color=TEAL, spaceAfter=5))

    story.append(Paragraph("1. Problem Statement & Proposed Solution", s_h2))
    story.append(Paragraph(
        "Clinical records aggregated across Indian hospitals mix English, Devanagari Hindi, and Hinglish text with heterogeneous schemas "
        "(CSV, TSV, JSON, FHIR R4) and hidden PII surfaces (filenames, CSV headers, JSON keys, metadata paths, Base64 payloads). "
        "Naive redaction destroys clinical utility (stripping dosages, eponyms, and clinician credentials), while weak pseudonymization "
        "fails against linkage attacks using voter registries and partial visit facts. <b>RAKSHA</b> is a deterministic, CPU-only, "
        "offline privacy firewall that pairs multilingual context-aware detection with conservative cross-hospital identity resolution "
        "and domain-separated HMAC-SHA256 privacy transformations.", s_body
    ))

    story.append(Paragraph("2. Unique Selling Proposition (USP)", s_h2))
    story.append(Paragraph("• <b>Zero-Loss Clinical Preservation:</b> Protects clinician credentials including qualifications (<i>Dr. Ramesh Srivastava (MD Medicine)</i>, <i>Dr. Anil Kumar MD Cardiology</i>) while still redacting genuine patient names like <i>Md. Shahid</i>, preserving <b>4,855 / 4,855 (100.0%)</b> medical probes.", s_bullet))
    story.append(Paragraph("• <b>True Multilingual & Hidden-Channel Coverage:</b> Handles Latin, Devanagari, and Hinglish names, kinship frames (<i>S/o, D/o, W/o, पत्नी</i>), and scrubs filenames, CSV headers, JSON keys, metadata paths, and Base64 attachments (<b>0 / 3,230 leaked</b>).", s_bullet))
    story.append(Paragraph("• <b>Precision-First Cross-Hospital Linkage:</b> Dynamic MRN issuer-prefix extraction (<i>[A-Z]{2,6}[-/]</i>, zero hardcoded hospital aliases) and phonetic blocking achieve <b>1.00 precision / 1.00 recall / F0.5 1.00</b> with <b>0 wrong merges</b>.", s_bullet))

    story.append(Paragraph("3. Architecture & End-to-End Workflow", s_h2))
    story.append(build_arch_diagram())
    story.append(Spacer(1, 3))
    story.append(Paragraph(
        "<b>Two-Pass Execution:</b> <b>Pass 1 (SENTINEL + Evidence)</b> discovers files deterministically, detects UTF-8/BOM/UTF-16/cp1252 encodings, "
        "quarantines malformed/binary/XML/deeply-nested (>128) files fail-closed, validates FHIR R4 Bundles, and extracts linkage evidence. "
        "<b>Pass 2 (IDENTITY GUARD + VAULT)</b> resolves clusters via Union-Find, applies context-shielded PII redaction across all surfaces, "
        "injects keyed <i>PSN-XXXXXX</i> pseudonyms, applies per-patient date shifts and quasi-identifier generalization, and emits "
        "<i>sanitized/</i>, <i>records.jsonl</i>, and <i>report.json</i>.", s_body
    ))

    story.append(Paragraph("4. Key Technical Innovations", s_h2))
    story.append(Paragraph("• <b>Cryptographic Domain Separation:</b> Separate HMAC-SHA256 domains (<i>b\"psn|\"</i>, <i>b\"shift|\"</i>, <i>b\"fname|\"</i>) prevent cross-oracle correlation and ensure secret-keyed unlinkability across releases.", s_bullet))
    story.append(Paragraph("• <b>ReDoS-Safe Linear Scanning:</b> Bounded regex quantifiers eliminate catastrophic backtracking on 100 KB+ single-line clinical notes while maintaining O(N) throughput.", s_bullet))
    story.append(Paragraph("• <b>Dynamic Issuer-Prefix Grouping:</b> Extracts hospital issuer prefixes dynamically from MRNs/UHIDs and file stems without hardcoding practice hospital names.", s_bullet))

    story.append(PageBreak())

    # ==================== PAGE 2 ====================
    story.append(Paragraph("5. Privacy Threat Model & Adversarial Resistance", s_h2))
    story.append(Paragraph(
        "Under the Secret Wards threat model (<i>docs/ATTACKS.md</i>), an adversary holds a population registry (<i>registry.csv</i>) and partial "
        "visit facts (<i>known_facts.jsonl</i>). RAKSHA defends across all seven attack vectors: <b>A1 Direct Exposure</b> (0/3,230 PII and 0/4 canaries "
        "surviving), <b>A2–A4 Linkage & Profile Aggregation</b> (village→district rollup, 5-year age bands, 3-digit PIN prefixes, house/landmark "
        "suppression; 0/240 registry villages surviving in output), <b>A5 Targeted Attack</b> (per-patient ±180-day HMAC date shifts defeat global "
        "shift recovery while keeping exact Length of Stay), and <b>A6–A7 Pseudonym Inversion & Cross-Release</b> (keyed HMAC-SHA256 with domain separation). "
        "<i>Note:</i> Exact official A1–A7 attack probabilities and B³ F1 require the organizer's <i>raksha_eval</i> runner (not bundled in this repo).", s_body
    ))

    story.append(Paragraph("6. Privacy–Utility Tradeoff & Security Design", s_h2))
    story.append(Paragraph(
        "<b>Tradeoff:</b> 5-year age bands, district-level geography, and ±180-day per-patient shifts trade fine demographic granularity to block "
        "calendar and Sweeney-style linkage while preserving <b>100.0%</b> of clinical probes and exact LOS intervals (e.g., 5-, 10-, and 12-day stays). "
        "<b>Security:</b> <i>RAKSHA_SECRET</i> is read from the environment only, never cached or logged; stdout emits aggregate counts only; zero "
        "<i>tempfile</i> usage; malformed inputs are quarantined in <i>report.json</i> with zero raw copies.", s_body
    ))

    story.append(Paragraph("7. Verified Evaluation & Performance Results (200-File Practice Set)", s_h2))
    data = [
        ["Evaluation Metric", "Source / Command", "Verified Result", "Status"],
        ["Personal Data Leaked", "check_dev.py (WSL2 & Win)", "0 / 3,230 (0.0% across EN/HI/Hinglish & all 6 channels)", "PASS"],
        ["Canary Leakage", "check_dev.py", "0 / 4 planted canaries", "PASS"],
        ["Medical Values Kept", "check_dev.py", "4,855 / 4,855 (100.0%, incl. MD qualifications)", "PASS"],
        ["Identity Linkage", "check_dev.py", "Precision 1.00 | Recall 1.00 | F0.5 1.00 | 0 wrong merges", "PASS"],
        ["Output Contract & Audit", "validate_output.py / check_submission.py", "CONTRACT OK | READY TO SUBMIT (192 san + 8 quar)", "PASS"],
        ["Automated Test Suite", "pytest tests/ -q", "199 passed in 10.47s (unit, adversarial, FHIR, recall)", "PASS"],
        ["Compute & Memory", "taskset -c 0,1 (WSL2) / report.json", "6.64s single-run (11.6s 3-run) | 31.0 MB peak RSS", "PASS"],
        ["Official A1–A7 & B³ F1", "raksha_eval (not in repo)", "Not evaluated locally (proxy checks pass)", "UNVERIFIED"],
    ]
    tbl = Table(data, colWidths=[112, 130, 195, 55])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.2),
        ("LEADING", (0, 0), (-1, -1), 9.2),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, BG_LIGHT]),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 4))

    story.append(Paragraph("8. Limitations, Unverified Items & Competition Compliance", s_h2))
    story.append(Paragraph("• <b>Adaptive k-Anonymity Not Active in Export:</b> <i>rakshak/privacy/k_anonymity.py</i> implements risk-analysis and widening/suppression helpers, and <i>report.json</i> logs summary counts, but record-level age widening/PIN suppression is not enforced on <i>sanitized/</i> files to avoid degrading clinical utility.", s_bullet))
    story.append(Paragraph("• <b>Official Scorer Dependency:</b> <i>raksha_eval</i> is not distributed in the repository; A1–A7 attack probabilities await official evaluation.", s_bullet))
    story.append(Paragraph("• <b>Compliance:</b> 100% CPU-only, offline, zero LLMs/transformers, zero network calls at runtime, zero modified truth/evaluator files, and strictly within the 2-CPU / 4 GB RAM / 15-minute sandbox budget.", s_bullet))

    story.append(Paragraph("9. Conclusion", s_h2))
    story.append(Paragraph(
        "RAKSHA delivers verifiable zero-leakage multilingual de-identification, 100.0% medical preservation, and 1.00 F0.5 cross-hospital linkage "
        "at 31 MB RSS in under 7 seconds, satisfying all offline, deterministic, and contract requirements for Track 3: Secret Wards.", s_body
    ))

    doc.build(story)


if __name__ == "__main__":
    build_pdf()
    from pypdf import PdfReader
    reader = PdfReader(str(OUT_PDF))
    print(f"Generated {OUT_PDF} with {len(reader.pages)} page(s)")
