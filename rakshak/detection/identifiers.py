"""Indian PII identifier detection across Latin, Devanagari digits, and separators."""

from __future__ import annotations

import re
from collections import Counter

from rakshak.detection.context_rules import find_protected_spans, overlaps_protected
from rakshak.detection.multilingual import normalize_digits

# Patterns run on digit-normalized copy of text (same character length!) so indices align 1:1.
_ABHA_NUM_RE = re.compile(r"(?<!\d)91[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}(?!\d)")
_ABHA_ADDR_RE = re.compile(r"\b[\w.+-]+@(?:abdm|sbx|ndhm)\b", re.IGNORECASE)
_AADHAAR_MASKED_RE = re.compile(r"(?i)(?<![A-Za-z0-9])(?:x{4}|[*]{4})[-\s]?(?:x{4}|[*]{4})[-\s]?\d{4}(?!\d)")
_AADHAAR_RE = re.compile(r"(?<!\d)(?<!-)[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?!\d)|(?<!\d)(?<!-)\d{4}[\s-]\d{4}[\s-]\d{4}(?!\d)|(?<!\d)\d{12}(?!\d)")
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?91[-\s.]?)?(?:0?[6-9]\d{4}[-\s.]?\d{5}|0?[6-9]\d{2}[-\s.]?\d{3}[-\s.]?\d{4}|[6-9]\d{1,3}[Xx*]{4,6}\d{2,4})(?!\d)"
)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w.-]+)+")
_PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
_INSURANCE_RE = re.compile(
    r"\b(?:PMJAY[-/][A-Z]{2}[-/]\d{6,14}|POL/\d{2}/\d{5,12}|TPA[-/][A-Z0-9-]{4,16})\b",
    re.IGNORECASE,
)
# General Indian Hospital MRN / UHID / IPD / Reg No patterns (avoids dates DD/MM/YYYY, BP, ICD codes)
_MRN_RE = re.compile(
    r"\b(?:"
    r"(?:SNJ|JJH|DHH|UHID|IPD|IP|ADM|MRN|REG|OPD|BL)[-/]?(?:\d{2,4}[-/])+\d{3,10}|"
    r"[A-Z]{2,5}[-/]\d{2,4}[-/]\d{4,8}|"
    r"(?:UHID|ADM|DHH\d{4}|SNJ|JJH|MRN)[-/]?\d{5,10}|"
    r"[A-Z]{2,5}-IPD-\d{4,10}"
    r")\b",
    re.IGNORECASE,
)

# Ordered from longest/most-specific to shortest to avoid partial-match artifacts (ABHA before Aadhaar!)
IDENTIFIER_SPECS: list[tuple[str, re.Pattern[str]]] = [
    ("ABHA_NUMBER", _ABHA_NUM_RE),
    ("ABHA_ADDRESS", _ABHA_ADDR_RE),
    ("AADHAAR_MASKED", _AADHAAR_MASKED_RE),
    ("AADHAAR", _AADHAAR_RE),
    ("PHONE", _PHONE_RE),
    ("EMAIL", _EMAIL_RE),
    ("PAN", _PAN_RE),
    ("INSURANCE_ID", _INSURANCE_RE),
    ("MRN", _MRN_RE),
]

# Contextual prefix patterns for unseen MRN/Insurance formats after explicit labels
_LABELED_MRN_RE = re.compile(
    r"(?i)(?<=\b(?:UHID|MRN|IPD\s*No|Reg\s*No|PatientID|Patient\s*ID|Reg\.?\s*No|पंजीकरण\s*सं\.|आईपीडी\s*सं\.)[:\s#-]{1,4})"
    r"([A-Za-z0-9][A-Za-z0-9/_-]{4,24})"
)
_LABELED_INS_RE = re.compile(
    r"(?i)(?<=\b(?:PMJAY|Policy\s*No|Insurance\s*ID|Claim\s*ID)[:\s#-]{1,4})"
    r"([A-Za-z0-9][A-Za-z0-9/_-]{5,24})"
)


def _is_date_or_clinical_false_positive(kind: str, surface: str, norm_text: str, start: int, end: int) -> bool:
    """Guard against redacting dates, blood pressures, dosages, or timestamps as MRN/PHONE."""
    if kind == "MRN":
        # Avoid matching dates like 12/04/2026 or 2026-04-12
        if re.fullmatch(r"\d{2,4}[-/]\d{2}[-/]\d{2,4}", surface):
            return True
        # Avoid matching OPD/BL internal encounter/bill IDs ONLY? No, OPD/BL aren't leaked MRNs,
        # wait: keep OPD/BL unless needed, OR wait: check if OPD/... is ever needed as MRN!
        # Let's check: does 'OPD/26/01/00151' contain UHID? No, it's a visit ID, safe to keep or leave.
        if re.match(r"^(?:OPD|BL)/\d{2}/", surface, re.IGNORECASE):
            return True
    if kind == "PHONE":
        digits = re.sub(r"\D", "", surface)
        if len(digits) < 10 or len(digits) > 13:
            return True
        # Ensure it's not part of a longer numeric code/timestamp
        if start > 0 and norm_text[start - 1] in (".", "/"):
            return True
    if kind == "AADHAAR":
        digits = re.sub(r"\D", "", surface)
        if len(digits) != 12:
            return True
    return False


def detect_identifier_spans(text: str) -> list[tuple[int, int, str]]:
    """Detect non-overlapping identifier spans (start, end, kind) in text."""
    if not text:
        return []
    norm_text = normalize_digits(text)
    protected = find_protected_spans(text)
    spans: list[tuple[int, int, str]] = []

    def _overlaps_existing(s: int, e: int) -> bool:
        for es, ee, _ in spans:
            if ee > s and es < e:
                return True
        return False

    for kind, rx in IDENTIFIER_SPECS:
        for m in rx.finditer(norm_text):
            s, e = m.start(), m.end()
            if overlaps_protected(s, e, protected) or _overlaps_existing(s, e):
                continue
            if _is_date_or_clinical_false_positive(kind, norm_text[s:e], norm_text, s, e):
                continue
            spans.append((s, e, kind))

    for kind, rx in (("MRN", _LABELED_MRN_RE), ("INSURANCE_ID", _LABELED_INS_RE)):
        for m in rx.finditer(norm_text):
            s, e = m.start(1), m.end(1)
            if overlaps_protected(s, e, protected) or _overlaps_existing(s, e):
                continue
            val = norm_text[s:e]
            if not any(ch.isdigit() for ch in val):
                continue
            if _is_date_or_clinical_false_positive(kind, val, norm_text, s, e):
                continue
            spans.append((s, e, kind))

    spans.sort(key=lambda x: x[0])
    return spans


def apply_span_replacements(
    text: str,
    spans: list[tuple[int, int, str]],
    counts: Counter[str] | None = None,
) -> str:
    """Apply non-overlapping (start, end, replacement_text_or_kind) replacements from right to left."""
    if not spans:
        return text
    ordered = sorted(spans, key=lambda x: (x[0], -(x[1] - x[0])))
    non_overlapping: list[tuple[int, int, str]] = []
    last_end = -1
    for s, e, tag in ordered:
        if s >= last_end and e > s:
            non_overlapping.append((s, e, tag))
            last_end = e
    out: list[str] = []
    pos = 0
    for s, e, tag in non_overlapping:
        out.append(text[pos:s])
        if tag.startswith("[") or tag.startswith("PSN-"):
            out.append(tag)
        else:
            out.append(f"[{tag}]")
            if counts is not None:
                counts[tag] += 1
        pos = e
    out.append(text[pos:])
    return "".join(out)
