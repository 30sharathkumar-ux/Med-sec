"""Contextual protection rules to prevent clinical over-redaction (Challenge-2 traps)."""

from __future__ import annotations

import re

# Spans that MUST NOT be redacted as patient PII or relative PII
PROTECTED_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Doctors & clinicians (Latin + Devanagari)
    (
        "DOCTOR",
        re.compile(
            r"(?i)(?:(?<=^)|(?<=[\s(\[,;:/\"']))"
            r"(?:Dr\.?|डॉ\.?)\s+"
            r"(?:[A-Z\u0900-\u097f][\w.\u0900-\u097f-]*)"
            r"(?:\s+(?!reviewed|advised|ordered|prescribed|saw|noted|took|ne|told|said|MD|MS|DNB|DM|MBBS\b)"
            r"[A-Z\u0900-\u097f][\w.\u0900-\u097f-]*){0,2}"
        ),
    ),
    # Medical eponyms & syndromes (never treat the eponym person name as a patient)
    (
        "EPONYM",
        re.compile(
            r"(?i)\b(?:"
            r"Addison(?:'s)?(?:\s+disease|\s+crisis)?|"
            r"Parkinson(?:'s)?(?:\s+disease)?|"
            r"Bell(?:'s)?\s+palsy|"
            r"Alzheimer(?:'s)?(?:\s+disease)?|"
            r"Hodgkin(?:'s)?(?:\s+lymphoma|\s+disease)?|"
            r"Non-Hodgkin(?:'s)?(?:\s+lymphoma)?|"
            r"Graves(?:'s?)?(?:\s+disease)?|"
            r"Cushing(?:'s)?(?:\s+syndrome|\s+disease)?|"
            r"Crohn(?:'s)?(?:\s+disease)?|"
            r"Hashimoto(?:'s)?(?:\s+thyroiditis)?|"
            r"Down(?:'s)?\s+syndrome|"
            r"Turner(?:'s)?\s+syndrome|"
            r"Raynaud(?:'s)?(?:\s+phenomenon|\s+disease)?|"
            r"Guillain[-\s]?Barr[eé](?:\s+syndrome)?|"
            r"Kawasaki(?:\s+disease)?|"
            r"Takayasu(?:'s)?(?:\s+arteritis)?|"
            r"Wilson(?:'s)?\s+disease|"
            r"Menier[e']?s?\s+disease|"
            r"Hansen(?:'s)?\s+disease"
            r")\b"
        ),
    ),
    # Hospital wards & bed numbers (distinct from residential Ward N in addresses)
    # Only protect "Ward N" when followed by clinical context: (Dept), /Bed, parenthetical department
    (
        "HOSPITAL_WARD",
        re.compile(
            r"(?i)(?:\bWard(?:/Bed)?\s*[:#-]?\s*\d+\s*\([^)\n]+\)(?:\s*/\s*Bed\s*\d+)?|\bWard(?:/Bed)?\s*[:#-]?\s*\d+\s*/\s*Bed\s*\d+|\bBed\s*(?:No\.?)?\s*\d+\b)"
        ),
    ),
    # ASHA community health worker
    ("ASHA", re.compile(r"(?i)\bASHA\s+workers?\b")),
    # Clinical complaint & history markers (C/O complaint, K/C/O, H/O)
    (
        "COMPLAINT_MARKER",
        re.compile(
            r"(?i)\b(?:N/?K/C/O|K/C/O|H/O)\b"
        ),
    ),
    # C/O followed by medical symptoms (NOT a relative name)
    (
        "CO_COMPLAINT",
        re.compile(
            r"(?i)\bC/O\s*[:\-]?\s*(?:fever|high\s+fever|cough|cold|pain|chest\s+pain|abdominal\s+pain|"
            r"pain\s+abdomen|headache|vomiting|nausea|diarrh?oea|loose\s+motions?|breathlessness|"
            r"shortness\s+of\s+breath|dyspno?ea|weakness|generalised\s+weakness|generalized\s+weakness|"
            r"dizziness|vertigo|palpitations|swelling|o?edema|rash|itching|bleeding|dysuria|"
            r"bukhar|khansi|pet\s+dard|dard|chakkar|kamzori|ult[iy])\b[^\n.;]*"
        ),
    ),
    # Dosages, frequencies, vitals, and lab values
    (
        "DOSE_OR_VITAL",
        re.compile(
            r"(?i)(?:"
            r"\b\d+(?:\.\d+)?\s*(?:mg/dL|g/dL|mIU/L|mmol/L|mg|mcg|ug|g|ml|mL|L|units?|IU|%|mmHg|/uL|/min|puffs?|sachets?)\b|"
            r"\b[01]-[01]-[01]\b|"
            r"\b(?:OD|BD|TDS|QID|SOS|HS|PRN|IV|IM|PO|SC)\s*(?:x\s*\d+\s*(?:days?|wks?|weeks?|months?))?\b|"
            r"\bBP\s*\d{2,3}/\d{2,3}\b|"
            r"\bTemp\s*\d{2,3}(?:\.\d+)?\s*°?\s*[FC]\b"
            r")"
        ),
    ),
]


def find_protected_spans(text: str) -> list[tuple[int, int, str]]:
    """Return sorted, merged (start, end, kind) character spans that must never be redacted."""
    raw_spans: list[tuple[int, int, str]] = []
    for kind, rx in PROTECTED_PATTERNS:
        for m in rx.finditer(text):
            raw_spans.append((m.start(), m.end(), kind))
    raw_spans.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    merged: list[tuple[int, int, str]] = []
    for start, end, kind in raw_spans:
        if not merged or start >= merged[-1][1]:
            merged.append((start, end, kind))
        elif end > merged[-1][1]:
            prev_s, _, prev_k = merged[-1]
            merged[-1] = (prev_s, end, prev_k)
    return merged


def overlaps_protected(start: int, end: int, protected: list[tuple[int, int, str]]) -> bool:
    """Return True if [start, end) overlaps any protected clinical/doctor span."""
    for ps, pe, _ in protected:
        if ps >= end:
            break
        if pe > start and ps < end:
            return True
    return False
