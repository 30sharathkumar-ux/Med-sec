"""Indian address component detection (house, locality, landmark, village, tehsil, district, PIN)."""

from __future__ import annotations

import re

from rakshak.detection.context_rules import find_protected_spans, overlaps_protected
from rakshak.detection.multilingual import normalize_digits

# Residential house / flat / plot markers (Latin + Devanagari)
_HOUSE_RE = re.compile(
    r"(?i)(?:"
    r"\b(?:H\.?\s*No\.?|House(?:\s*No\.?)?|Makan\s*No\.?|Qtr\.?\s*No\.?|Plot\s*No\.?|Flat\s*No\.?|Door\s*No\.?)\s*[:#-]?\s*[A-Za-z0-9/-]+|"
    r"मकान\s*(?:नं\.?|सं\.?|नंबर)\s*[:#-]?\s*[0-9\u0966-\u096fA-Za-z/-]+"
    r")"
)

# Residential locality / ward / mohalla / colony (excluded when overlapping hospital Ward N)
_LOCALITY_RE = re.compile(
    r"(?i)(?:"
    r"\bWard\s*(?:No\.?)?\s*\d+\b|"
    r"\b(?:Gali|Lane|Street|St\.|Sector|Phase|Chawl)\s+(?:No\.?\s*)?[A-Za-z0-9/-]+|"
    r"\b(?:Mohalla|Moh\.?|Colony|Nagar|Basti|Tola|Enclave|Vihar|Puram)\s+[A-Z\u0900-\u097f][\w\u0900-\u097f-]*(?:\s+[A-Z\u0900-\u097f][\w\u0900-\u097f-]*){0,3}|"
    r"\b[A-Z][a-z]+\s+(?:Nagar|Colony|Basti|Tola|Bazar|Bazaar|Chowk|Vihar|Puram|Ganj)\b|"
    r"(?:मोहल्ला|कॉलोनी)\s+[^\n,;|।]+|"
    r"(?:वार्ड|गली|सेक्टर|फेज)\s*(?:नं\.?|नंबर)?\s*[0-9\u0966-\u096fA-Za-z\u0900-\u097f-]+"
    r")"
)

# Landmarks (English + Hindi) — negative lookbehind prevents O(N^2) scanning on long tokens
_LANDMARK_RE = re.compile(
    r"(?i)(?:"
    r"\b(?:near|opp\.?|opposite|behind|beside|adjacent\s+to|in\s+front\s+of)\s+[^,\n;|]{1,80}|"
    r"(?<![^\s,;|])[^\s,;|]{1,40}(?:\s+[^\s,;|]{1,40}){0,3}\s+के\s+(?:पास|पीछे|सामने|बगल)"
    r")"
)

# Village / Gram / Gaon
_VILLAGE_RE = re.compile(
    r"(?i)(?:"
    r"\b(?:Vill\.?|Village|Gram|Gaon)\s*[:\-]?\s*([A-Z\u0900-\u097f][^\n,;|।]*)|"
    r"(?:ग्राम|गाँव|गांव)\s*[:\-]?\s*([^\n,;|।]+)"
    r")"
)

# Unlabeled village: multi-word place name right before Tehsil/Block/Distt label (after comma or mohalla)
_VILLAGE_BEFORE_TEHSIL_RE = re.compile(
    r"(?i)(?:,\s*|(?:Nagar|Colony|Basti|Bazar|Bazaar)\s+[A-Z][a-z]+\s*,\s*)"
    r"([A-Z][a-z]+(?:\s+(?:Kalan|Khurd|Buzurg|Khas|Jadid|Qadeem))?)"
    r"\s*,\s*(?:Tehsil|Teh\.?|Block|Taluka|Distt\.?|District|Dist\.?)"
)

# Tehsil / Block / Taluka
_TEHSIL_RE = re.compile(
    r"(?i)(?:"
    r"\b(?:Tehsil|Teh\.?|Taluka|Block)\s*[:\-]?\s*[A-Za-z\u0900-\u097f][^\n,;|।-]*|"
    r"(?:तहसील|ब्लॉक)\s*[:\-]?\s*[^\n,;|।-]+"
    r")"
)

# District (in free-text address lines)
_DISTRICT_RE = re.compile(
    r"(?i)(?:"
    r"\b(?:Distt\.?|District|Dist\.?|Jila)\s*[:\-]?\s*[A-Za-z\u0900-\u097f][^\n,;|।0-9-]*|"
    r"(?:जिला)\s*[:\-]?\s*[^\n,;|।0-9-]+"
    r")"
)

# Contextual 6-digit Indian PIN code (after dash, comma+space, or PIN label — avoids 6-digit platelet counts!)
_PIN_CONTEXT_RE = re.compile(
    r"(?i)(?:(?<=PIN[:\s-])|(?<=Pin\sCode[:\s-])|(?<=पिन[:\s-])|(?<=-\s)|(?<=,\s))([1-8]\d{5})(?!\d)"
)


def detect_address_spans(
    text: str,
    generalize_pin: bool = True,
    keep_district: bool = False,
) -> list[tuple[int, int, str]]:
    """Detect free-text address components while protecting hospital wards and clinical values."""
    if not text:
        return []
    norm_text = normalize_digits(text)
    protected = find_protected_spans(text)
    spans: list[tuple[int, int, str]] = []

    def _add(s: int, e: int, repl: str) -> None:
        if e <= s or overlaps_protected(s, e, protected):
            return
        for es, ee, _ in spans:
            if ee > s and es < e:
                return
        spans.append((s, e, repl))

    for m in _HOUSE_RE.finditer(norm_text):
        _add(m.start(), m.end(), "HOUSE")

    for m in _LANDMARK_RE.finditer(text):
        _add(m.start(), m.end(), "LANDMARK")

    for m in _VILLAGE_RE.finditer(text):
        # Replace just the village name value if preceded by label, or entire span
        val_grp = 1 if m.group(1) is not None else 2
        if m.group(val_grp):
            _add(m.start(val_grp), m.end(val_grp), "VILLAGE")

    # Unlabeled village names appearing before Tehsil/District labels
    for m in _VILLAGE_BEFORE_TEHSIL_RE.finditer(text):
        _add(m.start(1), m.end(1), "VILLAGE")

    for m in _TEHSIL_RE.finditer(text):
        _add(m.start(), m.end(), "TEHSIL")

    if not keep_district:
        for m in _DISTRICT_RE.finditer(text):
            _add(m.start(), m.end(), "DISTRICT")

    for m in _LOCALITY_RE.finditer(norm_text):
        # Extra guard: do not touch "Ward N" if immediately followed by "(Dept)" or "/ Bed"
        tail = text[m.end() : m.end() + 25]
        if re.match(r"^\s*(?:\([^)]+\)|/\s*Bed\b)", tail, re.IGNORECASE):
            continue
        _add(m.start(), m.end(), "LOCALITY")

    for m in _PIN_CONTEXT_RE.finditer(norm_text):
        pin = m.group(1)
        repl = f"{pin[:3]}***" if generalize_pin else "[PIN]"
        _add(m.start(1), m.end(1), repl)

    spans.sort(key=lambda x: x[0])
    return spans
