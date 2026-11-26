"""Name and identifier normalization for cross-script, cross-hospital record linkage.

Covers:
 - Unicode NFKC + casefold
 - Devanagari-to-Latin transliteration (rule-based, no external library required)
 - Honorific / title stripping
 - Patronymic relation extraction (S/o, D/o, W/o, C/O)
 - Indian phone / Aadhaar / ABHA / MRN digit normalization
 - Vowel-tolerant phonetic keying for fuzzy matching
"""
from __future__ import annotations

import re
import unicodedata
from typing import Optional

# ---------------------------------------------------------------------------
# Devanagari → Latin transliteration map (ITRANS-inspired, deterministic)
# ---------------------------------------------------------------------------
_DEVA_VOWELS = {
    '\u0905': 'a', '\u0906': 'aa', '\u0907': 'i', '\u0908': 'ii',
    '\u0909': 'u', '\u090A': 'uu', '\u090B': 'ri', '\u090F': 'e',
    '\u0910': 'ai', '\u0913': 'o', '\u0914': 'au',
}

_DEVA_MATRAS = {
    '\u093E': 'aa', '\u093F': 'i', '\u0940': 'ii',
    '\u0941': 'u', '\u0942': 'uu', '\u0943': 'ri',
    '\u0947': 'e', '\u0948': 'ai', '\u094B': 'o', '\u094C': 'au',
}

_DEVA_CONSONANTS = {
    '\u0915': 'k', '\u0916': 'kh', '\u0917': 'g', '\u0918': 'gh', '\u0919': 'ng',
    '\u091A': 'ch', '\u091B': 'chh', '\u091C': 'j', '\u091D': 'jh', '\u091E': 'ny',
    '\u091F': 't', '\u0920': 'th', '\u0921': 'd', '\u0922': 'dh', '\u0923': 'n',
    '\u0924': 't', '\u0925': 'th', '\u0926': 'd', '\u0927': 'dh', '\u0928': 'n',
    '\u092A': 'p', '\u092B': 'ph', '\u092C': 'b', '\u092D': 'bh', '\u092E': 'm',
    '\u092F': 'y', '\u0930': 'r', '\u0932': 'l', '\u0935': 'v',
    '\u0936': 'sh', '\u0937': 'sh', '\u0938': 's', '\u0939': 'h',
    '\u0933': 'l', '\u0934': 'l',
    '\u0958': 'q', '\u0959': 'khh', '\u095A': 'ghh', '\u095B': 'z',
    '\u095C': 'dh', '\u095D': 'rh', '\u095E': 'f', '\u095F': 'y',
}

_DEVA_DIGITS = {
    '\u0966': '0', '\u0967': '1', '\u0968': '2', '\u0969': '3', '\u096A': '4',
    '\u096B': '5', '\u096C': '6', '\u096D': '7', '\u096E': '8', '\u096F': '9',
}

VIRAMA = '\u094D'
NUKTA = '\u093C'
ANUSVARA = '\u0902'
CHANDRABINDU = '\u0901'
VISARGA = '\u0903'


def transliterate_devanagari(text: str) -> str:
    """Convert Devanagari text to approximate Latin transliteration."""
    result: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]

        # Devanagari digits
        if ch in _DEVA_DIGITS:
            result.append(_DEVA_DIGITS[ch])
            i += 1
            continue

        # Anusvara / Chandrabindu / Visarga
        if ch == ANUSVARA:
            result.append('n')
            i += 1
            continue
        if ch == CHANDRABINDU:
            result.append('n')
            i += 1
            continue
        if ch == VISARGA:
            result.append('h')
            i += 1
            continue

        # Nukta: skip (modifies previous consonant)
        if ch == NUKTA:
            i += 1
            continue

        # Independent vowels
        if ch in _DEVA_VOWELS:
            result.append(_DEVA_VOWELS[ch])
            i += 1
            continue

        # Consonants
        if ch in _DEVA_CONSONANTS:
            cons = _DEVA_CONSONANTS[ch]
            i += 1
            # Check for nukta modifying this consonant
            if i < n and text[i] == NUKTA:
                i += 1
            # Check for virama (halant) → conjunct
            if i < n and text[i] == VIRAMA:
                result.append(cons)
                i += 1
                continue
            # Check for matra (dependent vowel)
            if i < n and text[i] in _DEVA_MATRAS:
                result.append(cons + _DEVA_MATRAS[text[i]])
                i += 1
                continue
            # Inherent 'a'
            result.append(cons + 'a')
            continue

        # Matra without consonant (unusual)
        if ch in _DEVA_MATRAS:
            result.append(_DEVA_MATRAS[ch])
            i += 1
            continue

        # Pass through non-Devanagari
        result.append(ch)
        i += 1

    return ''.join(result)


def has_devanagari(text: str) -> bool:
    """Check if text contains Devanagari characters."""
    return any('\u0900' <= ch <= '\u097F' for ch in text)


# ---------------------------------------------------------------------------
# Honorific / title patterns
# ---------------------------------------------------------------------------
_HONORIFICS_RE = re.compile(
    r'\b(?:shri|shree|shr[iī]mat[iī]?|श्री|श्रीमती|smt\.?|mr\.?|mrs\.?|ms\.?'
    r'|sahab|sahib|saab|ji|jee|didi|bhaiya|bhai|devi|begum|bibi|babu|master'
    r')\b',
    re.IGNORECASE,
)

_TITLE_RE = re.compile(
    r'\b(?:dr\.?|doctor|prof\.?|professor)\b',
    re.IGNORECASE,
)

# Common Indian name abbreviations for normalization
_ABBREV_MAP = {
    'md': 'mohammad', 'mohd': 'mohammad', 'moh': 'mohammad', 'md.': 'mohammad',
    'mohd.': 'mohammad', 'mhd': 'mohammad',
    'ch': 'chaudhary', 'ch.': 'chaudhary',
    'pt': 'pandit', 'pt.': 'pandit',
    'kr': 'kumar', 'kr.': 'kumar',
    'km': 'kumari', 'km.': 'kumari',
}


def normalize_text(text: str) -> str:
    """NFKC normalize, casefold, strip diacritics for comparison."""
    text = unicodedata.normalize('NFKC', text)
    text = text.casefold()
    # Remove zero-width characters
    text = re.sub(r'[\u200b\u200c\u200d\ufeff]', '', text)
    return text


def normalize_name(name: str) -> str:
    """Normalize a name for comparison: NFKC, casefold, transliterate Devanagari,
    strip honorifics, expand abbreviations, collapse whitespace."""
    name = normalize_text(name)
    if has_devanagari(name):
        name = transliterate_devanagari(name)
    name = _HONORIFICS_RE.sub('', name)
    name = _TITLE_RE.sub('', name)
    # Expand common abbreviations
    tokens = name.split()
    expanded = []
    for tok in tokens:
        clean = tok.strip('.,;:')
        if clean in _ABBREV_MAP:
            expanded.append(_ABBREV_MAP[clean])
        else:
            expanded.append(tok)
    name = ' '.join(expanded)
    # Remove punctuation and collapse whitespace
    name = re.sub(r'[^\w\s]', ' ', name)
    name = re.sub(r'\s+', ' ', name).strip()
    return name


def phonetic_key(name: str) -> str:
    """Generate a vowel-tolerant phonetic key for fuzzy matching.

    Drops all vowels after the first character, collapses duplicate consonants,
    and normalizes common Indian consonant alternations.
    """
    name = normalize_name(name)
    if not name:
        return ''

    # Token-level phonetic keys
    tokens = name.split()
    keys = []
    for token in tokens:
        if len(token) < 2:
            keys.append(token)
            continue
        # Keep first char, drop vowels from rest
        first = token[0]
        rest = re.sub(r'[aeiou]', '', token[1:])
        # Normalize common alternations
        rest = rest.replace('ph', 'f')
        rest = rest.replace('bh', 'b')
        rest = rest.replace('dh', 'd')
        rest = rest.replace('th', 't')
        rest = rest.replace('kh', 'k')
        rest = rest.replace('gh', 'g')
        rest = rest.replace('chh', 'ch')
        rest = rest.replace('jh', 'j')
        rest = rest.replace('sh', 's')
        # Collapse doubles
        collapsed = []
        for ch in first + rest:
            if collapsed and ch == collapsed[-1]:
                continue
            collapsed.append(ch)
        keys.append(''.join(collapsed))
    return ' '.join(keys)


# ---------------------------------------------------------------------------
# Identifier normalization
# ---------------------------------------------------------------------------
_DIGIT_RE = re.compile(r'\d')
_NON_DIGIT_RE = re.compile(r'[^\d]')

# Devanagari digits to ASCII
_INDIC_DIGIT_MAP = str.maketrans(
    '०१२३४५६७८९',
    '0123456789',
)


def normalize_phone(phone: str) -> Optional[str]:
    """Normalize an Indian phone number to 10 digits (no country code)."""
    phone = phone.translate(_INDIC_DIGIT_MAP)
    digits = _NON_DIGIT_RE.sub('', phone)
    if len(digits) == 12 and digits.startswith('91'):
        digits = digits[2:]
    elif len(digits) == 11 and digits.startswith('0'):
        digits = digits[1:]
    if len(digits) == 10 and digits[0] in '6789':
        return digits
    return None


def normalize_aadhaar(aadhaar: str) -> Optional[str]:
    """Normalize Aadhaar to 12 digits."""
    aadhaar = aadhaar.translate(_INDIC_DIGIT_MAP)
    digits = _NON_DIGIT_RE.sub('', aadhaar)
    # Handle masked Aadhaar (last 4 digits)
    if len(digits) == 4:
        return f'XXXX{digits}'
    if len(digits) == 12:
        return digits
    return None


def normalize_abha(abha: str) -> Optional[str]:
    """Normalize ABHA number to 14 digits."""
    abha = abha.translate(_INDIC_DIGIT_MAP)
    digits = _NON_DIGIT_RE.sub('', abha)
    if len(digits) == 14:
        return digits
    return None


def normalize_mrn(mrn: str) -> str:
    """Normalize MRN/UHID: uppercase, strip whitespace."""
    return re.sub(r'\s+', '', mrn.strip().upper())


def extract_digits(text: str) -> str:
    """Extract only digit characters from text."""
    text = text.translate(_INDIC_DIGIT_MAP)
    return _NON_DIGIT_RE.sub('', text)


# ---------------------------------------------------------------------------
# Relation extraction
# ---------------------------------------------------------------------------
_RELATION_RE = re.compile(
    r'(?:(?:S|D|W|C)\s*/\s*(?:o|O)\s+|'
    r'(?:son|daughter|wife|husband)\s+(?:of)\s+|'
    r'पुत्र(?:ी)?\s+|बेटा\s+|बेटी\s+|पत्नी\s+|पति\s+)'
    r'([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F\s.]+?)(?:\s*[,;|\n]|$)',
    re.IGNORECASE,
)


def extract_relative_name(text: str) -> Optional[str]:
    """Extract relative name from S/o, D/o, W/o, C/O patterns."""
    m = _RELATION_RE.search(text)
    if m:
        name = m.group(1).strip()
        if len(name) > 1:
            return normalize_name(name)
    return None
