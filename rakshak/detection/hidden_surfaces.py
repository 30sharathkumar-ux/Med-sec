"""Detection & sanitization for hidden PII surfaces: filenames, headers, JSON keys, metadata, base64."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from collections import Counter
from pathlib import Path
from typing import Callable

from rakshak.detection.identifiers import detect_identifier_spans
from rakshak.detection.multilingual import (
    canonical_latin_name,
    has_devanagari,
    normalize_digits,
    normalize_surface,
    phonetic_token_key,
)
from rakshak.detection.names import (
    DEVA_NAME_TOKENS,
    LATIN_NAME_TOKENS,
    NON_NAME_STOPWORDS,
)

_B64_STD_RE = re.compile(r"^[A-Za-z0-9+/=\s]{16,}$")
_B64_URL_RE = re.compile(r"^[A-Za-z0-9\-_=\s]{16,}$")
_EMBEDDED_B64_RE = re.compile(r"(?<![A-Za-z0-9+/_\-])([A-Za-z0-9+/_\-]{20,}={0,2})(?![A-Za-z0-9+/_\-])")
_MAX_B64_BYTES = 1_048_576  # 1 MiB safety bound

# Generic hospital/file prefixes and Devanagari clinical/schema terms that are NOT PII
_SAFE_FILENAME_TOKENS = frozenset({
    "discharge", "summary", "report", "nursing", "visitor", "log", "ward", "bed",
    "opd", "ipd", "claims", "results", "registration", "patients", "legacy", "export",
    "bundle", "arogya", "sanjeevani", "jeevanjyoti", "dhhardoi", "dhh", "city",
    "lifeline", "pathkind", "whatsapp", "forward", "bulk", "lab", "rx", "ds",
    "note", "notes", "clean", "drug", "formulary", "reference", "ranges", "dengue",
    "management", "protocol", "census", "readme", "ambulance", "helpdesk", "tickets",
    "patient", "index", "scanned", "consent", "form", "vitals", "sheet", "ward5",
    "doc", "file", "record", "records", "data", "clinical", "medical", "hospital",
})

_SAFE_DEVA_HEADER_TOKENS = frozenset({
    "रोगी", "मरीज", "मरीज़", "नाम", "का", "की", "के", "आयु", "उम्र", "लिंग",
    "पता", "ग्राम", "गाँव", "गांव", "तहसील", "जिला", "पिन", "मोबाइल", "संपर्क",
    "तारीख", "दिनांक", "भर्ती", "छुट्टी", "पिता", "पति", "माता", "माँ",
    "पंजीकरण", "संख्या", "सं", "नं", "विभाग", "वार्ड", "दवा", "निदान", "जांच",
    "रिपोर्ट", "रक्तचाप", "तापमान", "वजन", "अस्पताल", "डॉक्टर",
})

# Path segments containing names/IDs inside export metadata strings
_PATH_PII_RE = re.compile(
    r"([A-Za-z]:\\[^\n\"']+|/(?:home|var|tmp|mnt|srv|exports|his)[^\n\"']+)",
    re.IGNORECASE,
)


def _split_unicode_tokens(text: str) -> list[str]:
    """Extract Latin and Devanagari word tokens (handles camelCase, underscores, hyphens)."""
    norm = normalize_surface(text)
    # Split camelCase boundaries before tokenizing
    norm = re.sub(r"([a-z])([A-Z])", r"\1 \2", norm)
    return re.findall(r"[A-Za-z]{2,}|[\u0900-\u097f]{2,}", norm)


def _has_deva_name_token(text: str, extra_names: set[str] | None = None) -> bool:
    """Return True if text contains a Devanagari personal name token (excluding schema labels)."""
    extra_keys: set[str] = set()
    if extra_names:
        for nm in extra_names:
            for tok in canonical_latin_name(nm).split():
                if len(tok) >= 3:
                    extra_keys.add(phonetic_token_key(tok))
    for tok in re.findall(r"[\u0900-\u097f]{2,}", normalize_surface(text)):
        if tok in _SAFE_DEVA_HEADER_TOKENS or tok in NON_NAME_STOPWORDS:
            continue
        if tok in DEVA_NAME_TOKENS:
            return True
        if extra_keys:
            canon = canonical_latin_name(tok)
            if canon and phonetic_token_key(canon) in extra_keys:
                return True
    return False


def filename_has_pii(rel_path: str, extra_patient_names: set[str] | None = None) -> bool:
    """Return True if a filename (stem) contains PII such as phone, MRN/IPD, or person name."""
    stem = Path(rel_path).stem
    norm_stem = normalize_digits(normalize_surface(stem))

    # Any Devanagari script in filename stem is treated as potential PII
    if has_devanagari(stem):
        return True

    # Check identifiers (phone, Aadhaar, ABHA, MRN, IPD, ADM, SNJ, JJH, DHH-IPD, email, PAN)
    if detect_identifier_spans(norm_stem):
        return True

    # Check MRN / registration / UHID patterns across underscore/hyphen separators
    if re.search(r"(?i)(?:adm|ipd|ip|uhid|snj|jjh|dhh|mrn|reg)[-_]?\d{2,}", norm_stem):
        return True

    # Build phonetic & exact token sets from discovered patient names
    extra_keys: set[str] = set()
    extra_full_norms: set[str] = set()
    if extra_patient_names:
        for nm in extra_patient_names:
            canon = canonical_latin_name(nm)
            if len(canon) >= 3:
                extra_full_norms.add(canon)
            for tok in canon.split():
                if len(tok) >= 3 and tok not in NON_NAME_STOPWORDS:
                    extra_keys.add(phonetic_token_key(tok))

    # Check full normalized name sequence across separators (_, -, .)
    stem_words = " ".join(t.lower() for t in _split_unicode_tokens(stem))
    for full_nm in extra_full_norms:
        if " " in full_nm and full_nm in stem_words:
            return True

    tokens = _split_unicode_tokens(stem)
    name_hits = 0
    unseen_title_seq = 0
    for tok in tokens:
        low = tok.lower()
        if low in _SAFE_FILENAME_TOKENS or low in NON_NAME_STOPWORDS:
            unseen_title_seq = 0
            continue
        if len(low) >= 3 and (low in LATIN_NAME_TOKENS or phonetic_token_key(low) in extra_keys):
            name_hits += 1
        if tok[0].isupper() and len(tok) >= 3 and not tok.isupper():
            unseen_title_seq += 1
            if unseen_title_seq >= 2:
                return True
        else:
            unseen_title_seq = 0

    return name_hits >= 1


def sanitize_filename(
    rel_path: str,
    secret: bytes,
    extra_patient_names: set[str] | None = None,
) -> str:
    """Return original rel_path if clean, or a deterministic HMAC-renamed path in the same folder."""
    if not filename_has_pii(rel_path, extra_patient_names=extra_patient_names):
        return rel_path
    p = Path(rel_path)
    tag = hmac.new(secret, b"fname|" + rel_path.encode("utf-8"), hashlib.sha256).hexdigest()[:10]
    new_name = f"doc_{tag}{p.suffix.lower()}"
    parent = p.parent.as_posix()
    return new_name if parent in ("", ".") else f"{parent}/{new_name}"


def sanitize_metadata_value(value: str, text_cleaner: Callable[[str], str]) -> str:
    """Clean export metadata strings such as Windows/Unix source_path or meta.source."""
    def _scrub_path(m: re.Match[str]) -> str:
        raw_p = m.group(1)
        sep = "\\" if "\\" in raw_p else "/"
        parts = raw_p.split(sep)
        cleaned_parts = []
        for idx, seg in enumerate(parts):
            if idx == 0 and (seg.endswith(":") or seg == ""):
                cleaned_parts.append(seg)
                continue
            if detect_identifier_spans(seg) or re.search(r"[A-Za-z]+_[A-Za-z]+_\d{4,}", seg):
                cleaned_parts.append("[REDACTED]")
            else:
                cleaned_parts.append(text_cleaner(seg))
        return sep.join(cleaned_parts)

    s = _PATH_PII_RE.sub(_scrub_path, value)
    return text_cleaner(s)


def _decode_b64_utf8(token: str, max_bytes: int = _MAX_B64_BYTES) -> tuple[str | None, bool]:
    """Decode standard or URL-safe Base64 (padded or unpadded) to UTF-8 text.

    Returns (decoded_text, is_urlsafe) or (None, False) if invalid/unsafe.
    """
    compact = "".join(token.split())
    if not compact or len(compact) > (max_bytes * 4 // 3 + 16):
        return None, False
    is_urlsafe = ("-" in compact or "_" in compact) and ("+" not in compact and "/" not in compact)
    if not (_B64_STD_RE.match(compact) or _B64_URL_RE.match(compact)):
        return None, False
    try:
        padded = compact + "=" * (-len(compact) % 4)
        raw = base64.urlsafe_b64decode(padded) if is_urlsafe else base64.b64decode(padded, validate=True)
        if len(raw) > max_bytes:
            return None, False
        decoded = raw.decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None, False
    if not decoded or not any(ch.isprintable() for ch in decoded):
        return None, False
    printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\r\n\t")
    if printable / len(decoded) < 0.85:
        return None, False
    return decoded, is_urlsafe


def sanitize_base64_text(
    b64_data: str,
    text_cleaner: Callable[[str], str],
    max_bytes: int = _MAX_B64_BYTES,
) -> str:
    """Decode base64 UTF-8 payload (standard or URL-safe), sanitize, and re-encode."""
    decoded, is_urlsafe = _decode_b64_utf8(b64_data, max_bytes=max_bytes)
    if decoded is None:
        return b64_data
    cleaned = text_cleaner(decoded)
    encoded_bytes = cleaned.encode("utf-8")
    if is_urlsafe:
        return base64.urlsafe_b64encode(encoded_bytes).decode("ascii")
    return base64.b64encode(encoded_bytes).decode("ascii")


def sanitize_embedded_base64(
    text: str,
    text_cleaner: Callable[[str], str],
    max_bytes: int = _MAX_B64_BYTES,
) -> str:
    """Detect and sanitize Base64 blocks embedded inside free text without false positives."""
    if not text or len(text) < 20:
        return text

    def _replace_match(m: re.Match[str]) -> str:
        tok = m.group(1)
        # Require Base64 structural cue (+, /, _, =, or >=24 chars with mixed case/digits)
        has_b64_cue = any(c in tok for c in "+/_=") or (
            len(tok) >= 24
            and any(c.islower() for c in tok)
            and any(c.isupper() for c in tok)
            and any(c.isdigit() for c in tok)
        )
        if not has_b64_cue:
            return tok
        decoded, is_urlsafe = _decode_b64_utf8(tok, max_bytes=max_bytes)
        if decoded is None:
            return tok
        # Avoid false positives on random decoded bytes: require whitespace/punctuation/Devanagari
        if not any(ch.isspace() or ch in ":,-@." or "\u0900" <= ch <= "\u097f" for ch in decoded):
            return tok
        cleaned = text_cleaner(decoded)
        if cleaned == decoded:
            return tok
        encoded_bytes = cleaned.encode("utf-8")
        if is_urlsafe:
            return base64.urlsafe_b64encode(encoded_bytes).decode("ascii")
        return base64.b64encode(encoded_bytes).decode("ascii")

    return _EMBEDDED_B64_RE.sub(_replace_match, text)


def sanitize_csv_header(
    header: list[str],
    text_cleaner: Callable[[str], str],
    pseudonym_lookup: Callable[[str], str | None] | None = None,
    extra_names: set[str] | None = None,
) -> list[str]:
    """Sanitize CSV/TSV column headers that themselves embed PII (Latin or Devanagari)."""
    out: list[str] = []
    seen: Counter[str] = Counter()
    for idx, col in enumerate(header):
        norm_col = normalize_digits(normalize_surface(col))
        has_id = bool(detect_identifier_spans(norm_col))
        tokens = [t.lower() for t in re.split(r"[^A-Za-z]+", norm_col) if len(t) >= 3]
        has_latin_name = any(t in LATIN_NAME_TOKENS and t not in NON_NAME_STOPWORDS for t in tokens)
        has_deva_name = _has_deva_name_token(col, extra_names=extra_names)
        if not has_id and not has_latin_name and not has_deva_name:
            out.append(col)
            continue
        pid = pseudonym_lookup(col) if pseudonym_lookup else None
        if pid:
            cand = pid
        else:
            cand = col
            if has_id or has_deva_name:
                cand = text_cleaner(cand).strip()
            if has_latin_name:
                parts = re.split(r"(\s+|_|-)", cand)
                cleaned_parts = []
                for part in parts:
                    low = part.lower().strip()
                    if len(low) >= 3 and low in LATIN_NAME_TOKENS and low not in NON_NAME_STOPWORDS:
                        cleaned_parts.append("[PATIENT_NAME]")
                    else:
                        cleaned_parts.append(part)
                cand = "".join(cleaned_parts)
            if cand == col:
                cand = f"patient_col_{idx}"
        seen[cand] += 1
        if seen[cand] > 1:
            cand = f"{cand}_{seen[cand]}"
        out.append(cand)
    return out


def sanitize_json_key(
    key: str,
    text_cleaner: Callable[[str], str],
    pseudonym_lookup: Callable[[str], str | None] | None = None,
    used_keys: set[str] | None = None,
    extra_names: set[str] | None = None,
) -> str:
    """Sanitize a JSON object key when it contains PII (Latin, Devanagari, or identifiers)."""
    norm_key = normalize_digits(normalize_surface(key))
    has_id = bool(detect_identifier_spans(norm_key))
    tokens = [t.lower() for t in re.split(r"[^A-Za-z]+", norm_key) if len(t) >= 3]
    has_latin_name = any(t in LATIN_NAME_TOKENS and t not in NON_NAME_STOPWORDS for t in tokens)
    has_deva_name = _has_deva_name_token(key, extra_names=extra_names)
    if not has_id and not has_latin_name and not has_deva_name:
        return key
    pid = pseudonym_lookup(key) if pseudonym_lookup else None
    new_key = pid if pid else text_cleaner(key).strip()
    if new_key == key or not new_key:
        new_key = "[REDACTED_KEY]"
    if used_keys is not None:
        base = new_key
        suffix = 2
        while new_key in used_keys:
            new_key = f"{base}_{suffix}"
            suffix += 1
        used_keys.add(new_key)
    return new_key
