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
from rakshak.detection.multilingual import canonical_latin_name, phonetic_token_key
from rakshak.detection.names import LATIN_NAME_TOKENS, NON_NAME_STOPWORDS

_B64_RE = re.compile(r"^[A-Za-z0-9+/=\s]{16,}$")

# Generic hospital/file prefixes that are NOT PII in filenames
_SAFE_FILENAME_TOKENS = frozenset({
    "discharge", "summary", "report", "nursing", "visitor", "log", "ward", "bed",
    "opd", "ipd", "claims", "results", "registration", "patients", "legacy", "export",
    "bundle", "arogya", "sanjeevani", "jeevanjyoti", "dhhardoi", "dhh", "city",
    "lifeline", "pathkind", "whatsapp", "forward", "bulk", "lab", "rx", "ds",
    "note", "notes", "clean", "drug", "formulary", "reference", "ranges", "dengue",
    "management", "protocol", "census", "readme", "ambulance", "helpdesk", "tickets",
    "patient", "index", "scanned", "consent", "form", "vitals", "sheet", "ward5",
})

# Path segments containing names/IDs inside export metadata strings
_PATH_PII_RE = re.compile(
    r"([A-Za-z]:\\[^\n\"']+|/(?:home|var|tmp|mnt|srv|exports|his)[^\n\"']+)",
    re.IGNORECASE,
)


def filename_has_pii(rel_path: str, extra_patient_names: set[str] | None = None) -> bool:
    """Return True if a filename (stem) contains PII such as phone, MRN/IPD, or person name."""
    stem = Path(rel_path).stem
    # Check identifiers (phone, Aadhaar, ABHA, MRN, IPD, ADM, SNJ, JJH, DHH-IPD)
    if detect_identifier_spans(stem):
        return True
    # Check lowercased MRN patterns like nursing_adm000161, nursing_ip-26-00134, nursing_ipd-2026-00459
    if re.search(r"(?i)(?:adm|ipd|ip|uhid|snj|jjh|dhh)[-_]?\d{2,}", stem):
        return True
    # Check person name tokens in filename (e.g., Discharge_Summary_Fatima_Bano_...)
    tokens = [t for t in re.split(r"[^A-Za-z]+", stem) if len(t) >= 3]
    extra_keys = set()
    if extra_patient_names:
        for nm in extra_patient_names:
            for tok in canonical_latin_name(nm).split():
                if len(tok) >= 3:
                    extra_keys.add(phonetic_token_key(tok))
    name_hits = 0
    for tok in tokens:
        low = tok.lower()
        if low in _SAFE_FILENAME_TOKENS or low in NON_NAME_STOPWORDS:
            continue
        if low in LATIN_NAME_TOKENS or phonetic_token_key(low) in extra_keys:
            name_hits += 1
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


def sanitize_base64_text(b64_data: str, text_cleaner: Callable[[str], str]) -> str:
    """Decode base64 UTF-8 payload, run full text sanitizer, and re-encode to valid base64."""
    compact = "".join(b64_data.split())
    if not compact or not _B64_RE.match(compact):
        return b64_data
    try:
        padded = compact + "=" * (-len(compact) % 4)
        raw = base64.b64decode(padded, validate=True)
        decoded = raw.decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return b64_data
    if not any(ch.isprintable() for ch in decoded):
        return b64_data
    cleaned = text_cleaner(decoded)
    return base64.b64encode(cleaned.encode("utf-8")).decode("ascii")


def sanitize_csv_header(
    header: list[str],
    text_cleaner: Callable[[str], str],
    pseudonym_lookup: Callable[[str], str | None] | None = None,
) -> list[str]:
    """Sanitize CSV/TSV column headers that themselves embed PII (e.g. ward_vitals_sheet.csv)."""
    out: list[str] = []
    seen: Counter[str] = Counter()
    for idx, col in enumerate(header):
        # Only alter headers that actually contain identifiers or personal names
        has_id = bool(detect_identifier_spans(col))
        tokens = [t.lower() for t in re.split(r"[^A-Za-z]+", col) if len(t) >= 3]
        has_name = any(t in LATIN_NAME_TOKENS and t not in NON_NAME_STOPWORDS for t in tokens)
        if not has_id and not has_name:
            out.append(col)
            continue
        pid = pseudonym_lookup(col) if pseudonym_lookup else None
        if pid:
            cand = pid
        else:
            # For headers with names: replace each name token individually
            cand = col
            if has_id:
                cand = text_cleaner(cand).strip()
            if has_name:
                # Replace individual name tokens that survived the text cleaner
                parts = re.split(r'(\s+)', cand)
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
) -> str:
    """Sanitize a JSON object key when it contains PII (e.g. by_uhid / by_name dicts)."""
    has_id = bool(detect_identifier_spans(key))
    tokens = [t.lower() for t in re.split(r"[^A-Za-z]+", key) if len(t) >= 3]
    has_name = any(t in LATIN_NAME_TOKENS and t not in NON_NAME_STOPWORDS for t in tokens)
    if not has_id and not has_name:
        return key
    pid = pseudonym_lookup(key) if pseudonym_lookup else None
    new_key = pid if pid else text_cleaner(key).strip()
    if new_key == key:
        new_key = "[REDACTED_KEY]"
    if used_keys is not None:
        base = new_key
        suffix = 2
        while new_key in used_keys:
            new_key = f"{base}_{suffix}"
            suffix += 1
        used_keys.add(new_key)
    return new_key
