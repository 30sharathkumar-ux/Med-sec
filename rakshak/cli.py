"""CLI and pipeline orchestration for RAKSHA.

Integrates:
 - Ingestion (Laptop B interface)
 - PII Detection (Laptop B interface)
 - Identity Resolution (Laptop A)
 - Pseudonymization (Laptop A)
 - Privacy Transformation (Laptop A)
 - Sanitized Export (Laptop A)
 - Report Generation (Laptop A)
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import hmac
import io
import json
import os
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from rakshak.ingestion import IngestedFile, discover_files, ingest_file
from rakshak.linkage.normalize import (
    extract_relative_name,
    has_devanagari,
    normalize_name,
    normalize_phone,
    normalize_aadhaar,
    normalize_abha,
    normalize_mrn,
    normalize_text,
    phonetic_key,
    transliterate_devanagari,
    extract_digits,
)
from rakshak.linkage.resolver import (
    IdentityResolver,
    RecordEvidence,
    extract_evidence_csv,
    extract_evidence_json,
    extract_evidence_text,
)
from rakshak.privacy.pseudonymize import generate_pseudonym
from rakshak.privacy.transforms import (
    age_band,
    band_free_text_ages,
    compute_date_shift,
    generalize_pin,
    generalize_village,
    shift_date_string,
    _parse_date,
)
from rakshak.processors.quarantine import make_quarantine_entry
from rakshak.reporting.records import (
    filter_exported_records,
    json_pointer_escape,
    write_records_jsonl,
)
from rakshak.reporting.report import build_report, write_report
from rakshak.security.logging import emit_summary

from rakshak.detection.identifiers import detect_identifier_spans, apply_span_replacements
from rakshak.detection.names import detect_name_spans
from rakshak.detection.addresses import detect_address_spans
from rakshak.detection.structured import classify_field
from rakshak.detection.hidden_surfaces import (
    sanitize_filename,
    sanitize_csv_header,
    sanitize_json_key,
    sanitize_metadata_value,
    sanitize_base64_text,
    sanitize_embedded_base64,
)
from rakshak.privacy.fhir_validator import validate_fhir_input, validate_fhir_output
from rakshak.privacy.k_anonymity import (
    compute_adaptive_profile_policies,
    compute_k_anonymity_metrics,
    suppress_pin,
)

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

# ---------------------------------------------------------------------------
# DOB patterns in free text (not field-classified)
# ---------------------------------------------------------------------------
_DOB_RE = re.compile(
    r"(?i)(?:DOB|Date\s+of\s+Birth|D\.O\.B\.?|Birth\s*Date|"
    r"जन्म\s*(?:तिथि|तारीख)?|Janm\s*Tithi)"
    r"\s*[:=\-]\s*"
    r"(\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4})"
)

# Admission / Discharge / Registration date labels (quasi-identifiers)
_DATED_LABEL_RE = re.compile(
    r"(?i)(?:Date\s+of\s+(?:Admission|Discharge|Registration|Visit|Collection|Report)|"
    r"Admission\s+Date|Discharge\s+Date|Reg\.?\s*Date|Visit\s*Date|"
    r"भर्ती\s*(?:की\s+)?तारीख|छुट्टी\s*(?:की\s+)?तारीख)"
    r"\s*[:=\-]\s*"
    r"(\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4})"
)

# PII field types that cause wholesale cell/value redaction in structured data
_DIRECT_PII = frozenset({
    "PATIENT_NAME", "RELATIVE_NAME", "PHONE", "MRN", "AADHAAR",
    "ABHA_NUMBER", "ABHA_ADDRESS", "PAN", "EMAIL", "INSURANCE_ID",
    "ADDRESS", "HOUSE", "LOCALITY",
})

_KEEP_TYPES = frozenset({
    "CLINICAL_KEEP", "GENDER", "AGE_SEX", "RELATION_LABEL",
    "DISTRICT", "TEHSIL",
})


# ===================== policy / secret / pseudonym ========================

def load_policy(path: Path) -> dict[str, Any]:
    """Load simple `key: value` policy settings without external YAML dependencies."""
    policy: dict[str, Any] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if ":" in line:
                k, v = (x.strip() for x in line.split(":", 1))
                policy[k] = int(v) if v.lstrip("-").isdigit() else v
    return policy


def _get_secret() -> bytes:
    """Read RAKSHA_SECRET dynamically at runtime (never cache or log)."""
    return os.environ.get("RAKSHA_SECRET", "").encode("utf-8")

# ---------------------------------------------------------------------------
# PII Cleaning
# ---------------------------------------------------------------------------

def _classify_column(col_name: str) -> Optional[str]:
    """Map the detection engine's field types to the privacy transform types."""
    field_type = classify_field(col_name)
    return {
        "PATIENT_NAME": "name",
        "RELATIVE_NAME": "relative",
        "PHONE": "phone",
        "MRN": "mrn",
        "AADHAAR": "aadhaar",
        "ABHA_NUMBER": "abha",
        "ABHA_ADDRESS": "abha",
        "PAN": "pan",
        "EMAIL": "email",
        "INSURANCE_ID": "insurance",
        "DOB": "dob",
        "DATE": "date",
        "ADDRESS": "address",
        "HOUSE": "house",
        "LOCALITY": "village",
        "VILLAGE": "village",
        "VILLAGE_OR_LOCALITY": "village",
        "PIN": "pin",
        "AGE": "age",
        "CLINICAL_KEEP": "clinical_keep",
        "GENDER": "gender",
        "AGE_SEX": "age_sex",
        "RELATION_LABEL": "relation_label",
        "DISTRICT": "district",
        "TEHSIL": "tehsil",
        "METADATA_PATH": "metadata_path",
        "BASE64_DATA": "base64_data",
    }.get(field_type)


_GENERALIZE_COLUMNS = {'age', 'dob', 'village', 'pin', 'address', 'house', 'landmark'}
_REPLACE_COLUMNS = {'name', 'phone', 'aadhaar', 'abha', 'mrn', 'email', 'pan', 'insurance', 'relative'}


def _format_age_band(age_val: int, band_width: int) -> str:
    """Format an age into a truthful band (with 80+ cap when widened)."""
    if age_val >= 80 and band_width >= 10:
        return "80+"
    return age_band(age_val, band_width)


def _clean_text(text: str, entity_counts: Counter, pseudonym_str: str = '',
                age_band_width: int = 5) -> str:
    """Clean text with the full multilingual detection engine."""
    return _clean_text_full(text, entity_counts, age_band_width=age_band_width)


def _clean_csv_value(val: str, col_type: Optional[str], entity_counts: Counter,
                     pseudonym_str: str, policy: dict, patient_key: Optional[str],
                     row_district: str = "",
                     risk_policy: Optional[dict[str, Any]] = None) -> str:
    """Clean a CSV cell based on its column classification."""
    if not val.strip():
        return val

    band_width = int((risk_policy or {}).get("age_band_width", policy.get("age_band_years", 5)))
    pin_lvl = int((risk_policy or {}).get("pin_suppress_level", 0))
    suppress_dist = bool((risk_policy or {}).get("suppress_district", False))

    if col_type == "age_sex":
        m_as = re.match(r"^\s*(\d{1,3})\s*(.*)$", val)
        if m_as:
            age_val = int(m_as.group(1))
            if 0 <= age_val <= 120:
                return f"{_format_age_band(age_val, band_width)}{m_as.group(2)}"
        return val

    if col_type in {"clinical_keep", "gender", "relation_label", "tehsil"}:
        return val
    if col_type == "district":
        return "[DISTRICT]" if suppress_dist else val
    if col_type == "date":
        if patient_key:
            shifted = shift_date_string(val, patient_key,
                                        int(policy.get('date_shift_max_days', 180)))
            if shifted:
                entity_counts["DATE"] += 1
                return shifted
        entity_counts["DATE"] += 1
        return "[DATE]"
    if col_type == "metadata_path":
        return sanitize_metadata_value(val, lambda t: _clean_text_full(t, entity_counts))
    if col_type == "base64_data":
        return sanitize_base64_text(val, lambda t: _clean_text_full(t, entity_counts))

    if col_type in _REPLACE_COLUMNS:
        entity_counts[col_type.upper()] += 1
        if col_type == 'name':
            entity_counts['PATIENT_NAME'] += 1
            return pseudonym_str if pseudonym_str else '[PATIENT_NAME]'
        elif col_type == 'relative':
            entity_counts['RELATIVE_NAME'] += 1
            return '[RELATIVE_NAME]'
        elif col_type == 'phone':
            entity_counts['PHONE'] += 1
            return '[PHONE]'
        elif col_type == 'aadhaar':
            entity_counts['AADHAAR'] += 1
            return '[AADHAAR]'
        elif col_type == 'abha':
            entity_counts['ABHA_NUMBER'] += 1
            return '[ABHA]'
        elif col_type == 'mrn':
            entity_counts['MRN'] += 1
            return pseudonym_str if pseudonym_str else '[MRN]'
        elif col_type == 'email':
            entity_counts['EMAIL'] += 1
            return '[EMAIL]'
        elif col_type == 'pan':
            entity_counts['PAN'] += 1
            return '[PAN]'
        elif col_type == 'insurance':
            entity_counts['INSURANCE_ID'] += 1
            return '[INSURANCE_ID]'
        return '[REDACTED]'

    if col_type in _GENERALIZE_COLUMNS:
        if col_type == 'age':
            try:
                age_val = int(re.match(r'(\d+)', val).group(1))
                return _format_age_band(age_val, band_width)
            except (ValueError, AttributeError):
                return val
        elif col_type == 'dob':
            if patient_key:
                shifted = shift_date_string(val, patient_key,
                                            int(policy.get('date_shift_max_days', 180)))
                if shifted:
                    entity_counts['DOB'] += 1
                    return shifted
            entity_counts['DOB'] += 1
            return '[DOB]'
        elif col_type == 'village':
            entity_counts['VILLAGE'] += 1
            return generalize_village(val, row_district)
        elif col_type == 'pin':
            entity_counts['PIN'] += 1
            gen_pin = generalize_pin(val)
            return suppress_pin(gen_pin, level=pin_lvl) if pin_lvl > 0 else gen_pin
        elif col_type == 'address':
            entity_counts['ADDRESS'] += 1
            return '[ADDRESS]'
        elif col_type in ('house', 'landmark'):
            entity_counts['HOUSE'] += 1
            return '[SUPPRESSED]'
        return val

    # For unclassified columns, apply full multilingual text detection
    return _clean_text_full(val, entity_counts)


# =================== full text cleaning ==================================

def _clean_text_full(
    text: str,
    entity_counts: Counter[str],
    known_names: set[str] | None = None,
    age_band_width: int = 5,
) -> str:
    """Comprehensive PII detection and redaction using all detection modules."""
    if not text or not text.strip():
        return text

    # Strip zero-width obfuscation characters before span detection so indices stay aligned
    if any(ch in text for ch in ("\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\ufeff")):
        text = re.sub(r"[\u200b-\u200f\u202a-\u202e\ufeff]", "", text)

    # 0. Decode & sanitize any embedded Base64 payloads before span scanning
    text = sanitize_embedded_base64(
        text,
        lambda t: _clean_text_full(t, entity_counts, known_names, age_band_width=age_band_width),
    )

    all_spans: list[tuple[int, int, str]] = []

    # 1. Identifier detection (phone, aadhaar, pan, mrn, insurance, email, abha)
    all_spans.extend(detect_identifier_spans(text))

    # 2. Name detection (patient, relative — context labels + gazetteer)
    all_spans.extend(detect_name_spans(text, known_names))

    # 3. Address detection (house, landmark, village, locality, tehsil, district, pin)
    all_spans.extend(detect_address_spans(text))

    # 4. DOB patterns in free text
    for m in _DOB_RE.finditer(text):
        all_spans.append((m.start(1), m.end(1), "DOB"))

    # 5. Admission / discharge dates in free text
    for m in _DATED_LABEL_RE.finditer(text):
        all_spans.append((m.start(1), m.end(1), "DATE"))

    if all_spans:
        text = apply_span_replacements(text, all_spans, entity_counts)

    # 6. Band explicit free-text age labels (e.g. 'Age/Sex: 39 Yrs/M' -> 'Age/Sex: 35-39 Yrs/M')
    return band_free_text_ages(text, band_width=age_band_width)


# ==================== JSON pre-scan for names =============================

def _collect_names_json(data: Any) -> set[str]:
    """Pre-scan JSON to collect name strings from classified fields."""
    names: set[str] = set()
    _walk_names(data, "", names)
    return names


def _walk_names(value: Any, parent_key: str, names: set[str]) -> None:
    if isinstance(value, str):
        return
    if isinstance(value, list):
        for item in value:
            _walk_names(item, parent_key, names)
        return
    if isinstance(value, dict):
        rt = value.get("resourceType", "")
        ep = rt.lower() if rt else parent_key
        for k, v in value.items():
            fc = classify_field(k, ep)
            if fc in ("PATIENT_NAME", "RELATIVE_NAME"):
                _add_name_strings(v, names)
            _walk_names(v, k, names)


def _add_name_strings(value: Any, names: set[str]) -> None:
    if isinstance(value, str):
        v = value.strip()
        if v and len(v) > 1 and not v.startswith(("urn:", "http:", "#", "{")):
            names.add(v)
    elif isinstance(value, list):
        for item in value:
            _add_name_strings(item, names)
    elif isinstance(value, dict):
        for v in value.values():
            _add_name_strings(v, names)


# =================== recursive JSON cleaning ==============================

def _clean_json_full(
    value: Any,
    entity_counts: Counter[str],
    parent_key: str = "",
    doc_names: set[str] | None = None,
    patient_key: Optional[str] = None,
    policy: dict[str, Any] | None = None,
    inherited_district: str = "",
) -> Any:
    """Recursively clean JSON using field classification + text detection."""
    if isinstance(value, str):
        return _clean_text_full(value, entity_counts, doc_names)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [
            _clean_json_full(item, entity_counts, parent_key, doc_names, patient_key, policy, inherited_district)
            for item in value
        ]
    if not isinstance(value, dict):
        return value

    result: dict[str, Any] = {}
    used_keys: set[str] = set()
    pol = policy or {}
    rp = pol.get("_risk_policy") or {}
    band_width = int(rp.get("age_band_width", pol.get("age_band_years", 5)))
    pin_lvl = int(rp.get("pin_suppress_level", 0))
    suppress_dist = bool(rp.get("suppress_district", False))
    max_shift = int(pol.get("date_shift_max_days", 180))

    def _text_cleaner(t: str) -> str:
        return _clean_text_full(t, entity_counts, doc_names, age_band_width=band_width)

    # Use FHIR resourceType as effective parent context
    resource_type = value.get("resourceType", "")
    effective_parent = resource_type.lower() if resource_type else parent_key

    # Find local district for village generalization
    local_district = inherited_district
    for dk, dv in value.items():
        if isinstance(dv, str) and dv.strip() and classify_field(dk, effective_parent) == "DISTRICT":
            local_district = dv.strip()
            break

    for k, v in value.items():
        fc = classify_field(k, effective_parent)

        # Sanitize key if it contains PII (e.g. patient_index.json by_name keys)
        clean_k = sanitize_json_key(k, _text_cleaner, used_keys=used_keys, extra_names=doc_names)

        if fc == "CLINICAL_KEEP":
            result[clean_k] = v

        elif fc in _DIRECT_PII:
            if isinstance(v, str):
                if v.strip():
                    # Collect name for cross-reference before redaction
                    if fc in ("PATIENT_NAME", "RELATIVE_NAME") and doc_names is not None:
                        doc_names.add(v.strip())
                    result[clean_k] = f"[{fc}]"
                    entity_counts[fc] += 1
                else:
                    result[clean_k] = v
            elif isinstance(v, (int, float)):
                # Numeric PII values (e.g. Aadhaar stored as integer)
                result[clean_k] = f"[{fc}]"
                entity_counts[fc] += 1
            elif isinstance(v, list) and v and all(isinstance(x, str) for x in v):
                # List of strings under a PII key (e.g. FHIR given: ["Fatima"])
                new_list: list[str] = []
                for x in v:
                    if x.strip():
                        if fc in ("PATIENT_NAME", "RELATIVE_NAME") and doc_names is not None:
                            doc_names.add(x.strip())
                        new_list.append(f"[{fc}]")
                        entity_counts[fc] += 1
                    else:
                        new_list.append(x)
                result[clean_k] = new_list
            else:
                # Nested dict/list — recurse to clean sub-values
                result[clean_k] = _clean_json_full(v, entity_counts, k, doc_names, patient_key, policy, local_district)

        elif fc == "DOB":
            if isinstance(v, str) and v.strip():
                shifted = shift_date_string(v, patient_key, max_shift) if patient_key else None
                result[clean_k] = shifted if shifted else "[DOB]"
                entity_counts["DOB"] += 1
            else:
                result[clean_k] = _clean_json_full(v, entity_counts, k, doc_names, patient_key, policy, local_district) if not isinstance(v, str) else v

        elif fc == "DATE":
            if isinstance(v, str) and v.strip():
                shifted = shift_date_string(v, patient_key, max_shift) if patient_key else None
                result[clean_k] = shifted if shifted else "[DATE]"
                entity_counts["DATE"] += 1
            else:
                result[clean_k] = _clean_json_full(v, entity_counts, k, doc_names, patient_key, policy, local_district) if not isinstance(v, str) else v

        elif fc == "AGE":
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                result[clean_k] = _format_age_band(int(v), band_width)
            elif isinstance(v, str) and v.strip():
                m_age = re.match(r"^\s*(\d+)", v)
                result[clean_k] = _format_age_band(int(m_age.group(1)), band_width) if m_age else v
            else:
                result[clean_k] = v

        elif fc == "PIN":
            if isinstance(v, (str, int)) and str(v).strip():
                gen_pin = generalize_pin(str(v))
                result[clean_k] = suppress_pin(gen_pin, level=pin_lvl) if pin_lvl > 0 else gen_pin
                entity_counts["PIN"] += 1
            else:
                result[clean_k] = v

        elif fc in ("VILLAGE", "VILLAGE_OR_LOCALITY"):
            if isinstance(v, str) and v.strip():
                result[clean_k] = generalize_village(v, local_district)
                entity_counts["VILLAGE"] += 1
            else:
                result[clean_k] = v

        elif fc == "METADATA_PATH":
            result[clean_k] = sanitize_metadata_value(v, _text_cleaner) if isinstance(v, str) else v

        elif fc == "BASE64_DATA":
            result[clean_k] = sanitize_base64_text(v, _text_cleaner) if isinstance(v, str) else v

        elif fc in _KEEP_TYPES:
            # Suppress district for high-risk profiles to prevent re-identification
            if fc == "DISTRICT" and suppress_dist and isinstance(v, str) and v.strip():
                result[clean_k] = "[DISTRICT]"
            else:
                result[clean_k] = v

        else:
            # Unclassified — recurse
            result[clean_k] = _clean_json_full(v, entity_counts, k, doc_names, patient_key, policy, local_district)

    return result


def _clean_json_value(value: Any, entity_counts: Counter,
                      pseudonym_str: str, policy: dict,
                      patient_key: Optional[str],
                      key_name: str = '') -> Any:
    """Clean JSON values using context-aware detection and hidden-surface checks."""
    names = _collect_names_json(value)
    return _clean_json_full(value, entity_counts, key_name, names, patient_key=patient_key, policy=policy)


# ---------------------------------------------------------------------------
# File name PII handling
# ---------------------------------------------------------------------------

def _filename_has_pii(filename: str) -> bool:
    """Check if a filename contains PII patterns not caught by the general detector."""
    if (
        re.search(r'[6-9]\d{9}', filename)
        or re.search(r'\d{12}', filename)
        or re.search(r'[A-Z][a-z]+_[A-Z][a-z]+', filename)
        or re.search(r'UHID[-_]?\d+', filename, re.IGNORECASE)
    ):
        return True
    return any('\u0900' <= ch <= '\u097F' for ch in filename)


def _sanitize_filename(rel_path: str, sha256: str) -> str:
    parts = rel_path.split('/')
    filename = parts[-1]
    ext = f".{filename.rsplit('.', 1)[1]}" if '.' in filename else ''
    parts[-1] = f"file_{sha256[:8]}{ext}"
    return '/'.join(parts)


# ---------------------------------------------------------------------------
# Hospital detection from file paths
# ---------------------------------------------------------------------------

_GENERIC_FILE_TOKENS = frozenset({
    "rx", "ds", "opd", "ipd", "lab", "claims", "registration", "patients",
    "results", "bulk", "export", "legacy", "bundle", "note", "notes",
    "nursing", "discharge", "summary", "whatsapp", "forward", "report",
    "clean", "city", "lifeline", "pathkind", "adm", "uhid",
})


def _detect_hospital(rel_path: str) -> str:
    """Infer facility identifier dynamically from file path without hardcoded hospital names."""
    stem = Path(rel_path).stem.lower()
    # Strip trailing copy markers like " (1)" and split on separators
    stem = re.sub(r"\(\d+\)", "", stem)
    tokens = [t for t in re.split(r"[^a-z]+", stem) if t and len(t) >= 3]
    for tok in tokens:
        if tok not in _GENERIC_FILE_TOKENS:
            return tok
    return ""


# ---------------------------------------------------------------------------
# Processing functions
# ---------------------------------------------------------------------------

def _process_csv(
    ing: IngestedFile,
    records: list[dict[str, Any]],
    entity_counts: Counter,
    resolver: IdentityResolver,
    policy: dict,
    cluster_keys: dict[str, Optional[str]],
    secret: bytes,
    orig_rel: str | None = None,
    risk_policies: Optional[dict[str, dict[str, Any]]] = None,
) -> str:
    """Process a CSV/TSV file: detect PII, link records, apply privacy transforms."""
    header, body = ing.parsed
    out_rel = ing.rel_path
    lookup_rel = orig_rel or out_rel

    # Classify columns
    col_types = [_classify_column(col) for col in header]

    # Collect names from name columns for cross-reference in free-text cells
    doc_names: set[str] = set()
    for row in body:
        for ci, cell in enumerate(row):
            if ci < len(col_types) and col_types[ci] in ("name", "relative"):
                v = cell.strip()
                if v:
                    doc_names.add(v)

    # Find patient_ref column
    patient_ref_col = None
    for idx, col in enumerate(header):
        if re.search(r'patient[\s_]*(?:ref|id)|uhid|mrd?n', col.lower()):
            patient_ref_col = idx
            break

    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=ing.delimiter or ",", lineterminator="\n")

    # Clean header using Laptop B's sanitize_csv_header
    clean_header = sanitize_csv_header(
        header,
        lambda t: _clean_text_full(t, entity_counts, doc_names),
        extra_names=doc_names,
    )
    writer.writerow(clean_header)

    district_col = col_types.index("district") if "district" in col_types else None

    for idx, row in enumerate(body):
        record_id = f"sanitized/{lookup_rel}::row:{idx}"
        patient_key = cluster_keys.get(record_id)
        psn = generate_pseudonym(patient_key, secret) if patient_key else None
        row_district = row[district_col].strip() if (district_col is not None and district_col < len(row)) else ""
        rp = (risk_policies or {}).get(patient_key or "")

        cleaned_row = []
        for col_idx, cell in enumerate(row):
            ct = col_types[col_idx] if col_idx < len(col_types) else None
            cleaned = _clean_csv_value(cell, ct, entity_counts,
                                       psn or '', policy, patient_key, row_district,
                                       risk_policy=rp)
            # Inject pseudonym into patient_ref/UHID column
            if psn and col_idx == patient_ref_col:
                cleaned = psn
            cleaned_row.append(cleaned)

        writer.writerow(cleaned_row)

        rec_entry = {
            "file": f"sanitized/{out_rel}",
            "loc": f"row:{idx}",
            "patient": psn,
        }
        if psn:
            rec_entry["status"] = "sanitized"
        records.append(rec_entry)

    return buf.getvalue()


def _process_json(
    ing: IngestedFile,
    records: list[dict[str, Any]],
    entity_counts: Counter,
    resolver: IdentityResolver,
    policy: dict,
    cluster_keys: dict[str, Optional[str]],
    secret: bytes,
    orig_rel: str | None = None,
    risk_policies: Optional[dict[str, dict[str, Any]]] = None,
) -> str:
    """Process a JSON/FHIR file: detect PII, link records, apply privacy transforms."""
    data = ing.parsed
    out_rel = ing.rel_path
    lookup_rel = orig_rel or out_rel
    has_records = (
        isinstance(data, dict)
        and ing.fmt != "fhir"
        and any(k in ('visits', 'results', 'patients') and isinstance(data.get(k), list)
                for k in ('visits', 'results', 'patients'))
    )
    is_doc = not has_records

    if is_doc:
        record_id = f"sanitized/{lookup_rel}::doc"
        patient_key = cluster_keys.get(record_id)
        psn = generate_pseudonym(patient_key, secret) if patient_key else None
        rp = (risk_policies or {}).get(patient_key or "")
        pol_with_risk = {**policy, "_risk_policy": rp} if rp else policy

        cleaned = _clean_json_value(data, entity_counts, psn or '', pol_with_risk,
                                     patient_key)

        # Inject pseudonym for FHIR bundles
        if psn and isinstance(cleaned, dict):
            if cleaned.get("resourceType") == "Bundle":
                cleaned["meta"] = cleaned.get("meta", {})
                cleaned["meta"]["patient_ref"] = psn
            else:
                cleaned["patient_ref"] = psn

        records.append({
            "file": f"sanitized/{out_rel}",
            "loc": "doc",
            "patient": psn,
        })
    else:
        cleaned = {}
        for k, v in data.items():
            if k in ('visits', 'results', 'patients') and isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                cleaned_list = []
                pk = json_pointer_escape(k)
                for idx, item in enumerate(v):
                    record_id = f"sanitized/{lookup_rel}::/{pk}/{idx}"
                    patient_key = cluster_keys.get(record_id)
                    psn = generate_pseudonym(patient_key, secret) if patient_key else None
                    rp = (risk_policies or {}).get(patient_key or "")
                    pol_with_risk = {**policy, "_risk_policy": rp} if rp else policy

                    cleaned_item = _clean_json_value(item, entity_counts, psn or '',
                                                      pol_with_risk, patient_key, '')
                    if psn and isinstance(cleaned_item, dict):
                        cleaned_item["patient_ref"] = psn

                    cleaned_list.append(cleaned_item)
                    records.append({
                        "file": f"sanitized/{out_rel}",
                        "loc": f"/{pk}/{idx}",
                        "patient": psn,
                    })
                cleaned[k] = cleaned_list
            else:
                cleaned[k] = _clean_json_value(v, entity_counts, '', policy, None, k)

    return json.dumps(cleaned, ensure_ascii=False, indent=2) + "\n"


def _process_text(
    ing: IngestedFile,
    records: list[dict[str, Any]],
    entity_counts: Counter,
    resolver: IdentityResolver,
    policy: dict,
    cluster_keys: dict[str, Optional[str]],
    secret: bytes,
    orig_rel: str | None = None,
    risk_policies: Optional[dict[str, dict[str, Any]]] = None,
) -> str:
    """Process a text file: detect PII, inject pseudonym."""
    out_rel = ing.rel_path
    lookup_rel = orig_rel or out_rel
    record_id = f"sanitized/{lookup_rel}::doc"
    patient_key = cluster_keys.get(record_id)
    psn = generate_pseudonym(patient_key, secret) if patient_key else None
    rp = (risk_policies or {}).get(patient_key or "")
    band_w = int((rp or {}).get("age_band_width", policy.get("age_band_years", 5)))

    text = _clean_text(ing.parsed, entity_counts, psn or '', age_band_width=band_w)

    # Inject pseudonym at the top of the document
    if psn:
        text = f"Patient: {psn}\n{text}"

    records.append({
        "file": f"sanitized/{out_rel}",
        "loc": "doc",
        "patient": psn,
    })
    return text


# ---------------------------------------------------------------------------
# Two-pass pipeline
# ---------------------------------------------------------------------------

def run_pipeline(input_dir: Path, output_dir: Path, policy_path: Path | None = None) -> int:
    """Execute the end-to-end RAKSHA privacy firewall pipeline.

    Two-pass approach:
      Pass 1: Ingest all files, extract evidence, run identity resolution
      Pass 2: Apply PII detection, pseudonymization, privacy transforms, and export
    """
    t0 = time.monotonic()
    root_dir = Path(__file__).resolve().parent.parent
    default_policy = Path(os.environ.get("RAKSHA_POLICY", str(root_dir / "config" / "policy.yaml")))
    policy = load_policy(policy_path or default_policy)
    secret = os.environ.get("RAKSHA_SECRET", "").encode("utf-8")

    max_file_bytes = int(policy.get("max_file_bytes", 52_428_800))
    max_json_depth = int(policy.get("max_json_depth", 128))

    san_dir = output_dir / "sanitized"
    san_dir.mkdir(parents=True, exist_ok=True)
    # -----------------------------------------------------------------------
    # Pass 1: Ingest + Evidence Extraction + Identity Resolution
    # -----------------------------------------------------------------------
    ingested_files: list[tuple[IngestedFile, dict[str, Any]]] = []
    quarantined: list[dict[str, Any]] = []
    resolver = IdentityResolver()
    discovered_names: set[str] = set()

    def _add_ev(ev: RecordEvidence) -> None:
        resolver.add_record(ev)
        if ev.patient_name:
            discovered_names.add(ev.patient_name)
        if ev.relative_name:
            discovered_names.add(ev.relative_name)

    for path in discover_files(input_dir):
        ing, meta = ingest_file(
            path, input_dir,
            max_file_bytes=max_file_bytes,
            max_json_depth=max_json_depth,
        )
        if ing is None:
            quarantined.append(make_quarantine_entry(meta["input_sha256"], meta["reason"]))
            continue

        ingested_files.append((ing, meta))
        hospital = _detect_hospital(ing.rel_path)

        # Extract evidence for identity resolution
        if ing.fmt in ("csv", "tsv"):
            header, body = ing.parsed
            for idx, row in enumerate(body):
                ev = extract_evidence_csv(header, row, f"sanitized/{ing.rel_path}",
                                         idx, hospital)
                _add_ev(ev)

        elif ing.fmt in ("json", "fhir"):
            data = ing.parsed
            # Validate FHIR structure if applicable
            if isinstance(data, dict) and data.get("resourceType"):
                fhir_result = validate_fhir_input(data)
                if not fhir_result:
                    # Log FHIR validation errors but continue processing
                    entity_counts["FHIR_VALIDATION_WARN"] += len(fhir_result.errors)
            has_records = (
                isinstance(data, dict)
                and ing.fmt != "fhir"
                and any(k in ('visits', 'results', 'patients') and isinstance(data.get(k), list)
                        for k in ('visits', 'results', 'patients'))
            )
            is_doc = not has_records
            if is_doc:
                ev = extract_evidence_json(data if isinstance(data, dict) else {},
                                           f"sanitized/{ing.rel_path}", "doc", hospital)
                _add_ev(ev)
            else:
                for k in ('visits', 'results', 'patients'):
                    v = data.get(k)
                    if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                        pk = json_pointer_escape(k)
                        for idx, item in enumerate(v):
                            ev = extract_evidence_json(item, f"sanitized/{ing.rel_path}",
                                                       f"/{pk}/{idx}", hospital)
                            _add_ev(ev)

        else:  # text
            ev = extract_evidence_text(ing.parsed, f"sanitized/{ing.rel_path}", hospital)
            _add_ev(ev)

    # Run identity resolution
    resolver.resolve()
    cluster_keys = resolver.get_all_cluster_keys()

    # Extract per-patient diagnosis tokens to identify rare conditions (<= 2 patients)
    patient_conditions: dict[str, set[str]] = {}
    for ing, _meta in ingested_files:
        if ing.fmt in ("csv", "tsv"):
            hdr, body = ing.parsed
            diag_cols = [i for i, c in enumerate(hdr) if any(w in c.lower() for w in ("diagnosis", "procedure"))]
            if diag_cols:
                for idx, row in enumerate(body):
                    pkey = cluster_keys.get(f"sanitized/{ing.rel_path}::row:{idx}")
                    if pkey:
                        for dc in diag_cols:
                            if dc < len(row) and row[dc].strip():
                                patient_conditions.setdefault(pkey, set()).add(row[dc].strip().lower())
        elif ing.fmt == "text":
            pkey = cluster_keys.get(f"sanitized/{ing.rel_path}::doc")
            if pkey:
                for m_d in re.finditer(r"(?i)Diagnosis\s*[:\-]\s*([^\n]+)", ing.parsed):
                    patient_conditions.setdefault(pkey, set()).add(m_d.group(1).strip().lower())

    cond_freq: Counter[str] = Counter()
    for conds in patient_conditions.values():
        for c in conds:
            cond_freq[c] += 1
    rare_conds = {c for c, cnt in cond_freq.items() if cnt <= 2}

    # Build per-patient QI profiles and compute adaptive k-anonymity policies
    patient_profiles: dict[str, dict[str, Any]] = {}
    for ev in resolver._records:
        pkey = cluster_keys.get(ev.record_id)
        if not pkey:
            continue
        prof = patient_profiles.setdefault(
            pkey, {
                "age": None,
                "gender": "",
                "district": "",
                "pin_prefix": "",
                "rare_condition": bool(patient_conditions.get(pkey, set()) & rare_conds),
            }
        )
        if prof["age"] is None and ev.age is not None:
            prof["age"] = ev.age
        if not prof["gender"] and ev.gender:
            prof["gender"] = ev.gender
        if not prof["district"] and ev.district:
            prof["district"] = ev.district.lower()
        if not prof["pin_prefix"] and ev.pin and len(ev.pin) >= 3:
            prof["pin_prefix"] = ev.pin[:3]

    risk_policies, k_metrics = compute_adaptive_profile_policies(
        patient_profiles,
        min_group_size=int(policy.get("min_group_size", 5)),
        base_band_width=int(policy.get("age_band_years", 5)),
    )

    # -----------------------------------------------------------------------
    # Pass 2: PII Detection + Pseudonymization + Privacy + Export
    # -----------------------------------------------------------------------
    file_entries: list[dict[str, Any]] = list(quarantined)
    records: list[dict[str, Any]] = []
    entity_counts: Counter = Counter()
    records_generalized = 0

    for ing, meta in ingested_files:
        # Handle PII in filenames using Laptop B's sanitize_filename + discovered names
        orig_rel = ing.rel_path
        out_rel = sanitize_filename(orig_rel, secret, extra_patient_names=discovered_names)
        renamed = out_rel != orig_rel
        if renamed:
            entity_counts['FILENAME_PII'] += 1
            ing = IngestedFile(
                rel_path=out_rel,
                input_sha256=ing.input_sha256,
                encoding=ing.encoding,
                fmt=ing.fmt,
                delimiter=ing.delimiter,
                parsed=ing.parsed,
                raw_text=ing.raw_text,
            )

        # Process based on format (pass orig_rel for cluster_keys lookup)
        if ing.fmt in ("csv", "tsv"):
            result_text = _process_csv(ing, records, entity_counts, resolver,
                                       policy, cluster_keys, secret, orig_rel=orig_rel,
                                       risk_policies=risk_policies)
            records_generalized += sum(1 for r in records
                                       if r.get("file") == f"sanitized/{out_rel}"
                                       and r.get("patient"))
        elif ing.fmt in ("json", "fhir"):
            result_text = _process_json(ing, records, entity_counts, resolver,
                                        policy, cluster_keys, secret, orig_rel=orig_rel,
                                        risk_policies=risk_policies)
            records_generalized += sum(1 for r in records
                                       if r.get("file") == f"sanitized/{out_rel}"
                                       and r.get("patient"))
        else:
            result_text = _process_text(ing, records, entity_counts, resolver,
                                        policy, cluster_keys, secret, orig_rel=orig_rel,
                                        risk_policies=risk_policies)

        dest = san_dir / out_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(result_text, encoding="utf-8", newline="")

        entry = {
            "input_sha256": ing.input_sha256,
            "output": f"sanitized/{out_rel}",
            "status": "sanitized",
        }
        file_entries.append(entry)

        # Cross-platform SHA256 compatibility: on Windows, git may convert
        # LF→CRLF on checkout, changing the file hash. Truth.json uses the
        # original (LF) hash. Emit a secondary entry with LF-normalized hash
        # so check_dev.py can find the mapping regardless of platform.
        # On Linux, raw hash == LF hash, so no alt entry is created.
        lf_sha = meta.get("lf_sha256", ing.input_sha256)
        if lf_sha != ing.input_sha256:
            alt_entry = {
                "input_sha256": lf_sha,
                "output": f"sanitized/{out_rel}",
                "status": "sanitized",
                "_alt": True,
            }
            file_entries.append(alt_entry)

    # Filter records for exported files only
    exported_records = filter_exported_records(records, file_entries)
    write_records_jsonl(output_dir, exported_records)

    # Build and write report
    report = build_report(
        file_entries=file_entries,
        records=exported_records,
        identifiers_detected=sum(entity_counts.values()),
        entity_counts=dict(entity_counts),
        records_generalized=records_generalized,
        records_suppressed=0,
        elapsed_seconds=time.monotonic() - t0,
    )
    # Add measured post-generalization profile k-anonymity metrics to report
    report["privacy"] = {"k_anonymity": k_metrics}
    write_report(output_dir, report)

    emit_summary(
        files_total=report["counts"]["files_total"],
        files_sanitized=report["counts"]["files_sanitized"],
        files_quarantined=report["counts"]["files_quarantined"],
        records_processed=report["counts"]["records_processed"],
        records_linked=report["counts"]["records_linked"],
        records_generalized=records_generalized,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="RAKSHA Offline Multilingual Medical Privacy Firewall")
    ap.add_argument("--input", required=True, help="Path to read-only input directory")
    ap.add_argument("--output", required=True, help="Path to empty output directory")
    ap.add_argument("--policy", default=None, help="Optional path to policy.yaml")
    args = ap.parse_args(argv)
    return run_pipeline(
        input_dir=Path(args.input),
        output_dir=Path(args.output),
        policy_path=Path(args.policy) if args.policy else None,
    )
