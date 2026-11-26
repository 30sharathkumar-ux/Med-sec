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
    "DOB", "ADDRESS", "HOUSE", "LOCALITY", "VILLAGE",
    "PIN", "VILLAGE_OR_LOCALITY",
})

_KEEP_TYPES = frozenset({
    "CLINICAL_KEEP", "AGE", "GENDER", "AGE_SEX", "RELATION_LABEL",
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


def _clean_text(text: str, entity_counts: Counter, pseudonym_str: str = '') -> str:
    """Clean text with the full multilingual detection engine."""
    return _clean_text_full(text, entity_counts)


def _clean_csv_value(val: str, col_type: Optional[str], entity_counts: Counter,
                     pseudonym_str: str, policy: dict, patient_key: Optional[str]) -> str:
    """Clean a CSV cell based on its column classification."""
    if not val.strip():
        return val

    if col_type in {"clinical_keep", "gender", "age_sex", "relation_label",
                    "district", "tehsil"}:
        return val
    if col_type == "date":
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
                band_width = int(policy.get('age_band_years', 5))
                return age_band(age_val, band_width)
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
            return '[VILLAGE]'
        elif col_type == 'pin':
            entity_counts['PIN'] += 1
            return generalize_pin(val)
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
) -> str:
    """Comprehensive PII detection and redaction using all detection modules."""
    if not text or not text.strip():
        return text

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

    if not all_spans:
        return text

    return apply_span_replacements(text, all_spans, entity_counts)


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
) -> Any:
    """Recursively clean JSON using field classification + text detection."""
    if isinstance(value, str):
        return _clean_text_full(value, entity_counts, doc_names)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_clean_json_full(item, entity_counts, parent_key, doc_names) for item in value]
    if not isinstance(value, dict):
        return value

    result: dict[str, Any] = {}
    used_keys: set[str] = set()

    def _text_cleaner(t: str) -> str:
        return _clean_text_full(t, entity_counts, doc_names)

    # Use FHIR resourceType as effective parent context
    resource_type = value.get("resourceType", "")
    effective_parent = resource_type.lower() if resource_type else parent_key

    for k, v in value.items():
        fc = classify_field(k, effective_parent)

        # Sanitize key if it contains PII (e.g. patient_index.json by_name keys)
        clean_k = sanitize_json_key(k, _text_cleaner, used_keys=used_keys)

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
                result[clean_k] = _clean_json_full(v, entity_counts, k, doc_names)

        elif fc == "DATE":
            if isinstance(v, str) and v.strip():
                result[clean_k] = "[DATE]"
                entity_counts["DATE"] += 1
            else:
                result[clean_k] = _clean_json_full(v, entity_counts, k, doc_names) if not isinstance(v, str) else v

        elif fc == "METADATA_PATH":
            result[clean_k] = sanitize_metadata_value(v, _text_cleaner) if isinstance(v, str) else v

        elif fc == "BASE64_DATA":
            result[clean_k] = sanitize_base64_text(v, _text_cleaner) if isinstance(v, str) else v

        elif fc in _KEEP_TYPES:
            result[clean_k] = v

        else:
            # Unclassified — recurse
            result[clean_k] = _clean_json_full(v, entity_counts, k, doc_names)

    return result


def _clean_json_value(value: Any, entity_counts: Counter,
                      pseudonym_str: str, policy: dict,
                      patient_key: Optional[str],
                      key_name: str = '') -> Any:
    """Clean JSON values using context-aware detection and hidden-surface checks."""
    names = _collect_names_json(value)
    return _clean_json_full(value, entity_counts, key_name, names)


# ---------------------------------------------------------------------------
# File name PII handling
# ---------------------------------------------------------------------------

def _filename_has_pii(filename: str) -> bool:
    """Check if a filename contains PII (phone numbers, names, etc.)."""
    # Phone numbers in filenames
    if re.search(r'[6-9]\d{9}', filename):
        return True
    # Aadhaar-like patterns
    if re.search(r'\d{12}', filename):
        return True
    # Names with underscores (e.g. Anita_Sharma)
    if re.search(r'[A-Z][a-z]+_[A-Z][a-z]+', filename):
        return True
    # Devanagari in filenames
    if any('\u0900' <= ch <= '\u097F' for ch in filename):
        return True
    # UHID patterns
    if re.search(r'UHID[-_]?\d+', filename, re.IGNORECASE):
        return True
    return False


def _sanitize_filename(rel_path: str, sha256: str) -> str:
    """Generate a sanitized filename using HMAC when the original contains PII."""
    parts = rel_path.split('/')
    filename = parts[-1]
    ext = ''
    if '.' in filename:
        name_part, ext = filename.rsplit('.', 1)
        ext = '.' + ext

    # Use first 8 chars of sha256 as safe replacement
    safe_name = f"file_{sha256[:8]}{ext}"
    parts[-1] = safe_name
    return '/'.join(parts)


# ---------------------------------------------------------------------------
# Hospital detection from file paths
# ---------------------------------------------------------------------------

def _detect_hospital(rel_path: str) -> str:
    """Infer hospital name from file path for linking context."""
    path_lower = rel_path.lower()
    if 'sanjeevani' in path_lower or 'snj' in path_lower:
        return 'sanjeevani'
    if 'jeevan' in path_lower or 'jyoti' in path_lower or 'jjh' in path_lower:
        return 'jeevanjyoti'
    if 'arogya' in path_lower:
        return 'arogya'
    if 'dh' in path_lower and 'hardoi' in path_lower or 'dhh' in path_lower:
        return 'dhh'
    return ''


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
    )
    writer.writerow(clean_header)

    for idx, row in enumerate(body):
        record_id = f"sanitized/{lookup_rel}::row:{idx}"
        patient_key = cluster_keys.get(record_id)
        psn = generate_pseudonym(patient_key, secret) if patient_key else None

        cleaned_row = []
        for col_idx, cell in enumerate(row):
            ct = col_types[col_idx] if col_idx < len(col_types) else None
            cleaned = _clean_csv_value(cell, ct, entity_counts,
                                       psn or '', policy, patient_key)
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
) -> str:
    """Process a JSON/FHIR file: detect PII, link records, apply privacy transforms."""
    data = ing.parsed
    out_rel = ing.rel_path
    lookup_rel = orig_rel or out_rel
    is_doc = (
        not isinstance(data, dict)
        or ing.fmt == "fhir"
        or not any(
            isinstance(v, list) and v and all(isinstance(x, dict) for x in v)
            for v in data.values()
        )
    )

    if is_doc:
        record_id = f"sanitized/{lookup_rel}::doc"
        patient_key = cluster_keys.get(record_id)
        psn = generate_pseudonym(patient_key, secret) if patient_key else None

        cleaned = _clean_json_value(data, entity_counts, psn or '', policy,
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
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                cleaned_list = []
                pk = json_pointer_escape(k)
                for idx, item in enumerate(v):
                    record_id = f"sanitized/{lookup_rel}::/{pk}/{idx}"
                    patient_key = cluster_keys.get(record_id)
                    psn = generate_pseudonym(patient_key, secret) if patient_key else None

                    cleaned_item = _clean_json_value(item, entity_counts, psn or '',
                                                      policy, patient_key, '')
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
) -> str:
    """Process a text file: detect PII, inject pseudonym."""
    out_rel = ing.rel_path
    lookup_rel = orig_rel or out_rel
    record_id = f"sanitized/{lookup_rel}::doc"
    patient_key = cluster_keys.get(record_id)
    psn = generate_pseudonym(patient_key, secret) if patient_key else None

    text = _clean_text(ing.parsed, entity_counts, psn or '')

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
                resolver.add_record(ev)

        elif ing.fmt in ("json", "fhir"):
            data = ing.parsed
            is_doc = (
                not isinstance(data, dict)
                or ing.fmt == "fhir"
                or not any(
                    isinstance(v, list) and v and all(isinstance(x, dict) for x in v)
                    for v in data.values()
                )
            )
            if is_doc:
                ev = extract_evidence_json(data if isinstance(data, dict) else {},
                                           f"sanitized/{ing.rel_path}", "doc", hospital)
                resolver.add_record(ev)
            else:
                for k, v in data.items():
                    if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                        pk = json_pointer_escape(k)
                        for idx, item in enumerate(v):
                            ev = extract_evidence_json(item, f"sanitized/{ing.rel_path}",
                                                       f"/{pk}/{idx}", hospital)
                            resolver.add_record(ev)

        else:  # text
            ev = extract_evidence_text(ing.parsed, f"sanitized/{ing.rel_path}", hospital)
            resolver.add_record(ev)

    # Run identity resolution
    resolver.resolve()
    cluster_keys = resolver.get_all_cluster_keys()

    # -----------------------------------------------------------------------
    # Pass 2: PII Detection + Pseudonymization + Privacy + Export
    # -----------------------------------------------------------------------
    file_entries: list[dict[str, Any]] = list(quarantined)
    records: list[dict[str, Any]] = []
    entity_counts: Counter = Counter()
    records_generalized = 0

    for ing, meta in ingested_files:
        # Handle PII in filenames using Laptop B's sanitize_filename
        orig_rel = ing.rel_path
        out_rel = sanitize_filename(orig_rel, secret)
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
                                       policy, cluster_keys, secret, orig_rel=orig_rel)
            records_generalized += sum(1 for r in records
                                       if r.get("file") == f"sanitized/{out_rel}"
                                       and r.get("patient"))
        elif ing.fmt in ("json", "fhir"):
            result_text = _process_json(ing, records, entity_counts, resolver,
                                        policy, cluster_keys, secret, orig_rel=orig_rel)
        else:
            result_text = _process_text(ing, records, entity_counts, resolver,
                                        policy, cluster_keys, secret, orig_rel=orig_rel)

        dest = san_dir / out_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(result_text, encoding="utf-8", newline="")

        entry = {
            "input_sha256": ing.input_sha256,
            "output": f"sanitized/{out_rel}",
            "status": "sanitized",
        }
        file_entries.append(entry)

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
