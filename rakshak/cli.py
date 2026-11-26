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


# ---------------------------------------------------------------------------
# Baseline PII detection patterns (kept from Stage 2-3; Laptop B will enhance)
# ---------------------------------------------------------------------------

_BASELINE_PATTERNS = [
    ("PHONE", re.compile(r'(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)')),
    ("AADHAAR", re.compile(r'(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)')),
    ("AADHAAR_MASKED", re.compile(r'(?i)\bXXXX[\s-]?XXXX[\s-]?\d{4}\b')),
    ("EMAIL", re.compile(r'[\w.+-]+@[\w-]+\.[\w.]+')),
    ("PAN", re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b')),
    ("ABHA", re.compile(r'(?<!\d)\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}(?!\d)')),
    ("INSURANCE_ID", re.compile(r'\b(?:INS|POL|PLY)[-/]?\d{6,15}\b', re.IGNORECASE)),
]

# Base64 detection for embedded PII
_BASE64_RE = re.compile(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

def _decode_and_clean_base64(text: str, entity_counts: Counter) -> str:
    """Find base64 blobs, decode them, clean PII, re-encode."""
    import base64
    def _replace_b64(m: re.Match) -> str:
        blob = m.group(0)
        try:
            decoded = base64.b64decode(blob).decode('utf-8', errors='ignore')
            if len(decoded) > 10:
                # Check if decoded content has PII
                has_pii = False
                for kind, rx in _BASELINE_PATTERNS:
                    if rx.search(decoded):
                        has_pii = True
                        break
                # Also check for name-like patterns
                if re.search(r'[A-Z][a-z]+\s+[A-Z][a-z]+', decoded):
                    has_pii = True
                if has_pii:
                    entity_counts['BASE64_PII'] += 1
                    cleaned = _clean_text_internal(decoded, entity_counts)
                    return base64.b64encode(cleaned.encode('utf-8')).decode('ascii')
        except Exception:
            pass
        return blob
    return _BASE64_RE.sub(_replace_b64, text)


def _clean_text_internal(text: str, entity_counts: Counter, pseudonym_str: str = '') -> str:
    """Core text cleaning without base64 handling (to avoid recursion)."""
    for kind, rx in _BASELINE_PATTERNS:
        text, n = rx.subn(f"[{kind}]", text)
        if n:
            entity_counts[kind] += n

    def _replace_name(m: re.Match) -> str:
        entity_counts['PATIENT_NAME'] += 1
        prefix = m.group(0)[:m.start(1) - m.start(0)]
        replacement = pseudonym_str if pseudonym_str else '[NAME]'
        return prefix + replacement

    text = _NAME_LABEL_RE.sub(_replace_name, text)

    def _replace_relative(m: re.Match) -> str:
        entity_counts['RELATIVE_NAME'] += 1
        prefix = m.group(0)[:m.start(1) - m.start(0)]
        return prefix + '[RELATIVE]'

    text = _RELATIVE_LABEL_RE.sub(_replace_relative, text)
    return text

# Name detection patterns for text
_NAME_LABEL_RE = re.compile(
    r'(?:(?:Patient|Pt\.?|Name|नाम|मरीज|Patient\'?s?\s*Name)\s*[:：]\s*)([^\n,;|]+)',
    re.IGNORECASE,
)
_RELATIVE_LABEL_RE = re.compile(
    r'(?:(?:S|D|W|C)\s*/\s*(?:o|O)\s+)([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F\s.]+?)(?:\s*[,;|\n]|$)',
    re.IGNORECASE,
)

# Column/key classifiers for structured PII detection
_PII_COLUMN_PATTERNS = {
    'name': re.compile(
        r'(?:patient|mareez|mariz)[\s_]*(?:name|naam|ka\s*naam)?'
        r'|^name$|^naam$|^full[\s_]*name$|patient.s?\s*name'
        r'|first[\s_]*name|last[\s_]*name|local',
        re.IGNORECASE,
    ),
    'phone': re.compile(r'mobile|phone|contact|दूरभाष|मोबाइल|fone|tel', re.IGNORECASE),
    'aadhaar': re.compile(r'aadh?a?r|आधार', re.IGNORECASE),
    'abha': re.compile(r'abha[\s_]*(?:no|number|id|address)?', re.IGNORECASE),
    'mrn': re.compile(
        r'uhid|mrd?n|ipd[\s_]*(?:no|number)?|opd[\s_]*(?:no|number)?'
        r'|reg[\s_]*(?:no|number|id)?|patient[\s_]*(?:id|ref)',
        re.IGNORECASE,
    ),
    'email': re.compile(r'email|e[\s_-]*mail', re.IGNORECASE),
    'pan': re.compile(r'^pan$|pan[\s_]*(?:no|number|card)', re.IGNORECASE),
    'insurance': re.compile(r'insurance|bima|policy[\s_]*(?:no|number|id)', re.IGNORECASE),
    'relative': re.compile(
        r'relative|guardian|father|mother|husband|wife|spouse'
        r'|pita[\s_]*(?:ka\s*naam)?|mata|pati|patni|relation[\s_]*name',
        re.IGNORECASE,
    ),
    'address': re.compile(r'address|pata|पता|निवास|line|street|rasta|gali', re.IGNORECASE),
    'village': re.compile(r'village|gram|gaon|गाँव|ग्राम|mohalla|city|town|sheher', re.IGNORECASE),
    'house': re.compile(r'house|makan|h\.?\s*no', re.IGNORECASE),
    'landmark': re.compile(r'landmark|near|opp', re.IGNORECASE),
    'dob': re.compile(r'dob|date[\s_]*of[\s_]*birth|janm[\s_]*tithi|जन्म', re.IGNORECASE),
    'age': re.compile(r'^age$|^umar$|^उम्र$|^आयु$', re.IGNORECASE),
    'pin': re.compile(r'pin[\s_]*(?:code)?|postal|डाक|zip', re.IGNORECASE),
}

# Columns to generalize (not remove entirely)
_GENERALIZE_COLUMNS = {'age', 'dob', 'village', 'pin', 'address', 'house', 'landmark'}

# Columns that are PII to replace
_REPLACE_COLUMNS = {'name', 'phone', 'aadhaar', 'abha', 'mrn', 'email', 'pan',
                     'insurance', 'relative'}

# Metadata keys that may contain PII
_METADATA_PII_KEYS = re.compile(
    r'source[\s_]*path|file[\s_]*name|export[\s_]*path|original[\s_]*file',
    re.IGNORECASE,
)


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


# ---------------------------------------------------------------------------
# PII Cleaning
# ---------------------------------------------------------------------------

def _classify_column(col_name: str) -> Optional[str]:
    """Classify a column/key name as a PII type or None."""
    col_lower = col_name.strip().lower()
    for pii_type, pattern in _PII_COLUMN_PATTERNS.items():
        if pattern.search(col_lower):
            return pii_type
    return None


def _clean_text(text: str, entity_counts: Counter, pseudonym_str: str = '') -> str:
    """Replace detected identifiers with typed placeholders, including base64."""
    # First handle base64-embedded PII
    text = _decode_and_clean_base64(text, entity_counts)
    # Then clean regular text PII
    return _clean_text_internal(text, entity_counts, pseudonym_str)


def _clean_csv_value(val: str, col_type: Optional[str], entity_counts: Counter,
                     pseudonym_str: str, policy: dict, patient_key: Optional[str]) -> str:
    """Clean a CSV cell based on its column classification."""
    if not val.strip():
        return val

    if col_type in _REPLACE_COLUMNS:
        entity_counts[col_type.upper()] += 1
        if col_type == 'name':
            entity_counts['PATIENT_NAME'] += 1
            return pseudonym_str if pseudonym_str else '[NAME]'
        elif col_type == 'relative':
            entity_counts['RELATIVE_NAME'] += 1
            return '[RELATIVE]'
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
            return '[INSURANCE]'
        return '[REDACTED]'

    if col_type in _GENERALIZE_COLUMNS:
        if col_type == 'age':
            try:
                age_val = int(re.match(r'(\d+)', val).group(1))
                band_width = int(policy.get('age_band_years', 5))
                return age_band(age_val, band_width)
            except (ValueError, AttributeError):
                return val
        elif col_type == 'dob' and patient_key:
            shifted = shift_date_string(val, patient_key,
                                        int(policy.get('date_shift_max_days', 180)))
            if shifted:
                entity_counts['DOB'] += 1
                return shifted
            return val
        elif col_type == 'village':
            entity_counts['VILLAGE'] += 1
            return '[VILLAGE]'
        elif col_type == 'pin':
            entity_counts['PIN'] += 1
            return generalize_pin(val)
        elif col_type == 'address':
            entity_counts['ADDRESS'] += 1
            # Generalize: remove house numbers, ward numbers, landmarks
            from rakshak.privacy.transforms import generalize_address as gen_addr
            return gen_addr(val)
        elif col_type in ('house', 'landmark'):
            entity_counts['HOUSE'] += 1
            return '[SUPPRESSED]'
        return val

    # For unclassified columns, apply baseline text detection
    return _clean_text(val, entity_counts, pseudonym_str)


def _clean_json_value(value: Any, entity_counts: Counter,
                      pseudonym_str: str, policy: dict,
                      patient_key: Optional[str],
                      key_name: str = '') -> Any:
    """Recursively clean JSON values based on key classification."""
    if isinstance(value, str):
        col_type = _classify_column(key_name) if key_name else None

        # Check for metadata PII paths
        if key_name and _METADATA_PII_KEYS.search(key_name):
            entity_counts['METADATA'] += 1
            return '[METADATA_REDACTED]'

        if col_type:
            return _clean_csv_value(value, col_type, entity_counts,
                                    pseudonym_str, policy, patient_key)
        return _clean_text(value, entity_counts, pseudonym_str)

    if isinstance(value, (int, float)):
        col_type = _classify_column(key_name) if key_name else None
        if col_type == 'aadhaar':
            entity_counts['AADHAAR'] += 1
            return '[AADHAAR]'
        if col_type == 'phone':
            entity_counts['PHONE'] += 1
            return '[PHONE]'
        return value

    if isinstance(value, list):
        return [_clean_json_value(x, entity_counts, pseudonym_str, policy,
                                  patient_key, key_name)
                for x in value]

    if isinstance(value, dict):
        result = {}
        for k, v in value.items():
            # Clean PII from JSON keys
            clean_key = k
            if isinstance(k, str):
                # Check if key itself contains PII (names, phones, paths)
                if re.search(r'[6-9]\d{9}', k) or re.search(r'[A-Z][a-z]+_[A-Z][a-z]+', k):
                    clean_key = _clean_text(k, entity_counts)
                    entity_counts['KEY_PII'] = entity_counts.get('KEY_PII', 0) + 1
                elif _METADATA_PII_KEYS.search(k):
                    pass  # key name is fine, value will be cleaned
                elif any('\u0900' <= ch <= '\u097F' for ch in k):
                    # Devanagari in keys — might be a patient name used as key
                    clean_key = _clean_text(k, entity_counts)
            result[clean_key] = _clean_json_value(v, entity_counts, pseudonym_str,
                                                   policy, patient_key, k)
        return result

    return value


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
) -> str:
    """Process a CSV/TSV file: detect PII, link records, apply privacy transforms."""
    header, body = ing.parsed
    out_rel = ing.rel_path
    hospital = _detect_hospital(ing.rel_path)

    # Classify columns
    col_types = [_classify_column(col) for col in header]

    # Find or add patient_ref column
    patient_ref_col = None
    for idx, col in enumerate(header):
        if re.search(r'patient[\s_]*(?:ref|id)|uhid|mrd?n', col.lower()):
            patient_ref_col = idx
            break

    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=ing.delimiter or ",", lineterminator="\n")

    # Clean header (rename only if header itself contains PII)
    clean_header = []
    for col in header:
        # Check if the header cell itself contains PII values (not just column names)
        h_cleaned = col
        for kind, rx in _BASELINE_PATTERNS:
            h_cleaned, n = rx.subn(f"[{kind}]", h_cleaned)
            if n:
                entity_counts[f'HEADER_{kind}'] = entity_counts.get(f'HEADER_{kind}', 0) + n
        # Check for name-like content in headers (e.g. "Patient: Ramesh Kumar" as header)
        if re.search(r'[A-Z][a-z]+\s+[A-Z][a-z]+', h_cleaned) and not _classify_column(h_cleaned):
            h_cleaned = _clean_text_internal(h_cleaned, entity_counts)
        clean_header.append(h_cleaned)
    writer.writerow(clean_header)

    for idx, row in enumerate(body):
        record_id = f"sanitized/{out_rel}::row:{idx}"
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

        # If no existing patient_ref column, we still write the pseudonym
        # via records.jsonl consistency requirement
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
) -> str:
    """Process a JSON/FHIR file: detect PII, link records, apply privacy transforms."""
    data = ing.parsed
    out_rel = ing.rel_path
    has_records = (
        isinstance(data, dict)
        and ing.fmt != "fhir"
        and any(k in ('visits', 'results', 'patients') and isinstance(data.get(k), list)
                for k in ('visits', 'results', 'patients'))
    )
    is_doc = not has_records

    if is_doc:
        record_id = f"sanitized/{out_rel}::doc"
        patient_key = cluster_keys.get(record_id)
        psn = generate_pseudonym(patient_key, secret) if patient_key else None

        cleaned = _clean_json_value(data, entity_counts, psn or '', policy,
                                     patient_key)

        # Inject pseudonym for FHIR bundles
        if psn and isinstance(cleaned, dict):
            if cleaned.get("resourceType") == "Bundle":
                # Add patient_ref to FHIR bundle
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
                    record_id = f"sanitized/{out_rel}::/{pk}/{idx}"
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
) -> str:
    """Process a text file: detect PII, inject pseudonym."""
    out_rel = ing.rel_path
    record_id = f"sanitized/{out_rel}::doc"
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

        # Output relative path (handle PII in filename upfront for consistency)
        out_rel = ing.rel_path
        if _filename_has_pii(Path(out_rel).name):
            out_rel = _sanitize_filename(out_rel, ing.input_sha256)

        # Extract evidence for identity resolution
        if ing.fmt in ("csv", "tsv"):
            header, body = ing.parsed
            for idx, row in enumerate(body):
                ev = extract_evidence_csv(header, row, f"sanitized/{out_rel}",
                                         idx, hospital)
                resolver.add_record(ev)

        elif ing.fmt in ("json", "fhir"):
            data = ing.parsed
            has_records = (
                isinstance(data, dict)
                and ing.fmt != "fhir"
                and any(k in ('visits', 'results', 'patients') and isinstance(data.get(k), list)
                        for k in ('visits', 'results', 'patients'))
            )
            is_doc = not has_records
            if is_doc:
                ev = extract_evidence_json(data if isinstance(data, dict) else {},
                                           f"sanitized/{out_rel}", "doc", hospital)
                resolver.add_record(ev)
            else:
                for k in ('visits', 'results', 'patients'):
                    v = data.get(k)
                    if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                        pk = json_pointer_escape(k)
                        for idx, item in enumerate(v):
                            ev = extract_evidence_json(item, f"sanitized/{out_rel}",
                                                       f"/{pk}/{idx}", hospital)
                            resolver.add_record(ev)

        else:  # text
            ev = extract_evidence_text(ing.parsed, f"sanitized/{out_rel}", hospital)
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
        # Handle PII in filenames
        out_rel = ing.rel_path
        renamed = False
        if _filename_has_pii(Path(out_rel).name):
            new_rel = _sanitize_filename(out_rel, ing.input_sha256)
            out_rel = new_rel
            renamed = True
            entity_counts['FILENAME_PII'] += 1

        # Create a modified IngestedFile with potentially renamed path
        if renamed:
            ing = IngestedFile(
                rel_path=out_rel,
                input_sha256=ing.input_sha256,
                encoding=ing.encoding,
                fmt=ing.fmt,
                delimiter=ing.delimiter,
                parsed=ing.parsed,
                raw_text=ing.raw_text,
            )

        # Process based on format
        if ing.fmt in ("csv", "tsv"):
            result_text = _process_csv(ing, records, entity_counts, resolver,
                                       policy, cluster_keys, secret)
            records_generalized += sum(1 for r in records
                                       if r.get("file") == f"sanitized/{out_rel}"
                                       and r.get("patient"))
        elif ing.fmt in ("json", "fhir"):
            result_text = _process_json(ing, records, entity_counts, resolver,
                                        policy, cluster_keys, secret)
        else:
            result_text = _process_text(ing, records, entity_counts, resolver,
                                        policy, cluster_keys, secret)

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
