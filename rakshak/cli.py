"""CLI and pipeline orchestration for RAKSHA."""

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
from typing import Any

from rakshak.ingestion import IngestedFile, discover_files, ingest_file
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


def pseudonym(patient_key: str, secret: bytes | None = None) -> str:
    """Generate a deterministic HMAC-SHA256 pseudonym keyed with RAKSHA_SECRET."""
    key = _get_secret() if secret is None else secret
    digest = hmac.new(key, patient_key.encode("utf-8"), hashlib.sha256).digest()
    n = int.from_bytes(digest[:5], "big")
    code = "".join(_ALPHABET[(n >> (5 * i)) & 31] for i in range(6))
    return f"PSN-{code}"


def date_shift_days(patient_key: str, policy: dict[str, Any], secret: bytes | None = None) -> int:
    """Deterministic per-patient date shift in [-max, +max], never 0."""
    m = int(policy.get("date_shift_max_days", 180))
    key = _get_secret() if secret is None else secret
    d = hmac.new(key, b"shift|" + patient_key.encode("utf-8"), hashlib.sha256).digest()
    v = int.from_bytes(d[:4], "big") % (2 * m) - m
    return v if v != 0 else 1


def shift_date(value: dt.date, patient_key: str, policy: dict[str, Any]) -> dt.date:
    return value + dt.timedelta(days=date_shift_days(patient_key, policy))


def age_band(age: int, policy: dict[str, Any]) -> str:
    w = int(policy.get("age_band_years", 5))
    lo = (age // w) * w
    return f"{lo}-{lo + w - 1}"


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


# ====================== format processors =================================

def _process_csv(
    ing: IngestedFile,
    records: list[dict[str, Any]],
    entity_counts: Counter[str],
    secret: bytes,
    out_rel: str,
) -> str:
    header, body = ing.parsed

    # Classify columns
    col_classes = [classify_field(h) for h in header]

    # First pass: collect names from name columns for cross-reference
    doc_names: set[str] = set()
    for row in body:
        for ci, cell in enumerate(row):
            if ci < len(col_classes) and col_classes[ci] in ("PATIENT_NAME", "RELATIVE_NAME"):
                v = cell.strip()
                if v:
                    doc_names.add(v)

    def _text_cleaner(t: str) -> str:
        return _clean_text_full(t, entity_counts, doc_names)

    # Sanitize headers (catches PII embedded in column names like ward_vitals_sheet)
    clean_header = sanitize_csv_header(header, _text_cleaner)

    # Process rows
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=ing.delimiter or ",", lineterminator="\n")
    writer.writerow(clean_header)

    for idx, row in enumerate(body):
        clean_row: list[str] = []
        for ci, cell in enumerate(row):
            ct = col_classes[ci] if ci < len(col_classes) else None

            if not cell.strip():
                clean_row.append(cell)
            elif ct == "CLINICAL_KEEP":
                clean_row.append(cell)
            elif ct in _DIRECT_PII:
                clean_row.append(f"[{ct}]")
                entity_counts[ct] += 1
            elif ct == "DATE":
                clean_row.append("[DATE]")
                entity_counts["DATE"] += 1
            elif ct in _KEEP_TYPES:
                clean_row.append(cell)
            elif ct == "METADATA_PATH":
                clean_row.append(sanitize_metadata_value(cell, _text_cleaner))
            elif ct == "BASE64_DATA":
                clean_row.append(sanitize_base64_text(cell, _text_cleaner))
            else:
                # Unclassified column — run full text cleaner
                clean_row.append(_clean_text_full(cell, entity_counts, doc_names))

        writer.writerow(clean_row)
        records.append({"file": f"sanitized/{out_rel}", "loc": f"row:{idx}", "patient": None})

    return buf.getvalue()


def _process_json(
    ing: IngestedFile,
    records: list[dict[str, Any]],
    entity_counts: Counter[str],
    secret: bytes,
    out_rel: str,
) -> str:
    data = ing.parsed

    # Pre-scan to collect all names for cross-reference
    doc_names = _collect_names_json(data)

    # Build records list (same logic as before)
    is_doc = (
        not isinstance(data, dict)
        or ing.fmt == "fhir"
        or not any(
            isinstance(v, list) and v and all(isinstance(x, dict) for x in v)
            for v in data.values()
        )
    )
    if is_doc:
        records.append({"file": f"sanitized/{out_rel}", "loc": "doc", "patient": None})
    else:
        for k, v in data.items():
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                pk = json_pointer_escape(k)
                for idx, _ in enumerate(v):
                    records.append({"file": f"sanitized/{out_rel}", "loc": f"/{pk}/{idx}", "patient": None})

    cleaned = _clean_json_full(data, entity_counts, "", doc_names)
    return json.dumps(cleaned, ensure_ascii=False, indent=2) + "\n"


def _process_text(
    ing: IngestedFile,
    records: list[dict[str, Any]],
    entity_counts: Counter[str],
    out_rel: str,
) -> str:
    records.append({"file": f"sanitized/{out_rel}", "loc": "doc", "patient": None})
    return _clean_text_full(ing.parsed, entity_counts)


# ====================== pipeline ==========================================

def _process_ingested(
    ing: IngestedFile,
    records: list[dict[str, Any]],
    entity_counts: Counter[str],
    secret: bytes,
    out_rel: str,
) -> str:
    if ing.fmt in ("csv", "tsv"):
        return _process_csv(ing, records, entity_counts, secret, out_rel)
    if ing.fmt in ("json", "fhir"):
        return _process_json(ing, records, entity_counts, secret, out_rel)
    return _process_text(ing, records, entity_counts, out_rel)


def run_pipeline(input_dir: Path, output_dir: Path, policy_path: Path | None = None) -> int:
    """Execute the end-to-end RAKSHA privacy firewall pipeline."""
    t0 = time.monotonic()
    root_dir = Path(__file__).resolve().parent.parent
    default_policy = Path(os.environ.get("RAKSHA_POLICY", str(root_dir / "config" / "policy.yaml")))
    policy = load_policy(policy_path or default_policy)

    max_file_bytes = int(policy.get("max_file_bytes", 52_428_800))
    max_json_depth = int(policy.get("max_json_depth", 128))

    san_dir = output_dir / "sanitized"
    san_dir.mkdir(parents=True, exist_ok=True)

    secret = _get_secret()
    file_entries: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    entity_counts: Counter[str] = Counter()

    for path in discover_files(input_dir):
        ing, meta = ingest_file(
            path,
            input_dir,
            max_file_bytes=max_file_bytes,
            max_json_depth=max_json_depth,
        )
        if ing is None:
            file_entries.append(make_quarantine_entry(meta["input_sha256"], meta["reason"]))
            continue

        # Sanitize filename if it contains PII (names, MRN, phone in stem)
        out_rel = sanitize_filename(ing.rel_path, secret)

        result_text = _process_ingested(ing, records, entity_counts, secret, out_rel)
        dest = san_dir / out_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(result_text, encoding="utf-8", newline="")
        file_entries.append(
            {
                "input_sha256": ing.input_sha256,
                "output": f"sanitized/{out_rel}",
                "status": "sanitized",
            }
        )

    exported_records = filter_exported_records(records, file_entries)
    write_records_jsonl(output_dir, exported_records)

    report = build_report(
        file_entries=file_entries,
        records=exported_records,
        identifiers_detected=sum(entity_counts.values()),
        entity_counts=dict(entity_counts),
        records_generalized=0,
        records_suppressed=0,
        elapsed_seconds=time.monotonic() - t0,
    )
    write_report(output_dir, report)

    emit_summary(
        files_total=report["counts"]["files_total"],
        files_sanitized=report["counts"]["files_sanitized"],
        files_quarantined=report["counts"]["files_quarantined"],
        records_processed=report["counts"]["records_processed"],
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
