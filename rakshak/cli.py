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

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

# Baseline regexes preserved during Stage 2-3 while structured/multilingual detection is built in Stages 4-6.
_BASELINE_PATTERNS = [
    ("PHONE", re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")),
    ("AADHAAR", re.compile(r"(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)")),
    ("EMAIL", re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")),
    ("PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    ("NAME", re.compile(r"(?i)(?<=name:)\s*[^\n,;|]+")),
]


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
    """Read RAKSHA_SECRET dynamically at runtime (never cache across secret changes or log)."""
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


def _clean_text_baseline(text: str, entity_counts: Counter[str]) -> str:
    for kind, rx in _BASELINE_PATTERNS:
        repl = f"[{kind}]" if kind != "NAME" else " [NAME]"
        text, n = rx.subn(repl, text)
        if n:
            entity_counts[kind] += n
    return text


def _clean_json_baseline(value: Any, entity_counts: Counter[str]) -> Any:
    if isinstance(value, str):
        return _clean_text_baseline(value, entity_counts)
    if isinstance(value, list):
        return [_clean_json_baseline(x, entity_counts) for x in value]
    if isinstance(value, dict):
        return {
            _clean_text_baseline(k, entity_counts): _clean_json_baseline(v, entity_counts)
            for k, v in value.items()
        }
    return value


def _process_ingested(
    ing: IngestedFile,
    records: list[dict[str, Any]],
    entity_counts: Counter[str],
) -> str:
    out_rel = ing.rel_path
    if ing.fmt in ("csv", "tsv"):
        header, body = ing.parsed
        buf = io.StringIO()
        writer = csv.writer(buf, delimiter=ing.delimiter or ",", lineterminator="\n")
        writer.writerow(header)
        for idx, row in enumerate(body):
            writer.writerow([_clean_text_baseline(c, entity_counts) for c in row])
            records.append({"file": f"sanitized/{out_rel}", "loc": f"row:{idx}", "patient": None})
        return buf.getvalue()

    if ing.fmt in ("json", "fhir"):
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
            records.append({"file": f"sanitized/{out_rel}", "loc": "doc", "patient": None})
        else:
            for k, v in data.items():
                if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                    pk = json_pointer_escape(k)
                    for idx, _ in enumerate(v):
                        records.append({"file": f"sanitized/{out_rel}", "loc": f"/{pk}/{idx}", "patient": None})
        cleaned = _clean_json_baseline(data, entity_counts)
        return json.dumps(cleaned, ensure_ascii=False, indent=2) + "\n"

    records.append({"file": f"sanitized/{out_rel}", "loc": "doc", "patient": None})
    return _clean_text_baseline(ing.parsed, entity_counts)


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

        result_text = _process_ingested(ing, records, entity_counts)
        dest = san_dir / ing.rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(result_text, encoding="utf-8", newline="")
        file_entries.append(
            {
                "input_sha256": ing.input_sha256,
                "output": f"sanitized/{ing.rel_path}",
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
