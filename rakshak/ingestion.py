"""Robust, bounded file discovery, format sniffing, and safe parsing."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rakshak.encoding import decode_bytes

SUPPORTED_EXTENSIONS = frozenset({".csv", ".tsv", ".json", ".txt"})
_XML_RE = re.compile(r"^\s*(?:<\?xml\b|<ClinicalDocument\b|<[A-Za-z_][\w:-]*(?:\s+xmlns=|\s*>))")


class IngestionError(ValueError):
    """Controlled ingestion failure mapped to a safe, PII-free quarantine reason."""

    def __init__(self, reason: str) -> None:
        safe = reason if reason.isidentifier() else "ingestion_error"
        super().__init__(safe)
        self.reason = safe


@dataclass(frozen=True)
class IngestedFile:
    """Validated and parsed representation of an eligible input file."""

    rel_path: str
    input_sha256: str
    encoding: str
    fmt: str  # "csv", "tsv", "json", "fhir", "text"
    delimiter: str | None
    parsed: Any
    raw_text: str


def discover_files(input_dir: Path) -> list[Path]:
    """Return all regular files under input_dir in deterministic POSIX-path order."""
    files = [p for p in input_dir.rglob("*") if p.is_file()]
    files.sort(key=lambda p: p.relative_to(input_dir).as_posix())
    return files


def check_json_depth(text: str, max_depth: int = 128) -> int:
    """Compute nesting depth of JSON braces/brackets iteratively without recursion."""
    depth = 0
    max_seen = 0
    in_string = False
    escape = False
    for ch in text:
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            depth += 1
            if depth > max_seen:
                max_seen = depth
            if depth > max_depth:
                raise IngestionError("excessive_nesting")
        elif ch in "}]":
            if depth > 0:
                depth -= 1
    return max_seen


def _looks_like_json(text: str) -> bool:
    """Return True if text parses as a JSON object or array (bounded depth)."""
    stripped = text.lstrip()
    if not stripped or stripped[0] not in "{[":
        return False
    try:
        check_json_depth(stripped, max_depth=128)
        parsed = json.loads(stripped)
        return isinstance(parsed, (dict, list))
    except (IngestionError, json.JSONDecodeError, ValueError):
        return False


def sniff_format(ext: str, text: str) -> str:
    """Determine actual content format and reject mismatched or unsupported payloads."""
    stripped = text.lstrip()
    if not stripped:
        raise IngestionError("empty_file")

    if _XML_RE.match(stripped):
        raise IngestionError("unsupported_format")

    if ext == ".json":
        check_json_depth(text, max_depth=128)
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise IngestionError("JSONDecodeError") from exc
        if isinstance(data, dict) and data.get("resourceType") == "Bundle":
            if not isinstance(data.get("entry"), list):
                raise IngestionError("invalid_fhir_bundle")
            return "fhir"
        return "json"

    if ext in (".csv", ".tsv"):
        if _looks_like_json(stripped):
            raise IngestionError("format_mismatch")
        return "tsv" if ext == ".tsv" else "csv"

    if ext == ".txt":
        return "text"

    raise IngestionError("unsupported_format")


def parse_csv_tsv(text: str, delimiter: str) -> tuple[list[str], list[list[str]]]:
    """Parse CSV/TSV deterministically, preserving header and row structure."""
    csv.field_size_limit(10_000_000)
    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter))
    except csv.Error as exc:
        raise IngestionError("csv_parse_error") from exc
    if not rows or not any(cell.strip() for row in rows for cell in row):
        raise IngestionError("empty_file")
    return rows[0], rows[1:]


def ingest_file(
    path: Path,
    input_root: Path,
    max_file_bytes: int = 52_428_800,
    max_json_depth: int = 128,
) -> tuple[IngestedFile | None, dict[str, Any]]:
    """Safely read, decode, sniff, and parse one file.

    Returns (IngestedFile, base_meta) on success, or (None, error_meta) on quarantine.
    Never exposes file paths, names, or raw content in error_meta.
    """
    rel = path.relative_to(input_root).as_posix()
    raw = path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    # Also compute LF-normalized hash for cross-platform truth.json compat
    lf_raw = raw.replace(b"\r\n", b"\n")
    lf_sha256 = hashlib.sha256(lf_raw).hexdigest()
    meta: dict[str, Any] = {"input_sha256": sha256, "lf_sha256": lf_sha256, "rel_path": rel}

    if len(raw) > max_file_bytes:
        return None, {"input_sha256": sha256, "reason": "file_too_large"}

    ext = path.suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        return None, {"input_sha256": sha256, "reason": "unsupported_format"}

    decoded, dec_err = decode_bytes(raw)
    if decoded is None:
        return None, {"input_sha256": sha256, "reason": dec_err or "undecodable_text"}

    try:
        if ext == ".json":
            check_json_depth(decoded.text, max_depth=max_json_depth)
        fmt = sniff_format(ext, decoded.text)
        delimiter: str | None = None
        if fmt in ("csv", "tsv"):
            delimiter = "\t" if fmt == "tsv" else ","
            parsed = parse_csv_tsv(decoded.text, delimiter)
        elif fmt in ("json", "fhir"):
            parsed = json.loads(decoded.text)
        else:
            parsed = decoded.text
    except IngestionError as exc:
        return None, {"input_sha256": sha256, "reason": exc.reason}
    except RecursionError:
        return None, {"input_sha256": sha256, "reason": "excessive_nesting"}
    except UnicodeError:
        return None, {"input_sha256": sha256, "reason": "undecodable_text"}

    return (
        IngestedFile(
            rel_path=rel,
            input_sha256=sha256,
            encoding=decoded.encoding,
            fmt=fmt,
            delimiter=delimiter,
            parsed=parsed,
            raw_text=decoded.text,
        ),
        meta,
    )
