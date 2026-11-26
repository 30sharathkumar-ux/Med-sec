"""Deterministic records.jsonl builder and RFC 6901 JSON pointer utilities."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def json_pointer_escape(token: str) -> str:
    """Escape a single RFC 6901 JSON Pointer reference token."""
    return token.replace("~", "~0").replace("/", "~1")


def filter_exported_records(
    records: list[dict[str, Any]],
    file_entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Keep only records belonging to files that were actually exported to sanitized/."""
    exported = {e["output"] for e in file_entries if e.get("output")}
    return [r for r in records if r.get("file") in exported]


def write_records_jsonl(out_dir: Path, records: list[dict[str, Any]]) -> None:
    """Write records.jsonl deterministically in UTF-8."""
    with open(out_dir / "records.jsonl", "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
