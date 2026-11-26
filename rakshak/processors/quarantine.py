"""Safe fail-closed quarantine entry builder."""

from __future__ import annotations

from typing import Any


def sanitize_reason(reason: str) -> str:
    """Normalize a quarantine reason into a safe ASCII identifier (never file contents)."""
    cleaned = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in reason.strip())
    cleaned = cleaned.strip("_")
    return cleaned or "quarantined_error"


def make_quarantine_entry(input_sha256: str, reason: str) -> dict[str, Any]:
    """Return a report.json file record for a quarantined input file."""
    return {
        "input_sha256": input_sha256,
        "output": None,
        "status": "quarantined",
        "reason": sanitize_reason(reason),
    }
