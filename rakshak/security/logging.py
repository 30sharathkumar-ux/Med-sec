"""PII-free operational logging and secret-safety helpers."""

from __future__ import annotations

import logging
import sys


def get_logger(name: str = "rakshak") -> logging.Logger:
    """Return a stderr logger constrained to safe operational summaries only."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.WARNING)
        logger.propagate = False
    return logger


def emit_summary(
    files_total: int,
    files_sanitized: int,
    files_quarantined: int,
    records_processed: int,
) -> None:
    """Print strictly numeric aggregate counts to stdout (never filenames, PII, or secrets)."""
    print(
        f"files {files_total} sanitized {files_sanitized} "
        f"quarantined {files_quarantined} records {records_processed}"
    )


def contains_secret(text: str, secret: bytes) -> bool:
    """Return True if a non-empty secret appears in text."""
    if not secret:
        return False
    return secret.decode("utf-8", errors="ignore") in text
