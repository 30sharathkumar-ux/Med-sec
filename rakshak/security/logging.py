"""Enhanced PII-free operational logging, secret guarding, and audit trail.

Security requirements:
 - RAKSHA_SECRET is never written to disk, logs, or output
 - No raw patient identity appears in logs
 - Only aggregate counts go to stdout/stderr
 - Intermediate data is wiped after processing
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Any


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
    records_linked: int = 0,
    records_generalized: int = 0,
) -> None:
    """Print strictly numeric aggregate counts to stdout (never filenames, PII, or secrets)."""
    print(
        f"files {files_total} sanitized {files_sanitized} "
        f"quarantined {files_quarantined} records {records_processed} "
        f"linked {records_linked} generalized {records_generalized}"
    )


def contains_secret(text: str, secret: bytes | None = None) -> bool:
    """Return True if a non-empty secret appears in text."""
    if secret is None:
        secret = os.environ.get("RAKSHA_SECRET", "").encode("utf-8")
    if not secret:
        return False
    return secret.decode("utf-8", errors="ignore") in text


def sanitize_log_message(msg: str) -> str:
    """Remove any potential PII from a log message, keeping only safe identifiers."""
    # Strip anything that looks like a phone number
    import re
    msg = re.sub(r'\b\d{10,12}\b', '[REDACTED]', msg)
    # Strip anything that looks like an Aadhaar
    msg = re.sub(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '[REDACTED]', msg)
    # Check for secret leakage
    if contains_secret(msg):
        return "[LOG SUPPRESSED: potential secret leakage]"
    return msg


def secure_wipe(data: bytearray) -> None:
    """Overwrite a bytearray with zeros for secure deletion."""
    for i in range(len(data)):
        data[i] = 0


def audit_output_for_pii(text: str) -> list[str]:
    """Quick audit of output text for potential PII leakage.

    Returns list of warnings (empty = clean).
    """
    import re
    warnings = []

    # Check for phone numbers
    if re.search(r'(?<!\d)[6-9]\d{9}(?!\d)', text):
        warnings.append("Possible phone number in output")

    # Check for Aadhaar patterns
    if re.search(r'(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)', text):
        warnings.append("Possible Aadhaar number in output")

    # Check for email addresses
    if re.search(r'[\w.+-]+@[\w-]+\.[\w.]+', text):
        warnings.append("Possible email address in output")

    # Check for secret leakage
    if contains_secret(text):
        warnings.append("CRITICAL: RAKSHA_SECRET found in output")

    return warnings
