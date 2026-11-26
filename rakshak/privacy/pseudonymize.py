"""HMAC-based deterministic pseudonymization.

Requirements:
 - Same patient + same RAKSHA_SECRET = same pseudonym (deterministic)
 - Different secret = different pseudonym (unlinkable across releases)
 - No plain SHA-based pseudonyms (HMAC only)
 - Never save or print the secret
 - No raw patient identity in logs
"""
from __future__ import annotations

import hashlib
import hmac
import os
from typing import Optional

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32: no I, L, O, U


def _get_secret() -> bytes:
    """Read RAKSHA_SECRET from environment. Never cache, never log."""
    return os.environ.get("RAKSHA_SECRET", "").encode("utf-8")


def generate_pseudonym(patient_key: str, secret: Optional[bytes] = None) -> str:
    """Generate a deterministic HMAC-SHA256 pseudonym.

    Args:
        patient_key: Canonical identity key for a patient cluster.
        secret: Optional explicit secret; defaults to RAKSHA_SECRET env var.

    Returns:
        A pseudonym in the form PSN-XXXXXX (6 Crockford base32 chars).
    """
    key = secret if secret is not None else _get_secret()
    digest = hmac.new(key, b"psn|" + patient_key.encode("utf-8"), hashlib.sha256).digest()
    n = int.from_bytes(digest[:5], "big")
    code = "".join(_ALPHABET[(n >> (5 * i)) & 31] for i in range(6))
    return f"PSN-{code}"


def pseudonym_is_valid(psn: str) -> bool:
    """Check if a string looks like a valid RAKSHA pseudonym."""
    if not psn or not psn.startswith("PSN-"):
        return False
    code = psn[4:]
    return len(code) == 6 and all(c in _ALPHABET for c in code)


def verify_pseudonym_determinism(patient_key: str, expected: str,
                                  secret: Optional[bytes] = None) -> bool:
    """Verify that a pseudonym matches the expected value for determinism checks."""
    return generate_pseudonym(patient_key, secret) == expected
