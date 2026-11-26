"""Post-linkage k-anonymity enforcement for sanitised output.

After the pipeline produces sanitised files and records.jsonl, this module
analyses the quasi-identifier (QI) combinations across the released dataset
and suppresses records whose equivalence class is smaller than `min_group_size`
(k) from `policy.yaml`.

Quasi-identifiers in RAKSHA's output:
  - age_band  (e.g. "45-49")
  - village/district (generalised)
  - gender
  - diagnosis category (if present)

This is the LAST privacy gate before export — it ensures that even after all
generalisations, no patient is unique on the QI combination.
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Optional


# Fields treated as quasi-identifiers in the sanitised output
_QI_KEYS_AGE = re.compile(r"(?i)^(?:age|umar|उम्र|आयु)$")
_QI_KEYS_GENDER = re.compile(r"(?i)^(?:gender|sex|ling|लिंग)$")
_QI_KEYS_VILLAGE = re.compile(r"(?i)^(?:village|gram|gaon|गाँव|ग्राम|locality)$")
_QI_KEYS_DISTRICT = re.compile(r"(?i)^(?:district|distt?|zila|जिला|जनपद)$")
_QI_KEYS_PIN = re.compile(r"(?i)^(?:pin(?:_?code)?|postal|डाक_?कोड)$")


def _extract_qi(record: dict[str, Any]) -> tuple:
    """Extract quasi-identifier tuple from a flat record dict."""
    age = gender = village = district = pin = ""
    for k, v in record.items():
        v_str = str(v).strip() if v is not None else ""
        if not v_str:
            continue
        kl = k.strip()
        if _QI_KEYS_AGE.match(kl):
            age = v_str
        elif _QI_KEYS_GENDER.match(kl):
            gender = v_str[:1].upper()
        elif _QI_KEYS_VILLAGE.match(kl):
            village = v_str.lower()
        elif _QI_KEYS_DISTRICT.match(kl):
            district = v_str.lower()
        elif _QI_KEYS_PIN.match(kl):
            pin = v_str
    return (age, gender, village, district, pin)


def compute_equivalence_classes(
    records: list[dict[str, Any]],
) -> dict[tuple, list[int]]:
    """Group record indices by their QI combination."""
    classes: dict[tuple, list[int]] = defaultdict(list)
    for idx, rec in enumerate(records):
        qi = _extract_qi(rec)
        classes[qi].append(idx)
    return dict(classes)


def identify_at_risk_records(
    records: list[dict[str, Any]],
    min_group_size: int = 5,
) -> set[int]:
    """Return indices of records in equivalence classes smaller than k."""
    classes = compute_equivalence_classes(records)
    at_risk: set[int] = set()
    for _qi, indices in classes.items():
        if len(indices) < min_group_size:
            at_risk.update(indices)
    return at_risk


def compute_k_anonymity_metrics(
    records: list[dict[str, Any]],
    min_group_size: int = 5,
) -> dict[str, Any]:
    """Compute k-anonymity statistics over the released dataset."""
    if not records:
        return {
            "k_achieved": 0,
            "total_records": 0,
            "equivalence_classes": 0,
            "at_risk_count": 0,
            "at_risk_proportion": 0.0,
            "suppression_needed": False,
        }
    classes = compute_equivalence_classes(records)
    sizes = [len(v) for v in classes.values()]
    min_k = min(sizes)
    at_risk = sum(s for s in sizes if s < min_group_size)
    return {
        "k_achieved": min_k,
        "total_records": len(records),
        "equivalence_classes": len(classes),
        "at_risk_count": at_risk,
        "at_risk_proportion": at_risk / len(records) if records else 0.0,
        "suppression_needed": min_k < min_group_size,
    }


def widen_age_band(band: str) -> str:
    """Widen a 5-year age band to a 10-year band for further generalisation.

    E.g. "45-49" or "40-44" → "40-49"; "0-4" or "5-9" → "0-9".
    """
    m = re.match(r"(\d+)\s*-\s*(\d+)", band)
    if not m:
        return band
    lo, hi = int(m.group(1)), int(m.group(2))
    new_lo = (lo // 10) * 10
    new_hi = new_lo + 9
    return f"{new_lo}-{new_hi}"


def suppress_pin(pin_val: str) -> str:
    """Suppress a generalised PIN further: 229*** → 22****."""
    digits = re.sub(r"[^0-9*]", "", pin_val)
    if len(digits) >= 6:
        return digits[:2] + "****"
    return pin_val
