"""Post-linkage adaptive k-anonymity & profile risk enforcement.

Computes quasi-identifier (QI) equivalence classes across resolved patient
profiles and determines per-patient adaptive generalization policies:
  - Standard (k >= min_group_size): 5-year age band, 3-digit PIN prefix (229***)
  - Moderate risk (k < min_group_size): suppress PIN to 2-digit prefix (22****)
    and widen age band to 10-year (or 80+ for seniors)
  - High risk (singleton on wide band + district, or extreme age + rare diagnosis):
    suppress PIN to [PIN] and widen age band to 20-year (or 80+)

Preserves district (clinical/utility probe) and all medical values/LOS.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

# Fields treated as quasi-identifiers in structured records
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
    """Compute k-anonymity statistics over a list of QI-bearing dicts."""
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
        "at_risk_proportion": round(at_risk / len(records), 4) if records else 0.0,
        "suppression_needed": min_k < min_group_size,
    }


def widen_age_band(band: str, width: int = 10) -> str:
    """Widen a 5-year age band to a 10-year (or 20-year) band."""
    m = re.match(r"(\d+)\s*-\s*(\d+)", band)
    if not m:
        return band
    lo = int(m.group(1))
    new_lo = (lo // width) * width
    new_hi = new_lo + width - 1
    return f"{new_lo}-{new_hi}"


def suppress_pin(pin_val: str, level: int = 1) -> str:
    """Suppress a generalised PIN further: level 1 -> 22****, level 2 -> [PIN]."""
    if level >= 2:
        return "[PIN]"
    digits = re.sub(r"[^0-9*]", "", pin_val)
    if len(digits) >= 6:
        return digits[:2] + "****"
    return "[PIN]"


def compute_adaptive_profile_policies(
    profiles: dict[str, dict[str, Any]],
    min_group_size: int = 5,
    base_band_width: int = 5,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Compute per-patient adaptive generalization policy from resolved profiles.

    Args:
        profiles: mapping patient_key -> {'age': int|None, 'gender': str,
                  'district': str, 'pin_prefix': str, 'rare_condition': bool}
        min_group_size: target equivalence class size (k)
        base_band_width: default age band width (5 years)

    Returns:
        (per_patient_policy, metrics_summary)
    """
    if not profiles:
        return {}, {
            "k_achieved": 0,
            "total_profiles": 0,
            "equivalence_classes": 0,
            "at_risk_profiles": 0,
            "profiles_widened": 0,
            "pins_suppressed": 0,
        }

    if len(profiles) < min_group_size:
        policies = {
            pkey: {"age_band_width": base_band_width, "pin_suppress_level": 0}
            for pkey in profiles
        }
        return policies, {
            "k_achieved": len(profiles),
            "total_profiles": len(profiles),
            "equivalence_classes": len(profiles),
            "at_risk_profiles": 0,
            "at_risk_proportion": 0.0,
            "profiles_widened": 0,
            "pins_suppressed": 0,
            "suppression_needed": False,
        }

    def _band_for(age: int | None, width: int) -> str:
        if age is None:
            return ""
        if age >= 80 and width >= 10:
            return "80+"
        lo = (age // width) * width
        return f"{lo}-{lo + width - 1}"

    # Initial 5-year equivalence classes: (5yr_band, gender, district, pin_prefix)
    init_classes: Counter[tuple] = Counter()
    for pdata in profiles.values():
        b5 = _band_for(pdata.get("age"), base_band_width)
        qi = (b5, pdata.get("gender", ""), pdata.get("district", ""), pdata.get("pin_prefix", ""))
        init_classes[qi] += 1

    policies: dict[str, dict[str, Any]] = {}
    widened_count = 0
    pin_suppressed_count = 0

    # First pass: widen age to 10-yr & suppress PIN to 2-digit if k < min_group_size or extreme/rare
    mid_classes: Counter[tuple] = Counter()
    temp_bands: dict[str, tuple[int, int]] = {}
    for pkey, pdata in profiles.items():
        age = pdata.get("age")
        b5 = _band_for(age, base_band_width)
        qi_init = (b5, pdata.get("gender", ""), pdata.get("district", ""), pdata.get("pin_prefix", ""))
        is_extreme = age is not None and (age >= 80 or age < 5)
        is_rare = bool(pdata.get("rare_condition", False))
        if init_classes[qi_init] < min_group_size or is_extreme or is_rare:
            band_w = 10
            pin_lvl = 1
        else:
            band_w = base_band_width
            pin_lvl = 0
        temp_bands[pkey] = (band_w, pin_lvl)
        b_mid = _band_for(age, band_w)
        # Drop PIN from mid_classes grouping when suppressed so district+gender+10yr forms larger cells
        mid_classes[(b_mid, pdata.get("gender", ""), pdata.get("district", ""))] += 1

    # Second pass: escalate to 20-yr + full [PIN] suppression ONLY for:
    #   - extreme ages (>=80 or <5), OR
    #   - rare-condition profiles, OR
    #   - singletons (count == 1) on (10yr_band, gender, district)
    # This preserves 10-yr bands (0.8 utility) for multi-member classes while protecting high-risk outliers.
    final_records: list[dict[str, Any]] = []
    for pkey, pdata in profiles.items():
        age = pdata.get("age")
        band_w, pin_lvl = temp_bands[pkey]
        b_mid = _band_for(age, band_w)
        qi_mid = (b_mid, pdata.get("gender", ""), pdata.get("district", ""))
        is_extreme = age is not None and (age >= 80 or age < 5)
        is_rare = bool(pdata.get("rare_condition", False))

        if is_extreme or is_rare or mid_classes[qi_mid] <= 1:
            band_w = 20
            pin_lvl = 2
        elif pin_lvl > 0:
            # Suppress PIN completely when k < min_group_size on 10-yr + district
            if mid_classes[qi_mid] < min_group_size:
                pin_lvl = 2

        if band_w > base_band_width:
            widened_count += 1
        if pin_lvl > 0:
            pin_suppressed_count += 1

        policies[pkey] = {"age_band_width": band_w, "pin_suppress_level": pin_lvl}
        final_records.append({
            "age": _band_for(age, band_w),
            "gender": pdata.get("gender", ""),
            "district": pdata.get("district", ""),
            "pin": "" if pin_lvl >= 2 else (pdata.get("pin_prefix", "")[:2] + "****" if pin_lvl == 1 else pdata.get("pin_prefix", "")),
        })

    final_metrics = compute_k_anonymity_metrics(final_records, min_group_size=min_group_size)
    final_metrics["total_profiles"] = len(profiles)
    final_metrics["profiles_widened"] = widened_count
    final_metrics["pins_suppressed"] = pin_suppressed_count
    final_metrics["at_risk_profiles"] = final_metrics.pop("at_risk_count", 0)
    return policies, final_metrics
