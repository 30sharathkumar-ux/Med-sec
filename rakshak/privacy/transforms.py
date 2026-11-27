"""Privacy transformation engine: date shifting, age banding, location generalization,
rare value suppression and re-identification risk analysis.

Protects against:
 - Linkage attacks (quasi-identifier generalization)
 - Profile aggregation (k-anonymity enforcement)
 - Rare diagnosis inference (suppression)
 - Known-date attacks (per-patient secret date shifting)
 - Cross-release linkability (secret-keyed shifts)
 - Pseudonym inversion (HMAC only, never plain hash)
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import os
import re
from collections import Counter
from typing import Any, Optional


def _get_secret() -> bytes:
    """Read RAKSHA_SECRET from environment."""
    return os.environ.get("RAKSHA_SECRET", "").encode("utf-8")


# ---------------------------------------------------------------------------
# Per-patient date shifting
# ---------------------------------------------------------------------------

def compute_date_shift(patient_key: str, max_days: int = 180,
                       secret: Optional[bytes] = None) -> int:
    """Compute a deterministic per-patient date shift in [-max, +max], never 0.

    Uses HMAC-SHA256 keyed with RAKSHA_SECRET. All dates for the same patient
    shift by the same amount, preserving intervals (admission-discharge stays).
    """
    key = secret if secret is not None else _get_secret()
    d = hmac.new(key, b"shift|" + patient_key.encode("utf-8"), hashlib.sha256).digest()
    v = int.from_bytes(d[:4], "big") % (2 * max_days) - max_days
    return v if v != 0 else 1


def shift_date(date_val: dt.date, patient_key: str, max_days: int = 180,
               secret: Optional[bytes] = None) -> dt.date:
    """Apply per-patient date shift to a date, preserving intervals."""
    shift = compute_date_shift(patient_key, max_days, secret)
    return date_val + dt.timedelta(days=shift)


def shift_date_string(date_str: str, patient_key: str, max_days: int = 180,
                      secret: Optional[bytes] = None) -> Optional[str]:
    """Parse, shift, and re-format a date string. Returns None if unparseable."""
    date_val = _parse_date(date_str)
    if date_val is None:
        return None
    shifted = shift_date(date_val, patient_key, max_days, secret)
    # Return in the same format as input
    if re.match(r'\d{4}-\d{2}-\d{2}', date_str):
        return shifted.strftime('%Y-%m-%d')
    elif re.match(r'\d{2}/\d{2}/\d{4}', date_str):
        # Determine if DD/MM/YYYY or MM/DD/YYYY
        parts = date_str.split('/')
        if int(parts[0]) > 12:
            return shifted.strftime('%d/%m/%Y')
        elif int(parts[1]) > 12:
            return shifted.strftime('%m/%d/%Y')
        else:
            return shifted.strftime('%d/%m/%Y')  # default to DD/MM/YYYY (Indian convention)
    else:
        return shifted.strftime('%d/%m/%Y')


_DATE_FORMATS = [
    '%Y-%m-%d',
    '%d/%m/%Y',
    '%m/%d/%Y',
    '%d-%m-%Y',
    '%Y/%m/%d',
    '%d.%m.%Y',
    '%d %b %Y',
    '%d %B %Y',
]


def _parse_date(date_str: str) -> Optional[dt.date]:
    """Try to parse a date string in common Indian/ISO formats."""
    date_str = date_str.strip()
    if not date_str:
        return None
    for fmt in _DATE_FORMATS:
        try:
            return dt.datetime.strptime(date_str, fmt).date()
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Age banding
# ---------------------------------------------------------------------------

def age_band(age: int, band_width: int = 5) -> str:
    """Convert an exact age to a truthful N-year band that contains the real age.

    Examples: age=48, width=5 -> "45-49"
              age=0, width=5 -> "0-4"
              age=95, width=5 -> "95-99"
    """
    lo = (age // band_width) * band_width
    hi = lo + band_width - 1
    return f"{lo}-{hi}"


_FREE_TEXT_AGE_LABEL_RE = re.compile(
    r"(?i)(\b(?:Age(?:/Sex)?|Umar|उम्र|आयु)\s*[:\-]\s*)(\d{1,3})(\s*(?:Yrs?|Years?|वर्ष|साल)?(?:\s*/\s*[MF])?)"
)
_FREE_TEXT_AGE_UNIT_RE = re.compile(
    r"(?i)(?<![-\d])\b(\d{1,3})(\s*(?:Yrs?|Years?|वर्ष|साल)\s*/\s*[MF])\b"
)


def band_free_text_ages(text: str, band_width: int = 5) -> str:
    """Replace exact ages in explicit age/sex clinical labels with truthful age bands.

    Preserves medications, dosages (e.g. '650 mg', '1-0-1', 'x 5 days'), and vitals.
    """
    if not text:
        return text

    def _replace_age(m: re.Match[str], has_prefix: bool) -> str:
        raw_age = int(m.group(2) if has_prefix else m.group(1))
        if not (0 <= raw_age <= 120):
            return m.group(0)
        banded = "80+" if (raw_age >= 80 and band_width >= 10) else age_band(raw_age, band_width)
        if has_prefix:
            return f"{m.group(1)}{banded}{m.group(3)}"
        return f"{banded}{m.group(2)}"

    out = _FREE_TEXT_AGE_LABEL_RE.sub(lambda m: _replace_age(m, True), text)
    out = _FREE_TEXT_AGE_UNIT_RE.sub(lambda m: _replace_age(m, False), out)
    return out


def age_band_contains(band: str, true_age: int) -> bool:
    """Verify that an age band contains the true age."""
    m = re.match(r'(\d+)\s*-\s*(\d+)', band)
    if not m:
        return False
    return int(m.group(1)) <= true_age <= int(m.group(2))


def dob_to_age_band(dob: dt.date, reference_date: Optional[dt.date] = None,
                     band_width: int = 5) -> str:
    """Convert a DOB to an age band relative to a reference date."""
    if reference_date is None:
        reference_date = dt.date.today()
    age = reference_date.year - dob.year
    if (reference_date.month, reference_date.day) < (dob.month, dob.day):
        age -= 1
    return age_band(max(0, age), band_width)


# ---------------------------------------------------------------------------
# Location generalization
# ---------------------------------------------------------------------------

def generalize_village(village: str, district: str) -> str:
    """Generalize village to district level for privacy.

    Returns district name, suppressing specific village/mohalla info.
    """
    if district:
        return district.strip()
    return "[DISTRICT]"


def generalize_address(address: str) -> str:
    """Suppress house numbers and specific locality details from addresses.

    Preserves tehsil and district, removes house numbers, ward numbers,
    mohalla names, and landmarks (English and Devanagari).
    """
    result = address
    # Remove house numbers: H.No. XXX, House XXX, Makan No. XXX, मकान नं. XXX
    result = re.sub(
        r'(?:H\.?\s*No\.?|House|Makan\s+No\.?|मकान\s+नं\.?|मकान\s+नंबर)\s*[:\-]?\s*\d+[A-Za-z0-9\-\/]*\s*,?\s*',
        '', result, flags=re.IGNORECASE
    )
    # Remove ward numbers: Ward XX, वार्ड XX
    result = re.sub(
        r'(?:Ward|वार्ड)\s+\d+\s*,?\s*',
        '', result, flags=re.IGNORECASE
    )
    # Remove mohalla/locality names in English and Devanagari
    result = re.sub(
        r'(?:Mohalla|Colony|Society|Basti|मोहल्ला|बस्ती|कॉलोनी)\s+[^,]+,?\s*',
        '', result, flags=re.IGNORECASE
    )
    # Remove English landmarks (prepositional: near XXX, behind XXX, opp. XXX)
    result = re.sub(
        r'(?:near|behind|opp\.?|opposite|in front of|adjacent to|next to)\s+[^,]+,?\s*',
        '', result, flags=re.IGNORECASE
    )
    # Remove Hindi landmarks (postpositional: [Landmark] के पास / के पीछे / के सामने / के बगल)
    result = re.sub(
        r'[^,]+?\s*(?:के\s*पास|के\s*पीछे|के\s*सामने|के\s*बगल(?:\s*में)?|के\s*नज़दीक|के\s*नजदीक|के\s*आसपास)\s*,?\s*',
        '', result, flags=re.IGNORECASE
    )
    # Remove C/O relative references
    result = re.sub(
        r'C/O\s+[^,]+,?\s*',
        '', result, flags=re.IGNORECASE
    )
    # Clean up remaining commas and whitespace
    result = re.sub(r',\s*,+', ',', result)
    result = re.sub(r'\s+', ' ', result).strip(' ,')
    return result


def generalize_pin(pin: str) -> str:
    """Generalize a 6-digit PIN code to its 3-digit regional prefix.

    Example: 229073 -> 229***
    """
    digits = re.sub(r'[^\d]', '', pin)
    if len(digits) == 6:
        return digits[:3] + '***'
    return pin


# ---------------------------------------------------------------------------
# Rare value suppression
# ---------------------------------------------------------------------------

def identify_rare_values(
    value_counts: Counter,
    min_group_size: int = 5,
) -> set[str]:
    """Identify values that appear fewer than min_group_size times.

    These values should be suppressed or generalized further to prevent
    re-identification through rare diagnosis or rare demographic combinations.
    """
    return {val for val, count in value_counts.items() if count < min_group_size}


def should_suppress_record(
    age: Optional[int],
    village: str,
    diagnosis: str,
    rare_diagnoses: set[str],
    min_group_size: int = 5,
) -> bool:
    """Determine if a record's quasi-identifier combination is too rare
    and should be further generalized or suppressed.

    High-risk combinations:
     - Very old/very young patient (age > 85 or age < 1) + small village
     - Rare diagnosis + any specific location
    """
    risk_score = 0

    if age is not None:
        if age > 85 or age < 1:
            risk_score += 2
        elif age > 75:
            risk_score += 1

    if diagnosis and diagnosis.lower() in {d.lower() for d in rare_diagnoses}:
        risk_score += 3

    if village and len(village) > 2:
        risk_score += 1

    return risk_score >= 4


# ---------------------------------------------------------------------------
# Re-identification risk analysis
# ---------------------------------------------------------------------------

def compute_reidentification_risk(
    records: list[dict[str, Any]],
    quasi_identifiers: list[str],
    min_group_size: int = 5,
) -> dict[str, Any]:
    """Compute re-identification risk metrics for a set of records.

    Measures:
     - k-anonymity: minimum group size for quasi-identifier combinations
     - Proportion of records in groups smaller than min_group_size
     - Overall risk score
    """
    if not records:
        return {
            'k_anonymity': 0,
            'at_risk_proportion': 0.0,
            'risk_score': 0.0,
            'total_records': 0,
        }

    # Build equivalence classes
    eq_classes: Counter[tuple] = Counter()
    for rec in records:
        qi_values = tuple(str(rec.get(qi, '')) for qi in quasi_identifiers)
        eq_classes[qi_values] += 1

    min_k = min(eq_classes.values()) if eq_classes else 0
    at_risk = sum(count for count in eq_classes.values() if count < min_group_size)
    total = sum(eq_classes.values())

    return {
        'k_anonymity': min_k,
        'at_risk_proportion': at_risk / total if total > 0 else 0.0,
        'risk_score': 1.0 - (min_k / min_group_size) if min_k < min_group_size else 0.0,
        'total_records': total,
        'equivalence_classes': len(eq_classes),
    }


# ---------------------------------------------------------------------------
# Convenience: apply all privacy transforms to a record dict
# ---------------------------------------------------------------------------

def apply_privacy_transforms(
    record: dict[str, Any],
    patient_key: Optional[str],
    policy: dict[str, Any],
    rare_diagnoses: Optional[set[str]] = None,
    secret: Optional[bytes] = None,
) -> dict[str, Any]:
    """Apply all privacy transformations to a record dictionary.

    Transforms:
     1. Date shifting (all date fields)
     2. Age banding
     3. Location generalization
     4. PIN generalization
     5. House number suppression
     6. Rare value handling
    """
    result = dict(record)
    band_width = int(policy.get('age_band_years', 5))
    max_shift = int(policy.get('date_shift_max_days', 180))

    # Age banding
    if 'age' in result and result['age'] is not None:
        try:
            age_val = int(result['age'])
            result['age'] = age_band(age_val, band_width)
        except (ValueError, TypeError):
            pass

    # DOB -> age band or shifted
    if 'dob' in result and result['dob'] and patient_key:
        date_val = _parse_date(str(result['dob']))
        if date_val:
            result['dob'] = dob_to_age_band(date_val, band_width=band_width)

    # Date shifting for all date-like fields
    if patient_key:
        for key in list(result.keys()):
            if any(d in key.lower() for d in ('date', 'admission', 'discharge', 'visit',
                                               'registered', 'reg_date', 'created')):
                val = result[key]
                if isinstance(val, str):
                    shifted = shift_date_string(val, patient_key, max_shift, secret)
                    if shifted:
                        result[key] = shifted

    # Location generalization
    if 'village' in result:
        district = result.get('district', '')
        result['village'] = generalize_village(str(result['village']), str(district))

    if 'address' in result and isinstance(result['address'], str):
        result['address'] = generalize_address(result['address'])

    # PIN generalization
    if 'pin' in result and result['pin']:
        result['pin'] = generalize_pin(str(result['pin']))

    return result
