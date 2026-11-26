"""Evidence-based identity resolution engine.

Links patient records across hospitals, languages and formats using:
 - Strong identifier matching (UHID, Aadhaar, ABHA, phone, insurance ID)
 - Cross-script name matching with phonetic fallback
 - Relative-name corroboration
 - Age + village + gender as secondary evidence
 - Conservative clustering: never merge on name alone
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    from rapidfuzz import fuzz as _fuzz
except ImportError:
    _fuzz = None

from rakshak.linkage.normalize import (
    _INDIC_DIGIT_MAP,
    extract_digits,
    extract_relative_name,
    has_devanagari,
    normalize_aadhaar,
    normalize_abha,
    normalize_mrn,
    normalize_name,
    normalize_phone,
    normalize_text,
    phonetic_key,
    transliterate_devanagari,
)


@dataclass
class RecordEvidence:
    """Extracted evidence from a single patient-bearing record."""
    record_id: str           # unique id: "file::loc"
    file_path: str           # relative path under sanitized/
    loc: str                 # row:N, /pointer, doc

    # Strong identifiers (any one is enough to link)
    phones: list[str] = field(default_factory=list)
    aadhaar: list[str] = field(default_factory=list)
    abha: list[str] = field(default_factory=list)
    mrns: list[str] = field(default_factory=list)
    pan: list[str] = field(default_factory=list)
    insurance_ids: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)

    # Names
    patient_name: str = ''
    patient_name_normalized: str = ''
    patient_name_phonetic: str = ''
    relative_name: str = ''
    relative_name_normalized: str = ''

    # Demographics
    age: Optional[int] = None
    gender: Optional[str] = None
    dob: Optional[str] = None  # normalized yyyy-mm-dd
    village: str = ''
    district: str = ''
    pin: str = ''

    # Hospital
    hospital: str = ''


# ---------------------------------------------------------------------------
# Evidence Extraction from structured data
# ---------------------------------------------------------------------------

# Column/key name classifiers (case-insensitive patterns)
_NAME_KEYS = re.compile(
    r'^(?:patient|mareez|mariz)[\s_]*(?:name|naam|ka\s*naam)$'
    r'|^name$|^naam$|^full[\s_]*name$'
    r'|patient\'s[\s_]*name'
    r'|first[\s_]*name|last[\s_]*name',
    re.IGNORECASE,
)
_PHONE_KEYS = re.compile(
    r'mobile|phone|contact|दूरभाष|मोबाइल|fone|tel',
    re.IGNORECASE,
)
_AADHAAR_KEYS = re.compile(
    r'aadh?a?r|आधार|aadhaar',
    re.IGNORECASE,
)
_ABHA_KEYS = re.compile(
    r'abha[\s_]*(?:no|number|id)?',
    re.IGNORECASE,
)
_MRN_KEYS = re.compile(
    r'uhid|mrd?n|ipd[\s_]*(?:no|number)?|opd[\s_]*(?:no|number)?'
    r'|reg(?:istration)?[\s_]*(?:no|number|id)\b|patient[\s_]*(?:id|ref)'
    r'|hospital[\s_]*uhid',
    re.IGNORECASE,
)
_AGE_KEYS = re.compile(
    r'^(?:age|umar|उम्र|आयु)(?:[\s_]*(?:yrs?|years?))?$',
    re.IGNORECASE,
)
_GENDER_KEYS = re.compile(
    r'^gender$|^sex$|^ling$|^लिंग$',
    re.IGNORECASE,
)
_DOB_KEYS = re.compile(
    r'dob|date[\s_]*of[\s_]*birth|janm[\s_]*tithi|जन्म[\s_]*तिथि',
    re.IGNORECASE,
)
_RELATIVE_KEYS = re.compile(
    r'\b(?:relative|guardian|father|mother|husband|wife|spouse'
    r'|s/o|d/o|w/o|c/o|pita|mata|pati|patni'
    r'|relation|rishtedar)\b',
    re.IGNORECASE,
)
_VILLAGE_KEYS = re.compile(
    r'village|gram|gaon|गाँव|ग्राम|mohalla|ward|locality',
    re.IGNORECASE,
)
_DISTRICT_KEYS = re.compile(
    r'district|distt?|zila|जिला|जनपद',
    re.IGNORECASE,
)
_PIN_KEYS = re.compile(
    r'pin[\s_]*(?:code)?|postal|डाक[\s_]*कोड',
    re.IGNORECASE,
)
_PAN_KEYS = re.compile(
    r'^(?:pan|pan[\s_]*(?:no|number|card)|patient[\s_]*pan)$',
    re.IGNORECASE,
)
_INSURANCE_KEYS = re.compile(
    r'insurance|bima|policy[\s_]*(?:no|number|id)',
    re.IGNORECASE,
)
_EMAIL_KEYS = re.compile(
    r'email|e[\s_-]*mail',
    re.IGNORECASE,
)
_HOSPITAL_KEYS = re.compile(
    r'hospital|facility|center|centre|clinic|अस्पताल',
    re.IGNORECASE,
)

# Age extraction from text
_AGE_TEXT_RE = re.compile(
    r'(\d{1,3})\s*(?:yrs?|years?|वर्ष|साल|/[MF])',
    re.IGNORECASE,
)

# Phone from text
_PHONE_TEXT_RE = re.compile(
    r'(?<!\d)(?:\+?91[\s-]?)?([6-9]\d{4}[\s-]?\d{5})(?!\d)',
)

# Gender from text
_GENDER_RE = re.compile(
    r'\b(?:male|female|M|F|पुरुष|महिला|स्त्री)\b',
    re.IGNORECASE,
)


def _parse_age(val: Any) -> Optional[int]:
    """Parse age from various formats."""
    if isinstance(val, (int, float)):
        age = int(val)
        return age if 0 <= age <= 120 else None
    if isinstance(val, str):
        val = val.strip()
        # "48", "48 Yrs", "48/M"
        m = re.match(r'^(\d{1,3})', val)
        if m:
            age = int(m.group(1))
            return age if 0 <= age <= 120 else None
    return None


def _parse_gender(val: Any) -> Optional[str]:
    """Normalize gender to M/F/O."""
    if not isinstance(val, str):
        return None
    val = val.strip().lower()
    if val in ('m', 'male', 'पुरुष'):
        return 'M'
    if val in ('f', 'female', 'महिला', 'स्त्री'):
        return 'F'
    return None


def extract_evidence_csv(
    header: list[str],
    row: list[str],
    file_path: str,
    row_idx: int,
    hospital: str = '',
) -> RecordEvidence:
    """Extract evidence from a CSV/TSV row using header semantics."""
    ev = RecordEvidence(
        record_id=f"{file_path}::row:{row_idx}",
        file_path=file_path,
        loc=f"row:{row_idx}",
        hospital=hospital,
    )

    name_parts: list[str] = []

    for col_idx, col_name in enumerate(header):
        if col_idx >= len(row):
            break
        val = row[col_idx].strip()
        if not val:
            continue

        col_lower = col_name.strip().lower()

        # Skip facility/payer/doctor columns from patient evidence
        if any(p in col_lower for p in ('payer', 'insurer', 'hospital', 'facility', 'doctor', 'dr_')):
            if _HOSPITAL_KEYS.search(col_lower):
                ev.hospital = val.strip()
            continue

        if _NAME_KEYS.search(col_lower):
            name_parts.append(val)
        elif col_lower in ('first_name', 'first name', 'first', 'fname'):
            name_parts.insert(0, val)
        elif col_lower in ('last_name', 'last name', 'last', 'lname', 'surname'):
            name_parts.append(val)
        elif _RELATIVE_KEYS.search(col_lower):
            # Could be "relation" column (S/o, D/o) or "relative name"
            if len(val) > 3:  # Likely a name, not just "S/o"
                ev.relative_name = val
                ev.relative_name_normalized = normalize_name(val)
        elif col_lower in ('relation', 'rishta', 'sambandh'):
            pass  # relation type, not name
        elif _PHONE_KEYS.search(col_lower):
            phone = normalize_phone(val)
            if phone:
                ev.phones.append(phone)
        elif _AADHAAR_KEYS.search(col_lower):
            aadhaar = normalize_aadhaar(val)
            if aadhaar:
                ev.aadhaar.append(aadhaar)
        elif _ABHA_KEYS.search(col_lower):
            abha = normalize_abha(val)
            if abha:
                ev.abha.append(abha)
        elif _MRN_KEYS.search(col_lower):
            ev.mrns.append(normalize_mrn(val))
        elif _AGE_KEYS.search(col_lower):
            ev.age = _parse_age(val)
        elif re.match(r'^age[\s_/]*sex$', col_lower):
            ev.age = _parse_age(val)
            m_sex = re.search(r'/\s*([MF]|male|female)\b', val, re.IGNORECASE)
            if m_sex:
                ev.gender = _parse_gender(m_sex.group(1))
        elif _GENDER_KEYS.search(col_lower):
            ev.gender = _parse_gender(val)
        elif _DOB_KEYS.search(col_lower):
            ev.dob = val
        elif _VILLAGE_KEYS.search(col_lower):
            ev.village = normalize_text(val)
        elif _DISTRICT_KEYS.search(col_lower):
            ev.district = normalize_text(val)
        elif _PIN_KEYS.search(col_lower):
            ev.pin = extract_digits(val)[:6]
        elif _PAN_KEYS.search(col_lower):
            ev.pan.append(val.strip().upper())
        elif _INSURANCE_KEYS.search(col_lower):
            ev.insurance_ids.append(val.strip())
        elif _EMAIL_KEYS.search(col_lower):
            ev.emails.append(val.strip().lower())
        elif _HOSPITAL_KEYS.search(col_lower):
            ev.hospital = val.strip()

        # Also try to extract relative from address fields
        if 'address' in col_lower or 'pata' in col_lower:
            rel = extract_relative_name(val)
            if rel and not ev.relative_name_normalized:
                ev.relative_name_normalized = rel

    if name_parts:
        full_name = ' '.join(name_parts)
        ev.patient_name = full_name
        ev.patient_name_normalized = normalize_name(full_name)
        ev.patient_name_phonetic = phonetic_key(full_name)

    return ev


def extract_evidence_json(
    data: dict[str, Any],
    file_path: str,
    loc: str,
    hospital: str = '',
) -> RecordEvidence:
    """Extract evidence from a JSON record (flat or nested)."""
    ev = RecordEvidence(
        record_id=f"{file_path}::{loc}",
        file_path=file_path,
        loc=loc,
        hospital=hospital,
    )

    # FHIR R4 Bundle: extract patient evidence ONLY from Patient resources
    if isinstance(data, dict) and data.get("resourceType") == "Bundle" and isinstance(data.get("entry"), list):
        for entry in data["entry"]:
            if not isinstance(entry, dict):
                continue
            res = entry.get("resource")
            if not isinstance(res, dict):
                continue
            rtype = res.get("resourceType")
            if rtype == "Organization" and isinstance(res.get("name"), str) and not ev.hospital:
                ev.hospital = res["name"].strip()
            elif rtype == "Patient":
                # Extract name
                for n in res.get("name", []) if isinstance(res.get("name"), list) else []:
                    if isinstance(n, dict):
                        if isinstance(n.get("text"), str) and n["text"].strip():
                            ev.patient_name = n["text"].strip()
                            break
                        parts = []
                        if isinstance(n.get("given"), list):
                            parts.extend(str(x) for x in n["given"] if x)
                        if isinstance(n.get("family"), str):
                            parts.append(n["family"])
                        if parts:
                            ev.patient_name = " ".join(parts)
                            break
                # Extract identifiers
                for ident in res.get("identifier", []) if isinstance(res.get("identifier"), list) else []:
                    if not isinstance(ident, dict):
                        continue
                    val = str(ident.get("value", "")).strip()
                    sys_str = str(ident.get("system", "")).lower()
                    if not val:
                        continue
                    if "aadhaar" in sys_str:
                        aa = normalize_aadhaar(val)
                        if aa:
                            ev.aadhaar.append(aa)
                    elif "abha" in sys_str:
                        ab = normalize_abha(val)
                        if ab:
                            ev.abha.append(ab)
                    else:
                        ev.mrns.append(normalize_mrn(val))
                # Extract telecom
                for tel in res.get("telecom", []) if isinstance(res.get("telecom"), list) else []:
                    if not isinstance(tel, dict):
                        continue
                    val = str(tel.get("value", "")).strip()
                    sys_str = str(tel.get("system", "")).lower()
                    if sys_str == "phone":
                        ph = normalize_phone(val)
                        if ph:
                            ev.phones.append(ph)
                    elif sys_str == "email" and val:
                        ev.emails.append(val.lower())
                # Extract gender, birthDate, address
                if isinstance(res.get("gender"), str):
                    ev.gender = _parse_gender(res["gender"])
                if isinstance(res.get("birthDate"), str):
                    ev.dob = res["birthDate"].strip()
                for addr in res.get("address", []) if isinstance(res.get("address"), list) else []:
                    if isinstance(addr, dict):
                        if isinstance(addr.get("city"), str):
                            ev.village = normalize_text(addr["city"])
                        if isinstance(addr.get("district"), str):
                            ev.district = normalize_text(addr["district"])
                        if isinstance(addr.get("postalCode"), str):
                            ev.pin = extract_digits(addr["postalCode"])[:6]
        if ev.patient_name:
            ev.patient_name_normalized = normalize_name(ev.patient_name)
            ev.patient_name_phonetic = phonetic_key(ev.patient_name)
        return ev

    def _walk(obj: Any, prefix: str = '') -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                key_lower = k.strip().lower()
                full_key = f"{prefix}.{key_lower}" if prefix else key_lower
                if any(p in key_lower for p in ('payer', 'insurer', 'doctor', 'practitioner', 'panels', 'tests', 'results', 'diagnosis', 'rx', 'vitals')):
                    continue

                if isinstance(v, str):
                    val = v.strip()
                    if not val:
                        continue

                    if _MRN_KEYS.search(key_lower):
                        ev.mrns.append(normalize_mrn(val))
                    elif _NAME_KEYS.search(key_lower) or key_lower in ('first', 'last', 'local'):
                        if key_lower == 'local' and has_devanagari(val):
                            norm = normalize_name(val)
                            if not ev.patient_name_normalized or len(norm) > len(ev.patient_name_normalized):
                                ev.patient_name_normalized = norm
                                ev.patient_name_phonetic = phonetic_key(val)
                        else:
                            if ev.patient_name:
                                ev.patient_name += ' ' + val
                            else:
                                ev.patient_name = val
                    elif _RELATIVE_KEYS.search(key_lower) and len(val) > 2:
                        ev.relative_name = val
                        ev.relative_name_normalized = normalize_name(val)
                    elif _PHONE_KEYS.search(key_lower):
                        phone = normalize_phone(val)
                        if phone:
                            ev.phones.append(phone)
                    elif _AADHAAR_KEYS.search(key_lower):
                        aa = normalize_aadhaar(val)
                        if aa:
                            ev.aadhaar.append(aa)
                    elif _ABHA_KEYS.search(key_lower):
                        ab = normalize_abha(val)
                        if ab:
                            ev.abha.append(ab)
                    elif _MRN_KEYS.search(key_lower):
                        ev.mrns.append(normalize_mrn(val))
                    elif _DOB_KEYS.search(key_lower):
                        ev.dob = val
                    elif _VILLAGE_KEYS.search(key_lower):
                        ev.village = normalize_text(val)
                    elif _DISTRICT_KEYS.search(key_lower):
                        ev.district = normalize_text(val)
                    elif _PIN_KEYS.search(key_lower):
                        ev.pin = extract_digits(val)[:6]
                    elif _GENDER_KEYS.search(key_lower):
                        ev.gender = _parse_gender(val)
                    elif _EMAIL_KEYS.search(key_lower):
                        ev.emails.append(val.lower())
                    elif _PAN_KEYS.search(key_lower):
                        ev.pan.append(val.upper())
                    elif _INSURANCE_KEYS.search(key_lower):
                        ev.insurance_ids.append(val)
                    elif _HOSPITAL_KEYS.search(key_lower) or key_lower == 'facility':
                        ev.hospital = val

                elif isinstance(v, (int, float)):
                    if _AGE_KEYS.search(key_lower):
                        ev.age = _parse_age(v)
                    elif _AADHAAR_KEYS.search(key_lower):
                        # Aadhaar stored as number
                        aa = normalize_aadhaar(str(int(v)))
                        if aa:
                            ev.aadhaar.append(aa)
                    elif _PHONE_KEYS.search(key_lower):
                        phone = normalize_phone(str(int(v)))
                        if phone:
                            ev.phones.append(phone)

                elif isinstance(v, (dict, list)):
                    _walk(v, full_key)

            # Build patient name from first+last if separate
            if 'name' in obj and isinstance(obj['name'], dict):
                name_dict = obj['name']
                parts = []
                for k in ('first', 'given', 'fname'):
                    if k in name_dict and isinstance(name_dict[k], str):
                        parts.append(name_dict[k].strip())
                for k in ('last', 'family', 'lname', 'surname'):
                    if k in name_dict and isinstance(name_dict[k], str):
                        parts.append(name_dict[k].strip())
                if parts:
                    full = ' '.join(parts)
                    if not ev.patient_name or len(full) > len(ev.patient_name):
                        ev.patient_name = full

        elif isinstance(obj, list):
            for item in obj:
                _walk(item, prefix)

    _walk(data)

    # Finalize name normalization
    if ev.patient_name and not ev.patient_name_normalized:
        ev.patient_name_normalized = normalize_name(ev.patient_name)
        ev.patient_name_phonetic = phonetic_key(ev.patient_name)

    return ev


def extract_evidence_text(
    text: str,
    file_path: str,
    hospital: str = '',
) -> RecordEvidence:
    """Extract evidence from free-text clinical notes."""
    ev = RecordEvidence(
        record_id=f"{file_path}::doc",
        file_path=file_path,
        loc='doc',
        hospital=hospital,
    )

    # Convert Indic numerals to ASCII for digit-based patterns
    text_digits = text.translate(_INDIC_DIGIT_MAP)

    # Patient name from labels (stop before Age/Sex/UHID/Relative/newline)
    name_patterns = [
        re.compile(
            r'(?:Patient\s+Name|Patient\'?s?\s+Name|Patient|Pt\.?|Name|नाम|मरीज(?:\s+का\s+नाम)?)\s*[:：]\s*'
            r'(.+?)(?:\s*(?:,|\n|\||;|\bAge\b|\bSex\b|\bGender\b|\bUHID\b|\bIPD\b|\bOPD\b|\bS/o\b|\bD/o\b|\bW/o\b|\bC/O\b|आयु|उम्र|लिंग)|$)',
            re.IGNORECASE,
        ),
    ]
    for pat in name_patterns:
        m = pat.search(text)
        if m:
            name = m.group(1).strip()
            # Don't capture if it looks like a complaint/diagnosis
            if len(name) > 1 and not re.match(r'(?:fever|cough|pain|cold)', name, re.IGNORECASE):
                ev.patient_name = name
                ev.patient_name_normalized = normalize_name(name)
                ev.patient_name_phonetic = phonetic_key(name)
                break

        # Fallback: "<Name>, S/o|D/o|W/o|C/O <Relative>" in discharge/clinical notes
        if not ev.patient_name:
            m_rel_name = re.search(
                r'(?:^|\n)[^\S\n]*([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F .]{1,40}?)\s*,?\s*'
                r'(?:S|D|W|C)\s*/\s*(?:o|O)\b',
                text,
            )
            if m_rel_name:
                cand = m_rel_name.group(1).strip()
                if len(cand) > 1 and not re.match(r'(?:discharge|note|opd|ipd|patient)\b', cand, re.IGNORECASE):
                    ev.patient_name = cand
                    ev.patient_name_normalized = normalize_name(cand)
                    ev.patient_name_phonetic = phonetic_key(cand)

    # Relative name from relation pattern or explicit labels
    rel = extract_relative_name(text)
    if rel:
        ev.relative_name_normalized = rel
    else:
        # Check explicit relative labels in Hindi/English
        rel_label_patterns = [
            re.compile(r'(?:(?:पिता|माता|पति|पत्नी)\s*(?:का\s*नाम)?\s*[:：]\s*)([^\n,;|]+)', re.IGNORECASE),
            re.compile(r'(?:(?:Father|Mother|Husband|Wife|Spouse|Relative|Guardian)\'?s?\s*(?:Name)?\s*[:：]\s*)([^\n,;|]+)', re.IGNORECASE),
        ]
        for rpat in rel_label_patterns:
            rm = rpat.search(text)
            if rm:
                ev.relative_name_normalized = normalize_name(rm.group(1).strip())
                break

    # Phone
    for m in _PHONE_TEXT_RE.finditer(text_digits):
        phone = normalize_phone(m.group(0))
        if phone:
            ev.phones.append(phone)

    # Age
    m = _AGE_TEXT_RE.search(text_digits)
    if m:
        ev.age = _parse_age(m.group(1))

    # Gender
    gm = _GENDER_RE.search(text)
    if gm:
        ev.gender = _parse_gender(gm.group(0))

    # MRN/UHID (must contain at least one digit and have explicit separator/number marker)
    uhid_re = re.compile(
        r'(?:UHID|MRN|MRD|IPD\s*(?:No\.?|#|:)|OPD\s*(?:No\.?|#|:)|Reg\.?\s*(?:No\.?|#|:)'
        r'|पंजीकरण\s*(?:सं\.?|संख्या|क्रमांक)?'
        r'|आईपीडी\s*(?:सं\.?|संख्या)?'
        r'|ओपीडी\s*(?:सं\.?|संख्या)?'
        r'|यूएचआईडी)\s*[:：]?\s*([A-Z0-9/\-]{4,})',
        re.IGNORECASE,
    )
    for m in uhid_re.finditer(text_digits):
        mrn_val = normalize_mrn(m.group(1))
        if any(c.isdigit() for c in mrn_val):
            ev.mrns.append(mrn_val)

    # Also catch MRN-like identifiers in context (e.g. "IPD-2026-00454" or "KGMU-001234" standalone)
    mrn_standalone_re = re.compile(
        r'(?:^|[\s,;|(])'
        r'((?:(?i:IPD|OPD|IP|OP|UHID|MRN|REG|ADM)[\s/\-]*[\dA-Z/\-]{4,})'
        r'|(?:[A-Z]{2,6}[-/]\d[0-9A-Z/\-]{3,}))',
        re.MULTILINE,
    )
    for m in mrn_standalone_re.finditer(text_digits):
        mrn_val = normalize_mrn(m.group(1))
        if any(c.isdigit() for c in mrn_val) and mrn_val not in ev.mrns:
            ev.mrns.append(mrn_val)

    # Village from labeled text (Hindi/English)
    village_re = re.compile(
        r'(?:Village|Gram|Gaon|ग्राम|गाँव|गांव|Mohalla|Ward|Locality'
        r'|निवासी|पता)\s*[:：]\s*([^\n,;|]+)',
        re.IGNORECASE,
    )
    vm = village_re.search(text)
    if vm:
        vill = vm.group(1).strip()
        if len(vill) > 1:
            ev.village = normalize_text(vill)

    # DOB from labeled text
    dob_re = re.compile(
        r'(?:DOB|Date\s*of\s*Birth|जन्म\s*तिथि|जन्मतिथि)\s*[:：]\s*'
        r'(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\d{4}[/\-]\d{1,2}[/\-]\d{1,2})',
        re.IGNORECASE,
    )
    dm = dob_re.search(text_digits)
    if dm:
        ev.dob = dm.group(1).strip()

    return ev


# ---------------------------------------------------------------------------
# DOB normalization helper
# ---------------------------------------------------------------------------

def _normalize_dob(dob: str) -> str:
    """Normalize DOB string to yyyy-mm-dd for comparison."""
    dob = dob.strip()
    if not dob:
        return ''
    # Already ISO
    m = re.match(r'^(\d{4})-(\d{2})-(\d{2})', dob)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    # DD/MM/YYYY or DD-MM-YYYY
    m = re.match(r'^(\d{1,2})[/\-](\d{1,2})[/\-](\d{4})', dob)
    if m:
        d, mo, y = m.group(1), m.group(2), m.group(3)
        return f"{y}-{int(mo):02d}-{int(d):02d}"
    # MM/DD/YYYY (US format) — ambiguous, try both
    return dob


def _age_from_dob(dob: str) -> int | None:
    """Derive approximate current age from a DOB string."""
    norm = _normalize_dob(dob)
    m = re.match(r'^(\d{4})-(\d{2})-(\d{2})$', norm)
    if not m:
        return None
    try:
        import datetime as _dt
        birth = _dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        today = _dt.date.today()
        age = today.year - birth.year
        if (today.month, today.day) < (birth.month, birth.day):
            age -= 1
        return age if 0 <= age <= 120 else None
    except (ValueError, OverflowError):
        return None


# ---------------------------------------------------------------------------
# Dynamic issuer-prefix extraction from MRN/UHID
# ---------------------------------------------------------------------------

GENERIC_ID_PREFIXES = frozenset({
    "UHID", "MRN", "MRDN", "IPD", "OPD", "ADM", "PAT", "ID", "REG", "LAB", "RX", "IP", "OP",
})
ISSUER_PREFIX_RE = re.compile(r"^([A-Z]{2,6})[-/]")


def extract_issuer_prefix(mrn: str) -> str | None:
    """Extract an institutional issuer prefix from an MRN (e.g. 'KGMU-1234' -> 'KGMU')."""
    m = ISSUER_PREFIX_RE.match(mrn.strip().upper())
    if not m:
        return None
    prefix = m.group(1)
    return None if prefix in GENERIC_ID_PREFIXES else prefix


def _infer_hospital_from_mrn(mrn: str) -> str:
    """Infer issuer tag from MRN prefix dynamically for cross-file MRN grouping."""
    prefix = extract_issuer_prefix(mrn)
    return f"issuer:{prefix.lower()}" if prefix else ''


def _effective_hospital(rec: 'RecordEvidence') -> str:
    """Get effective hospital: from path/metadata, or inferred from MRN prefix."""
    if rec.hospital:
        return rec.hospital
    for mrn in rec.mrns:
        h = _infer_hospital_from_mrn(mrn)
        if h:
            return h
    return ''


# ---------------------------------------------------------------------------
# Identity Resolution Engine
# ---------------------------------------------------------------------------

class IdentityResolver:
    """Conservative evidence-based identity resolver.

    Strategy:
     1. Build an inverted index on strong identifiers (phone, Aadhaar, ABHA, MRN, etc.)
     2. For each pair sharing a strong ID, merge into a cluster
     3. For name-only matches, require at least one corroborating clue
        (relative name, DOB, village+age) to avoid homonym merges
     4. Never transitively merge through weak evidence
    """

    def __init__(self) -> None:
        self._records: list[RecordEvidence] = []
        self._clusters: dict[str, int] = {}  # record_id -> cluster_id
        self._next_cluster = 0

    def add_record(self, evidence: RecordEvidence) -> None:
        """Register a record for resolution."""
        self._records.append(evidence)

    def resolve(self) -> dict[str, int]:
        """Run resolution and return record_id -> cluster_id mapping."""
        # Phase 1: Index strong identifiers
        phone_index: dict[str, list[int]] = defaultdict(list)
        aadhaar_index: dict[str, list[int]] = defaultdict(list)
        abha_index: dict[str, list[int]] = defaultdict(list)
        mrn_index: dict[str, list[int]] = defaultdict(list)
        email_index: dict[str, list[int]] = defaultdict(list)
        pan_index: dict[str, list[int]] = defaultdict(list)
        insurance_index: dict[str, list[int]] = defaultdict(list)

        for idx, rec in enumerate(self._records):
            for phone in rec.phones:
                phone_index[phone].append(idx)
            for aa in rec.aadhaar:
                if not aa.startswith('XXXX'):  # Don't index masked Aadhaar
                    aadhaar_index[aa].append(idx)
            for ab in rec.abha:
                abha_index[ab].append(idx)
            for mrn in rec.mrns:
                mrn_index[mrn].append(idx)
            for email in rec.emails:
                email_index[email].append(idx)
            for pan in rec.pan:
                pan_index[pan].append(idx)
            for ins in rec.insurance_ids:
                insurance_index[ins].append(idx)

        # Phase 2: Union-Find for clustering
        parent = list(range(len(self._records)))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: int, b: int) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        # Merge records sharing strong identifiers
        # Guard against facility/payer IDs that appear on records with conflicting names
        for index in [phone_index, aadhaar_index, abha_index,
                      email_index, pan_index, insurance_index]:
            for _key, indices in index.items():
                if len(indices) < 2:
                    continue
                # Check if names conflict wildly (e.g. a shared payer PAN or helpline phone)
                # Group by phonetic key so spelling/transliteration variants count as 1 person
                distinct_names = {
                    self._records[i].patient_name_phonetic or self._records[i].patient_name_normalized
                    for i in indices
                    if self._records[i].patient_name_normalized
                }
                if len(distinct_names) >= 3:
                    # Too many distinct names sharing one ID -> likely a non-patient ID
                    continue
                for i in range(1, len(indices)):
                    if self._compatible_for_id_merge(self._records[indices[0]], self._records[indices[i]]):
                        union(indices[0], indices[i])

        # MRNs: only merge within same hospital to avoid cross-hospital collisions
        # Use MRN prefix hospital when explicit, else effective hospital
        for _key, indices in mrn_index.items():
            if len(indices) < 2:
                continue
            mrn_hosp = _infer_hospital_from_mrn(_key)
            hospital_groups: dict[str, list[int]] = defaultdict(list)
            for idx in indices:
                h = mrn_hosp or _effective_hospital(self._records[idx]) or 'unknown'
                hospital_groups[h].append(idx)
            # Also try cross-group merging for 'unknown' records with known hospitals
            unknown_group = hospital_groups.pop('unknown', [])
            for _h, group in hospital_groups.items():
                # Merge known-hospital group internally
                distinct_names = {
                    self._records[i].patient_name_phonetic or self._records[i].patient_name_normalized
                    for i in group
                    if self._records[i].patient_name_normalized
                }
                if len(distinct_names) >= 3:
                    continue
                for i in range(1, len(group)):
                    if self._compatible_for_id_merge(self._records[group[0]], self._records[group[i]]):
                        union(group[0], group[i])
                # Merge unknown-hospital records into this group if compatible
                for uidx in unknown_group:
                    if self._compatible_for_id_merge(self._records[group[0]], self._records[uidx]):
                        union(group[0], uidx)

        # Phase 3: Name-based matching with corroboration
        # Build name index for candidate blocking (multiple strategies)
        name_index: dict[str, list[int]] = defaultdict(list)
        phonetic_index: dict[str, list[int]] = defaultdict(list)
        phone_last4_index: dict[str, list[int]] = defaultdict(list)
        relative_index: dict[str, list[int]] = defaultdict(list)

        for idx, rec in enumerate(self._records):
            if rec.patient_name_normalized:
                # Use first token as block key
                tokens = rec.patient_name_normalized.split()
                if tokens and len(tokens[0]) > 1:
                    name_index[tokens[0]].append(idx)
                # Also block on last token (surname)
                if len(tokens) > 1 and len(tokens[-1]) > 1:
                    name_index[tokens[-1]].append(idx)
            if rec.patient_name_phonetic:
                phon_tokens = rec.patient_name_phonetic.split()
                if phon_tokens and len(phon_tokens[0]) > 1:
                    phonetic_index[phon_tokens[0]].append(idx)
                if len(phon_tokens) > 1 and len(phon_tokens[-1]) > 1:
                    phonetic_index[phon_tokens[-1]].append(idx)
            # Phone last-4 blocking: group records by last 4 digits of phone
            for phone in rec.phones:
                if len(phone) >= 4:
                    phone_last4_index[phone[-4:]].append(idx)
            # Relative name blocking
            if rec.relative_name_normalized:
                rel_tokens = rec.relative_name_normalized.split()
                if rel_tokens and len(rel_tokens[0]) > 2:
                    relative_index[rel_tokens[0]].append(idx)

        # Try name-based merges with corroboration
        checked_pairs: set[tuple[int, int]] = set()

        for index in [name_index, phonetic_index, phone_last4_index, relative_index]:
            for _block, indices in index.items():
                for i, idx_a in enumerate(indices):
                    for idx_b in indices[i + 1:]:
                        if find(idx_a) == find(idx_b):
                            continue
                        pair = (min(idx_a, idx_b), max(idx_a, idx_b))
                        if pair in checked_pairs:
                            continue
                        checked_pairs.add(pair)

                        if self._should_merge(self._records[idx_a], self._records[idx_b]):
                            union(idx_a, idx_b)

        # Phase 4: Build cluster mapping
        cluster_map: dict[int, int] = {}
        result: dict[str, int] = {}
        for idx, rec in enumerate(self._records):
            root = find(idx)
            if root not in cluster_map:
                cluster_map[root] = self._next_cluster
                self._next_cluster += 1
            result[rec.record_id] = cluster_map[root]

        self._clusters = result
        return result

    def _compatible_for_id_merge(self, a: RecordEvidence, b: RecordEvidence) -> bool:
        """Check that two records sharing a strong ID don't have starkly conflicting demographics."""
        if a.patient_name_normalized and b.patient_name_normalized:
            if not self._names_match(a, b):
                # Allow if one name is just first name or phonetic variant, otherwise reject
                a_toks = set(a.patient_name_normalized.split())
                b_toks = set(b.patient_name_normalized.split())
                if not (a_toks & b_toks):
                    return False
        # DOB conflict: different DOBs → different patients
        if a.dob and b.dob:
            a_norm = _normalize_dob(a.dob)
            b_norm = _normalize_dob(b.dob)
            if a_norm and b_norm and a_norm != b_norm:
                return False
        # Severe age conflict (>5 years apart) → different patients
        if a.age is not None and b.age is not None and abs(a.age - b.age) > 5:
            return False
        # Relative name conflict: both have relatives but they don't match
        if (a.relative_name_normalized and b.relative_name_normalized
                and len(a.relative_name_normalized) > 3 and len(b.relative_name_normalized) > 3
                and not self._text_similar(a.relative_name_normalized, b.relative_name_normalized)):
            # Additional guard: if the relative names are completely different, block merge
            a_rel_toks = set(a.relative_name_normalized.split())
            b_rel_toks = set(b.relative_name_normalized.split())
            if not (a_rel_toks & b_rel_toks):
                return False
        return True

    def _should_merge(self, a: RecordEvidence, b: RecordEvidence) -> bool:
        """Determine if two records should be merged based on evidence.

        Requires name similarity PLUS at least one corroborating clue.
        Never merges on name alone to prevent homonym false merges.
        """
        # Both must have names
        if not a.patient_name_normalized or not b.patient_name_normalized:
            return False

        # Hard conflicts: if DOB or age contradict, never merge
        if a.dob and b.dob:
            a_norm = _normalize_dob(a.dob)
            b_norm = _normalize_dob(b.dob)
            if a_norm and b_norm and a_norm != b_norm:
                return False
        if a.age is not None and b.age is not None and abs(a.age - b.age) > 5:
            return False
        # Conflicting relative names → block
        if (a.relative_name_normalized and b.relative_name_normalized
                and len(a.relative_name_normalized) > 3 and len(b.relative_name_normalized) > 3):
            a_rel_toks = set(a.relative_name_normalized.split())
            b_rel_toks = set(b.relative_name_normalized.split())
            if not (a_rel_toks & b_rel_toks):
                return False
        # Conflicting village → block (only if both have village info)
        if (a.village and b.village
                and not self._text_similar(a.village, b.village)):
            return False

        # Check name similarity
        name_match = self._names_match(a, b)
        if not name_match:
            return False

        # Count corroborating evidence
        corroboration = 0

        # Relative name match
        if (a.relative_name_normalized and b.relative_name_normalized and
                self._text_similar(a.relative_name_normalized, b.relative_name_normalized)):
            corroboration += 2

        # DOB match (use normalized comparison)
        if a.dob and b.dob:
            a_norm = _normalize_dob(a.dob)
            b_norm = _normalize_dob(b.dob)
            if a_norm and b_norm and a_norm == b_norm:
                corroboration += 2

        # DOB ↔ age cross-match: derive age from DOB and compare
        if not (a.dob and b.dob):
            dob_age_match = False
            if a.dob and b.age is not None:
                a_age = _age_from_dob(a.dob)
                if a_age is not None and abs(a_age - b.age) <= 2:
                    dob_age_match = True
            elif b.dob and a.age is not None:
                b_age = _age_from_dob(b.dob)
                if b_age is not None and abs(b_age - a.age) <= 2:
                    dob_age_match = True
            if dob_age_match:
                corroboration += 1.5

        # Village + age match
        if (a.village and b.village and
                self._text_similar(a.village, b.village)):
            corroboration += 1
            if a.age is not None and b.age is not None and abs(a.age - b.age) <= 2:
                corroboration += 1

        # Gender match (weak but supportive)
        if a.gender and b.gender and a.gender == b.gender:
            corroboration += 0.5

        # District match
        if (a.district and b.district and
                self._text_similar(a.district, b.district)):
            corroboration += 0.5

        # Masked Aadhaar last-4 match
        a_masked = [aa for aa in a.aadhaar if aa.startswith('XXXX')]
        b_masked = [aa for aa in b.aadhaar if aa.startswith('XXXX')]
        if a_masked and b_masked and set(a_masked) & set(b_masked):
            corroboration += 1

        # Phone match (may not be in strong index if only one record has it)
        if a.phones and b.phones and set(a.phones) & set(b.phones):
            corroboration += 3  # Phone is a strong identifier

        # Need at least 2 points of corroboration for name-only links
        # Use higher threshold for common names
        threshold = 2
        a_tokens = set(a.patient_name_normalized.split())
        b_tokens = set(b.patient_name_normalized.split())
        generic_tokens = {'kumar', 'devi', 'singh', 'kaur', 'lal', 'ram', 'bai', 'bano',
                          'begum', 'bi', 'mohammad', 'md', 'ji', 'sahab', 'prasad', 'yadav',
                          'verma', 'chaudhary', 'chauhan', 'pandey', 'mishra', 'tiwari',
                          'patel', 'lodhi', 'thakur', 'paswan', 'nishad', 'rajput',
                          'ansari', 'siddiqui', 'gupta'}
        # If name is very common (all tokens are generic), require stronger evidence
        if a_tokens and a_tokens.issubset(generic_tokens):
            threshold = 3
        if b_tokens and b_tokens.issubset(generic_tokens):
            threshold = 3
        return corroboration >= threshold

    def _names_match(self, a: RecordEvidence, b: RecordEvidence) -> bool:
        """Check if two records' patient names match (direct or cross-script)."""
        if not a.patient_name_normalized or not b.patient_name_normalized:
            return False

        # Exact normalized match
        if a.patient_name_normalized == b.patient_name_normalized:
            return True

        # Token overlap: at least 2 shared meaningful tokens
        a_tokens = set(a.patient_name_normalized.split())
        b_tokens = set(b.patient_name_normalized.split())
        # Remove very common tokens that don't identify
        generic = {'kumar', 'devi', 'singh', 'kaur', 'lal', 'ram', 'bai', 'bano',
                   'begum', 'bi', 'mohammad', 'md', 'ji', 'sahab', 'prasad',
                   'sahab', 'amma', 'didi', 'bhaiya', 'behenji'}
        a_meaningful = a_tokens - generic
        b_meaningful = b_tokens - generic
        shared = a_tokens & b_tokens
        shared_meaningful = a_meaningful & b_meaningful

        if len(shared) >= 2 and len(shared_meaningful) >= 1:
            return True

        # Single meaningful token match: when both names have exactly 1 meaningful
        # token (e.g. "Fatima" vs "Fatima"), allow match only if phonetic also agrees
        if (len(a_meaningful) == 1 and len(b_meaningful) == 1
                and a_meaningful == b_meaningful):
            # Require phonetic agreement for safety
            if (a.patient_name_phonetic and b.patient_name_phonetic
                    and a.patient_name_phonetic == b.patient_name_phonetic):
                return True

        # Phonetic match
        if (a.patient_name_phonetic and b.patient_name_phonetic and
                a.patient_name_phonetic == b.patient_name_phonetic):
            return True

        # Cross-script phonetic token matching: when names come from different
        # scripts (e.g. Devanagari transliterated vs Latin), token overlap is
        # zero but phonetic tokens should match well.
        if a.patient_name_phonetic and b.patient_name_phonetic:
            a_phon_tokens = set(a.patient_name_phonetic.split())
            b_phon_tokens = set(b.patient_name_phonetic.split())
            phon_shared = a_phon_tokens & b_phon_tokens
            phon_meaningful = phon_shared - {phonetic_key(g).strip() for g in generic if phonetic_key(g).strip()}
            # If all phonetic tokens match (or all meaningful ones), treat as name match
            phon_total = min(len(a_phon_tokens), len(b_phon_tokens))
            if phon_total >= 2 and len(phon_shared) >= phon_total:
                return True
            # Relaxed: at least 2 phonetic tokens shared with 1+ meaningful
            if len(phon_shared) >= 2 and len(phon_meaningful) >= 1:
                return True

        # Try fuzzy matching with token overlap
        if len(shared_meaningful) >= 1:
            # At least one meaningful token shared and phonetic similarity
            a_phon_tokens = set(a.patient_name_phonetic.split()) if a.patient_name_phonetic else set()
            b_phon_tokens = set(b.patient_name_phonetic.split()) if b.patient_name_phonetic else set()
            phon_shared = a_phon_tokens & b_phon_tokens
            if len(phon_shared) >= 2:
                return True

        # rapidfuzz token_sort_ratio for fuzzy matching (spelling variants)
        if _fuzz is not None and a_meaningful and b_meaningful:
            score = _fuzz.token_sort_ratio(a.patient_name_normalized, b.patient_name_normalized)
            if score >= 85:
                return True

        # One name is a prefix/subset of the other (e.g. "Asha Rajput" vs "Asha Devi Rajput")
        # Require at least 2 meaningful tokens on each side to avoid "Asha" ⊂ "Asha Rajput" false links
        if a_meaningful and b_meaningful and len(a_meaningful) >= 2 and len(b_meaningful) >= 2:
            if a_meaningful.issubset(b_meaningful) or b_meaningful.issubset(a_meaningful):
                return True

        return False

    def _text_similar(self, a: str, b: str) -> bool:
        """Check if two normalized strings are similar."""
        if a == b:
            return True
        # Simple token overlap
        a_tokens = set(a.split())
        b_tokens = set(b.split())
        if a_tokens and b_tokens:
            overlap = len(a_tokens & b_tokens)
            total = min(len(a_tokens), len(b_tokens))
            if total > 0 and overlap / total >= 0.5:
                return True
        # Phonetic key comparison for cross-script
        a_phon = phonetic_key(a)
        b_phon = phonetic_key(b)
        if a_phon and b_phon and a_phon == b_phon:
            return True
        # Phonetic token overlap: for cross-script matches where tokens differ
        # but phonetic keys overlap significantly (e.g. Devanagari transliterations)
        if a_phon and b_phon:
            a_phon_toks = set(a_phon.split())
            b_phon_toks = set(b_phon.split())
            phon_overlap = len(a_phon_toks & b_phon_toks)
            phon_total = min(len(a_phon_toks), len(b_phon_toks))
            if phon_total > 0 and phon_overlap / phon_total >= 0.5:
                return True
        # rapidfuzz fallback
        if _fuzz is not None:
            if _fuzz.token_sort_ratio(a, b) >= 80:
                return True
        return False

    def get_cluster_key(self, record_id: str) -> Optional[str]:
        """Get the canonical key for a record's cluster (for pseudonym generation)."""
        if record_id not in self._clusters:
            return None
        cluster_id = self._clusters[record_id]
        # Find the lexicographically first record in the cluster as canonical key
        members = [rec for rec in self._records
                   if self._clusters.get(rec.record_id) == cluster_id]
        if not members:
            return None

        # Use strongest identifier as canonical key for determinism
        for rec in sorted(members, key=lambda r: r.record_id):
            for phone in sorted(rec.phones):
                return f"phone:{phone}"
            for aa in sorted(rec.aadhaar):
                if not aa.startswith('XXXX'):
                    return f"aadhaar:{aa}"
        # Fall back to name + first discriminant
        for rec in sorted(members, key=lambda r: r.record_id):
            if rec.patient_name_normalized:
                suffix = rec.dob or rec.village or str(rec.age) or rec.district or ''
                return f"name:{rec.patient_name_normalized}|{suffix}"

        return f"cluster:{cluster_id}"

    def get_all_cluster_keys(self) -> dict[str, Optional[str]]:
        """Return record_id -> canonical cluster key for all records."""
        # Build cluster -> canonical key mapping once
        cluster_keys: dict[int, str] = {}
        cluster_members: dict[int, list[RecordEvidence]] = defaultdict(list)

        for rec in self._records:
            cid = self._clusters.get(rec.record_id)
            if cid is not None:
                cluster_members[cid].append(rec)

        for cid, members in cluster_members.items():
            members_sorted = sorted(members, key=lambda r: r.record_id)
            key = None
            # Prefer strongest identifier
            for rec in members_sorted:
                if rec.phones:
                    key = f"phone:{sorted(rec.phones)[0]}"
                    break
                if any(not aa.startswith('XXXX') for aa in rec.aadhaar):
                    aa = sorted(a for a in rec.aadhaar if not a.startswith('XXXX'))[0]
                    key = f"aadhaar:{aa}"
                    break
                if rec.abha:
                    key = f"abha:{sorted(rec.abha)[0]}"
                    break
                if rec.emails:
                    key = f"email:{sorted(rec.emails)[0]}"
                    break
                if rec.mrns:
                    h = rec.hospital or "hosp"
                    key = f"mrn:{h}:{sorted(rec.mrns)[0]}"
                    break
            if key is None:
                # Only assign a cluster key if the record has actual patient evidence
                has_evidence = any(
                    r.patient_name_normalized or r.phones or r.aadhaar or r.abha or r.mrns or r.emails
                    for r in members_sorted
                )
                if not has_evidence:
                    continue
                # Use cluster-specific key so distinct clusters NEVER collide on homonym names
                first_rec = members_sorted[0]
                key = f"cluster:{first_rec.record_id}|{first_rec.patient_name_normalized}"
            cluster_keys[cid] = key

        result: dict[str, Optional[str]] = {}
        for rec in self._records:
            cid = self._clusters.get(rec.record_id)
            result[rec.record_id] = cluster_keys.get(cid) if cid is not None else None

        return result
