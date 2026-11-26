"""Semantic column and field classifier across English, Hindi, Hinglish, and unseen labels."""

from __future__ import annotations

import re

from rakshak.detection.multilingual import normalize_surface

# Semantic categories for structured CSV/TSV columns and JSON object keys
# NOTE: "value" and "display" are intentionally EXCLUDED — they need context-aware
# classification (FHIR identifier.value = MRN, telecom.value = phone, etc.)
CLINICAL_KEEP_FIELDS = frozenset({
    "doctor", "ref_doctor", "referred_by", "consultant", "author", "reviewed_by",
    "drug", "medicine", "strength", "form", "category", "schedule", "dosage", "frequency", "duration",
    "test", "loinc", "unit", "range", "ref_range", "reference_range", "result",
    "diagnosis", "code", "complaints", "history", "procedure", "package_code",
    "vitals", "bp", "pulse", "temp_f", "temp", "spo2", "weight_kg", "weight",
    "department", "ward", "wards", "beds", "occupied", "dengue_cases", "week",
    "amount_inr", "status", "schema", "facility", "report_type", "lab", "panels",
    "rx", "system", "resourceType", "clinicalStatus", "valueQuantity",
    "medicationCodeableConcept", "dosageInstruction", "component", "qualification", "class",
    "intent", "section", "title", "contentType", "language", "trip", "from", "to",
})


def _norm_key(key: str) -> str:
    s = normalize_surface(key).lower().strip()
    s = re.sub(r"\([^)]*\)", " ", s)
    s = re.sub(r"[^a-z0-9\u0900-\u097f]+", " ", s).strip()
    return s


def classify_field(key: str, parent_key: str = "") -> str | None:
    """Classify a CSV header or JSON key into a semantic PII/QI/clinical role.

    Returns one of:
      PATIENT_NAME, RELATIVE_NAME, PHONE, EMAIL, MRN, AADHAAR, ABHA_NUMBER,
      ABHA_ADDRESS, PAN, INSURANCE_ID, DOB, AGE, GENDER, DATE, ADDRESS,
      HOUSE, LOCALITY, VILLAGE, TEHSIL, DISTRICT, PIN, METADATA_PATH,
      BASE64_DATA, CLINICAL_KEEP, or None.
    """
    raw_low = normalize_surface(key).lower().strip()
    if key in CLINICAL_KEEP_FIELDS or raw_low in CLINICAL_KEEP_FIELDS:
        return "CLINICAL_KEEP"

    nk = _norm_key(key)
    np = _norm_key(parent_key)

    if not nk:
        return None

    # ----- FHIR "value" context-aware classification -----
    # value under identifier/telecom/coding parents needs special handling
    if nk == "value":
        if np in ("identifier",):
            return None  # identifier.value = MRN/ABHA — let text cleaner handle
        if np in ("telecom",):
            return "PHONE"  # telecom.value = phone number string
        if np in ("coding", "type", "category", "code", "clinicalstatus",
                   "valuequantity", "component", "dosageinstruction",
                   "medicationcodeableconcept", "quantity", "doseandrate"):
            return "CLINICAL_KEEP"
        # CSV column named "value" with no FHIR parent — treat as clinical lab result
        if not np:
            return "CLINICAL_KEEP"
        # Default: let text cleaner run
        return None

    # ----- FHIR "display" context-aware classification -----
    if nk == "display":
        if np in ("subject", "patient", "beneficiary", "individual"):
            return "PATIENT_NAME"
        if np in ("author", "performer", "recorder", "asserter", "practitioner",
                   "requester", "managingorganization", "organization", "source",
                   "serviceprovider"):
            return "CLINICAL_KEEP"
        if np in ("relationship", "contact"):
            return "RELATIVE_NAME"
        # coding.display, type.display, clinicalStatus.display etc. → clinical
        if np in ("coding", "type", "category", "code", "clinicalstatus",
                   "class", "priority", "use", "maritalstatus"):
            return "CLINICAL_KEEP"
        # Default display: let text cleaner handle
        return None

    # Explicit clinical protection checks first
    if any(w in nk for w in ("doctor", "consultant", "referred by", "ref doctor", "author", "physician", "reviewed by")):
        return "CLINICAL_KEEP"
    if any(w in nk for w in ("drug", "medicine", "strength", "dosage", "frequency", "loinc", "test", "diagnosis", "procedure", "vitals", "ref range", "reference range")):
        return "CLINICAL_KEEP"

    # Base64 attachment payloads
    if nk in ("data", "payload", "encoded data", "base64 content", "attachment data",
              "base64", "content data", "data base64") and (
        nk != "data" or np in ("attachment", "content", "")
    ):
        return "BASE64_DATA"

    # Metadata / file paths
    if nk in ("source path", "file path", "export path", "source_path") or (nk == "source" and np == "meta"):
        return "METADATA_PATH"

    # Guardian / relative fields
    if np in ("guardian", "contact", "attendant") and nk == "name":
        return "RELATIVE_NAME"
    # Use word-boundary check to prevent "pati" matching "patient"
    _nk_words = set(nk.split())
    if _nk_words & {"relative", "guardian", "father", "husband", "mother", "spouse", "attendant", "pita", "pati", "पिता", "पति"}:
        return "RELATIVE_NAME"
    if nk == "relation":
        return "RELATION_LABEL"

    # Direct identifiers
    if "abha" in nk:
        return "ABHA_ADDRESS" if "address" in nk else "ABHA_NUMBER"
    if "aadhaar" in nk or "aadhar" in nk or "uidai" in nk:
        return "AADHAAR"
    if "pan" == nk or nk.endswith(" pan") or "payer pan" in nk:
        return "PAN"
    if any(w in nk for w in ("pmjay", "policy", "insurance", "claim id", "tpa")):
        return "INSURANCE_ID"
    if any(w in nk for w in ("email", "e mail")):
        return "EMAIL"
    if any(w in nk for w in ("phone", "mobile", "mob", "contact", "callback", "tel", "मोबाइल", "संपर्क")) and nk != "contact":
        return "PHONE"
    if any(w in nk for w in ("uhid", "mrn", "reg no", "patientid", "patient id", "patient ref", "ipd", "पंजीकरण", "आईपीडी")):
        return "MRN"

    # Names — protect hospital/facility name fields
    if np == "name" and nk in ("first", "last", "local", "text", "given", "family"):
        return "PATIENT_NAME"
    if nk in ("patient name", "patient s name", "pt name", "name", "naam", "नाम", "मरीज़ का नाम", "मरीज का नाम", "first name", "firstname", "last name", "lastname", "beneficiary", "name of beneficiary"):
        if np in ("facility", "organization", "lab", "hospital", "panels",
                  "practitioner", "location", "careteam", "healthcareservice",
                  "export meta", "export_meta"):
            return "CLINICAL_KEEP"
        return "PATIENT_NAME"
    if nk == "hospital":
        return "CLINICAL_KEEP"
    if "patient" in nk and "name" in nk:
        return "PATIENT_NAME"
    if np == "raised by" and nk == "name":
        return "PATIENT_NAME"

    # Quasi-identifiers: DOB, Age, Gender, Dates, Locations
    if any(w in nk for w in ("dob", "birth", "janm", "जन्म")):
        return "DOB"
    if nk in ("age sex", "age gender"):
        return "AGE_SEX"
    if nk in ("age", "umar", "आयु"):
        return "AGE"
    if nk in ("gender", "sex", "ling", "लिंग"):
        return "GENDER"
    if any(w in nk for w in ("admission date", "discharge date", "visit date", "reg date", "registered", "collected", "reported", "recordeddate", "authoredon", "performeddatetime", "effectivedatetime", "तारीख", "exported at", "generated at", "timestamp")) or nk in ("date", "start", "end"):
        return "DATE"

    if nk in ("pin", "pincode", "pin code", "postalcode", "zip", "पिन"):
        return "PIN"
    if any(w in nk for w in ("district", "distt", "jila", "जिला")):
        return "DISTRICT"
    if any(w in nk for w in ("tehsil", "taluka", "block", "तहसील")):
        return "TEHSIL"
    if any(w in nk for w in ("village", "gaon", "gram", "city", "ग्राम", "गाँव", "गांव")):
        return "VILLAGE" if "mohalla" not in nk else "VILLAGE_OR_LOCALITY"
    if any(w in nk for w in ("street", "house", "makan", "locality", "mohalla")):
        return "ADDRESS"
    if any(w in nk for w in ("address", "pata", "पता", "address note")) or (nk == "line" and np == "address"):
        return "ADDRESS"

    return None
