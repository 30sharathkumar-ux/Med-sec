"""Synthetic unseen-data robustness & false-positive test suite (Person B Sprint)."""

from __future__ import annotations

import base64
import json
import unittest
from collections import Counter

from rakshak.cli import _clean_text_full, _clean_json_full, _collect_names_json
from rakshak.detection.addresses import detect_address_spans
from rakshak.detection.hidden_surfaces import (
    sanitize_base64_text,
    sanitize_csv_header,
    sanitize_filename,
    sanitize_json_key,
    sanitize_metadata_value,
)
from rakshak.detection.identifiers import detect_identifier_spans
from rakshak.detection.names import detect_name_spans


class Phase1SyntheticUnseenTests(unittest.TestCase):
    """Phase 1: Unseen Indian names, regional spellings, Hinglish, new IDs & addresses."""

    def test_unseen_indian_names_in_context(self) -> None:
        # None of these names are in LATIN_NAME_TOKENS or DEVA_NAME_TOKENS
        samples = [
            "Patient Name: Venkataraman Subramanian, Age: 54/M, UHID: AIIMS-DLH-2026-99123",
            "Pt. Name: Debashish Bandyopadhyay | Mob: 9876501234",
            "मरीज़ का नाम: वेंकटरमन सुब्रमण्यन | आयु: 54 वर्ष",
            "Patient: Thirumalai Muthukumar, S/o Krishnamurthy Iyer",
        ]
        for text in samples:
            cleaned = _clean_text_full(text, Counter())
            for leaked in (
                "Venkataraman", "Subramanian", "Debashish", "Bandyopadhyay",
                "वेंकटरमन", "सुब्रमण्यन", "Thirumalai", "Muthukumar", "Krishnamurthy", "Iyer",
            ):
                self.assertNotIn(leaked, cleaned, f"Leaked unseen name '{leaked}' in: {cleaned}")

    def test_regional_spellings_and_transliterations(self) -> None:
        text = (
            "Patient Name: Soumyajit Mukhopadhyay\n"
            "Note: सौम्यजीत मुखोपाध्याय came for follow-up. "
            "Also spelled Soumyajeet Mukhopadhay in old file."
        )
        cleaned = _clean_text_full(text, Counter())
        for tok in ("Soumyajit", "Mukhopadhyay", "सौम्यजीत", "मुखोपाध्याय", "Soumyajeet", "Mukhopadhay"):
            self.assertNotIn(tok, cleaned, f"Regional variant '{tok}' leaked in: {cleaned}")

    def test_unseen_hospital_and_insurance_ids(self) -> None:
        text = (
            "UHID: AIIMS-DLH-2026-99123 | Alt MRN: CMC-VEL-77412 | Reg: KGMU/26/88412\n"
            "Insurance: CGHS-DEL-884120 | ESIC/UP/2026/44123 | AB-PMJAY-991234"
        )
        cleaned = _clean_text_full(text, Counter())
        for ident in (
            "AIIMS-DLH-2026-99123", "CMC-VEL-77412", "KGMU/26/88412",
            "CGHS-DEL-884120", "ESIC/UP/2026/44123", "AB-PMJAY-991234",
        ):
            self.assertNotIn(ident, cleaned, f"Identifier '{ident}' leaked in: {cleaned}")

    def test_new_address_and_locality_formats(self) -> None:
        text = (
            "Address: Gali No. 4, Sector 14, Phase 2, Distt: Gautam Buddha Nagar - 201301\n"
            "पता: गली नं. 5, सेक्टर 12, कॉलोनी अशोक विहार, जिला गाजियाबाद - २०१००१"
        )
        cleaned = _clean_text_full(text, Counter())
        for addr in ("Gali No. 4", "Sector 14", "Phase 2", "गली नं. 5", "सेक्टर 12", "201301", "२०१००१"):
            self.assertNotIn(addr, cleaned, f"Address '{addr}' leaked in: {cleaned}")


class Phase2AdvancedMultilingualTests(unittest.TestCase):
    """Phase 2: Spacing, punctuation, Unicode normalization, mixed-script, kinship, narratives."""

    def test_spacing_and_punctuation_variations(self) -> None:
        text = (
            "Name :-  Mohd . Shahid  |  S / o  Abdul   Kalam\n"
            "Patient Name = Devendra Nath\n"
            "नामः राजेश्वरी देवी | आयु: 42"
        )
        cleaned = _clean_text_full(text, Counter())
        for tok in ("Shahid", "Abdul", "Kalam", "Devendra", "Nath", "राजेश्वरी", "देवी"):
            self.assertNotIn(tok, cleaned, f"Spacing/punctuation variant '{tok}' leaked in: {cleaned}")

    def test_unicode_homoglyphs_and_zero_width(self) -> None:
        # Zero-width space inside name and Cyrillic 'а' (\u0430) in phone/name
        text = "Patient Name: R\u200bamesh K\u200bumar | Mob: 98\u200b76543210 | Аadhaar: 2345 6789 0123"
        cleaned = _clean_text_full(text, Counter())
        self.assertNotIn("R\u200bamesh", cleaned)
        self.assertNotIn("Ramesh", cleaned)
        self.assertNotIn("98\u200b76543210", cleaned)
        self.assertNotIn("2345 6789 0123", cleaned)

    def test_mixed_script_names(self) -> None:
        text = "Patient Name: Ramesh कुमार, W/o राहुल Singh"
        cleaned = _clean_text_full(text, Counter())
        for tok in ("Ramesh", "कुमार", "राहुल", "Singh"):
            self.assertNotIn(tok, cleaned, f"Mixed-script token '{tok}' leaked in: {cleaned}")

    def test_unfamiliar_kinship_and_narratives(self) -> None:
        text = (
            "Hinglish note: saas ka naam Kamla Devi hai, sasur ka naam Brijmohan Lal.\n"
            "Devar ka naam Pradeep Kumar aur bhabhi ka naam Sunita Devi hai.\n"
            "सास का नाम सुमित्रा देवी है और देवर का नाम महेश है।\n"
            "Kal Subramanian ji aaye the, Reena ki report aaj aayi, Suresh bhai ne bataya."
        )
        cleaned = _clean_text_full(text, Counter())
        for tok in (
            "Kamla", "Brijmohan", "Pradeep", "Sunita",
            "सुमित्रा", "महेश", "Subramanian", "Reena", "Suresh",
        ):
            self.assertNotIn(tok, cleaned, f"Kinship/narrative name '{tok}' leaked in: {cleaned}")


class Phase3StructuredDataTests(unittest.TestCase):
    """Phase 3: Nested FHIR, unusual JSON keys, CSV/TSV headers, Unicode escapes, Base64, metadata."""

    def test_nested_fhir_resource(self) -> None:
        bundle = {
            "resourceType": "Bundle",
            "meta": {"source": r"C:\exports\Ramesh_Kumar_9876543210\bundle.json"},
            "entry": [
                {
                    "resource": {
                        "resourceType": "Patient",
                        "id": "pat-1",
                        "name": [{"given": ["Aarav"], "family": "Chatterjee"}],
                        "telecom": [{"system": "phone", "value": "9811223344"}],
                        "address": [{"line": ["Gali No 3, Sector 9"], "postalCode": "110001"}],
                    }
                },
                {
                    "resource": {
                        "resourceType": "Observation",
                        "subject": {"display": "Aarav Chatterjee"},
                        "performer": [{"display": "Dr. Meenakshi Iyer"}],
                        "code": {"coding": [{"system": "http://loinc.org", "code": "718-7", "display": "Hemoglobin"}]},
                        "valueQuantity": {"value": 13.4, "unit": "g/dL"},
                    }
                },
            ],
        }
        names = _collect_names_json(bundle)
        cleaned = _clean_json_full(bundle, Counter(), doc_names=names, patient_key="pk-1")
        dumped = json.dumps(cleaned, ensure_ascii=False)
        for leaked in ("Aarav", "Chatterjee", "9811223344", "110001", "Ramesh", "9876543210"):
            self.assertNotIn(leaked, dumped)
        # Clinical & doctor preserved
        self.assertIn("Dr. Meenakshi Iyer", dumped)
        self.assertIn("Hemoglobin", dumped)
        self.assertIn("13.4", dumped)

    def test_unicode_escapes_in_json(self) -> None:
        raw_json = r'{"patientName": "\u0930\u093e\u0939\u0941\u0932 \u0936\u0930\u094d\u092e\u093e", "diagnosis": "Dengue"}'
        parsed = json.loads(raw_json)
        names = _collect_names_json(parsed)
        cleaned = _clean_json_full(parsed, Counter(), doc_names=names)
        self.assertNotIn("राहुल", cleaned["patientName"])
        self.assertNotIn("शर्मा", cleaned["patientName"])
        self.assertEqual(cleaned["diagnosis"], "Dengue")

    def test_unusual_json_keys_and_csv_headers(self) -> None:
        headers = ["patient_Ramesh_9876543210", "रोगी_राहुल_शर्मा", "Hemoglobin_g_dL"]
        cleaned_hdr = sanitize_csv_header(headers, lambda s: _clean_text_full(s, Counter()))
        joined = "|".join(cleaned_hdr)
        self.assertNotIn("Ramesh", joined)
        self.assertNotIn("9876543210", joined)
        self.assertNotIn("राहुल", joined)
        self.assertNotIn("शर्मा", joined)
        self.assertIn("Hemoglobin_g_dL", cleaned_hdr)

        used: set[str] = set()
        k1 = sanitize_json_key("रोगी_सीता_9811122233", lambda s: _clean_text_full(s, Counter()), used_keys=used)
        self.assertNotIn("सीता", k1)
        self.assertNotIn("9811122233", k1)

    def test_large_and_malformed_base64(self) -> None:
        # Large valid base64 (~100 KB) with PII at the end
        padding_text = "Clinical observation stable. " * 3000 + "Patient Name: Harishankar Prasad, Mob: 9876543210."
        b64_large = base64.b64encode(padding_text.encode("utf-8")).decode("ascii")
        out_large = sanitize_base64_text(b64_large, lambda s: _clean_text_full(s, Counter()))
        decoded_large = base64.b64decode(out_large).decode("utf-8")
        self.assertNotIn("Harishankar", decoded_large)
        self.assertNotIn("9876543210", decoded_large)
        self.assertIn("Clinical observation stable.", decoded_large)

        # Malformed base64 should return unchanged without crashing
        malformed = "Not!Valid@Base64###Payload===="
        self.assertEqual(sanitize_base64_text(malformed, lambda s: _clean_text_full(s, Counter())), malformed)


class Phase4FalsePositiveTests(unittest.TestCase):
    """Phase 4: Ensure clinical terms, doctors, labs, vitals, meds, procedures are preserved."""

    def test_clinical_preservation_in_free_text(self) -> None:
        note = (
            "Consultant: Dr. Ramesh Srivastava (MD Medicine) and डॉ. कविता शर्मा reviewed.\n"
            "K/C/O Hypertension, Type 2 Diabetes Mellitus, Bell's palsy, Parkinson's disease.\n"
            "C/O fever, cough, headache, pet dard.\n"
            "Vitals: BP 130/80 mmHg, Temp 101.4 F, SpO2 97%, Pulse 88 /min.\n"
            "Labs: Hb 11.4 g/dL, WBC 8200 /uL, Platelets 185000, Serum Creatinine 1.1 mg/dL, HbA1c 7.2%.\n"
            "Rx: Tab. Paracetamol 650 mg 1-0-1 x 5 days, Tab. Azithromycin 500 mg OD x 3 days,\n"
            "Tab. Metformin 500 mg BD, Inj. Ceftriaxone 1 g IV.\n"
            "Procedure: Laparoscopic cholecystectomy planned in Ward 4 (Surgery) / Bed 12."
        )
        cleaned = _clean_text_full(note, Counter())
        must_keep = [
            "Dr. Ramesh Srivastava",
            "डॉ. कविता शर्मा",
            "Hypertension",
            "Diabetes Mellitus",
            "Bell's palsy",
            "Parkinson's disease",
            "BP 130/80",
            "101.4 F",
            "97%",
            "11.4 g/dL",
            "8200 /uL",
            "185000",
            "1.1 mg/dL",
            "Paracetamol",
            "Azithromycin",
            "Metformin",
            "Ceftriaxone",
            "1-0-1",
            "Laparoscopic cholecystectomy",
            "Ward 4 (Surgery) / Bed 12",
        ]
        for item in must_keep:
            self.assertIn(item, cleaned, f"Clinical item '{item}' was falsely redacted in:\n{cleaned}")


if __name__ == "__main__":
    unittest.main()
