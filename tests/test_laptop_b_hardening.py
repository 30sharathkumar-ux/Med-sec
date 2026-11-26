"""Unit tests for RAKSHA Laptop-B generalization and contract hardening (Phases 1-6)."""

from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from rakshak.cli import _clean_text_full, run_pipeline
from rakshak.detection.hidden_surfaces import (
    filename_has_pii,
    sanitize_base64_text,
    sanitize_csv_header,
    sanitize_embedded_base64,
    sanitize_filename,
    sanitize_json_key,
)
from rakshak.detection.names import detect_name_spans
from rakshak.detection.structured import classify_field


class Phase1ReportAccountingTests(unittest.TestCase):
    """Phase 1: exactly one report.files entry per input file using raw-byte SHA-256."""

    def test_single_report_entry_per_file_with_crlf(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inp = root / "in"
            out = root / "out"
            inp.mkdir()
            # Write a CRLF file and an unsupported file
            (inp / "note.txt").write_bytes(b"Patient Name: Ramesh Kumar\r\nFever 2 days\r\n")
            (inp / "scan.pdf").write_bytes(b"%PDF-1.4\r\nbinary\r\n")

            old = os.environ.get("RAKSHA_SECRET")
            os.environ["RAKSHA_SECRET"] = "test-secret"
            try:
                rc = run_pipeline(inp, out)
            finally:
                if old is None:
                    os.environ.pop("RAKSHA_SECRET", None)
                else:
                    os.environ["RAKSHA_SECRET"] = old

            self.assertEqual(rc, 0)
            report = json.loads((out / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(len(report["files"]), 2)
            self.assertEqual(report["counts"]["files_total"], 2)
            self.assertEqual(report["counts"]["files_sanitized"], 1)
            self.assertEqual(report["counts"]["files_quarantined"], 1)


class Phase2FilenameSanitizationTests(unittest.TestCase):
    """Phase 2: Latin, Devanagari, separator variations, unseen names, safe clinical preservation."""

    def test_unseen_names_and_separators(self) -> None:
        secret = b"secret-key"
        # Unseen name via extra_patient_names with hyphen and underscore
        self.assertTrue(filename_has_pii("notes/Zorawar-Qadri_summary.txt", {"Zorawar Qadri"}))
        self.assertTrue(filename_has_pii("discharge/Discharge_Summary_Kavita-Verma.txt"))
        self.assertTrue(filename_has_pii("notes/राहुल_सिंह_नोट.txt"))
        self.assertTrue(filename_has_pii("notes/nursing_ipd-2026-00459.txt"))

        # Safe clinical filenames must NOT be renamed
        self.assertFalse(filename_has_pii("clean/dengue_management_protocol.txt"))
        self.assertFalse(filename_has_pii("clean/drug_formulary.csv"))
        self.assertFalse(filename_has_pii("clean/lab_reference_ranges.csv"))

        # Preserves directory structure & extension
        renamed = sanitize_filename("discharge/Zorawar_Qadri_note.txt", secret, {"Zorawar Qadri"})
        self.assertTrue(renamed.startswith("discharge/doc_"))
        self.assertTrue(renamed.endswith(".txt"))
        self.assertNotIn("Zorawar", renamed)


class Phase3DevanagariStructuredKeyTests(unittest.TestCase):
    """Phase 3: Devanagari and Latin CSV headers & JSON keys."""

    def test_devanagari_and_latin_headers_and_keys(self) -> None:
        counts: Counter[str] = Counter()
        cleaner = lambda t: _clean_text_full(t, counts)

        headers = ["रोगी का नाम", "आयु", "राहुल सिंह", "9876543210", "९८७६५४३२१०"]
        cleaned_hdr = sanitize_csv_header(headers, cleaner)
        # Clinical schema headers preserved
        self.assertEqual(cleaned_hdr[0], "रोगी का नाम")
        self.assertEqual(cleaned_hdr[1], "आयु")
        # Person-name and identifier headers sanitized
        self.assertNotIn("राहुल", cleaned_hdr[2])
        self.assertNotIn("9876543210", cleaned_hdr[3])
        self.assertNotIn("९८७६५४३२१०", cleaned_hdr[4])

        used: set[str] = set()
        self.assertEqual(sanitize_json_key("clinicalStatus", cleaner, used_keys=used), "clinicalStatus")
        self.assertNotIn("राहुल", sanitize_json_key("राहुल सिंह", cleaner, used_keys=used))
        self.assertNotIn("Fatima", sanitize_json_key("Fatima Bano", cleaner, used_keys=used))


class Phase4Base64HardeningTests(unittest.TestCase):
    """Phase 4: valid, invalid, padded, unpadded, URL-safe, embedded Base64 & key variants."""

    def test_attachment_key_variants(self) -> None:
        for k in ("payload", "encoded_data", "base64_content", "attachment_data", "base64"):
            self.assertEqual(classify_field(k), "BASE64_DATA")

    def test_standard_urlsafe_unpadded_and_invalid(self) -> None:
        counts: Counter[str] = Counter()
        cleaner = lambda t: _clean_text_full(t, counts)
        raw = "Patient Name: Ramesh Kumar, Phone: 9876543210"

        # Standard padded
        b64_std = base64.b64encode(raw.encode("utf-8")).decode("ascii")
        out_std = base64.b64decode(sanitize_base64_text(b64_std, cleaner)).decode("utf-8")
        self.assertNotIn("Ramesh", out_std)
        self.assertNotIn("9876543210", out_std)

        # URL-safe unpadded
        b64_url = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")
        out_url_raw = sanitize_base64_text(b64_url, cleaner)
        out_url = base64.urlsafe_b64decode(out_url_raw + "=" * (-len(out_url_raw) % 4)).decode("utf-8")
        self.assertNotIn("Ramesh", out_url)
        self.assertNotIn("9876543210", out_url)

        # Invalid Base64 returned unchanged (safe)
        self.assertEqual(sanitize_base64_text("not!valid!base64@@@", cleaner), "not!valid!base64@@@")

    def test_embedded_base64_and_no_false_positives(self) -> None:
        counts: Counter[str] = Counter()
        cleaner = lambda t: _clean_text_full(t, counts)
        payload = base64.b64encode(b"Patient Name: Anita Sharma, Phone: 9811122233").decode("ascii")
        text = f"Attachment: {payload} | Tab Paracetamol 500mg BD"
        cleaned = sanitize_embedded_base64(text, cleaner)
        self.assertIn("Paracetamol 500mg BD", cleaned)
        self.assertNotIn(payload, cleaned)

        # Ordinary alphanumeric ID must NOT be altered
        benign = "Protocol ID: ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"
        self.assertEqual(sanitize_embedded_base64(benign, cleaner), benign)


class Phase5ClinicalUtilityTests(unittest.TestCase):
    """Phase 5: date shifting, age banding, PIN/village generalization, clinical preservation."""

    def test_json_and_csv_utility_preservation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inp = root / "in"
            out = root / "out"
            inp.mkdir()
            (inp / "patients.json").write_text(
                json.dumps({
                    "patients": [
                        {
                            "uhid": "SNJ-26-000101",
                            "patient_name": "Ramesh Kumar",
                            "age": 48,
                            "dob": "1978-05-10",
                            "admission_date": "2026-03-01",
                            "discharge_date": "2026-03-05",
                            "village": "Khaspura",
                            "district": "Hardoi",
                            "pin": "241001",
                            "diagnosis": "Dengue fever",
                            "medicine": "Paracetamol 500mg",
                        }
                    ]
                }),
                encoding="utf-8",
            )

            old = os.environ.get("RAKSHA_SECRET")
            os.environ["RAKSHA_SECRET"] = "test-secret"
            try:
                rc = run_pipeline(inp, out)
            finally:
                if old is None:
                    os.environ.pop("RAKSHA_SECRET", None)
                else:
                    os.environ["RAKSHA_SECRET"] = old

            self.assertEqual(rc, 0)
            san = json.loads((out / "sanitized" / "patients.json").read_text(encoding="utf-8"))
            rec = san["patients"][0]
            self.assertEqual(rec["age"], "45-49")
            self.assertEqual(rec["pin"], "241***")
            self.assertEqual(rec["village"], "Hardoi")
            self.assertEqual(rec["diagnosis"], "Dengue fever")
            self.assertEqual(rec["medicine"], "Paracetamol 500mg")
            # Dates shifted (not [DATE]) and 4-day LOS preserved
            self.assertNotEqual(rec["admission_date"], "[DATE]")
            self.assertNotEqual(rec["admission_date"], "2026-03-01")
            from datetime import date
            d_adm = date.fromisoformat(rec["admission_date"])
            d_dis = date.fromisoformat(rec["discharge_date"])
            self.assertEqual((d_dis - d_adm).days, 4)


class Phase6MultilingualKinshipTests(unittest.TestCase):
    """Phase 6: Devanagari and Hinglish kinship frames."""

    def test_kinship_frames_detected_without_overredaction(self) -> None:
        samples = [
            ("Uski maa ka naam Savitri Devi hai.", "Savitri Devi"),
            ("baap ka naam Harishankar Tiwari hai", "Harishankar Tiwari"),
            ("bhai ka naam Suresh Verma, beta ka naam Aman Verma", "Suresh Verma"),
            ("माता का नाम कमला देवी है।", "कमला देवी"),
            ("माँ का नाम: सीता रानी", "सीता रानी"),
        ]
        for text, expected in samples:
            spans = detect_name_spans(text)
            extracted = [text[s:e] for s, e, _ in spans]
            self.assertTrue(
                any(expected in ex for ex in extracted),
                f"Expected {expected!r} in {extracted!r} for {text!r}",
            )


if __name__ == "__main__":
    unittest.main()
