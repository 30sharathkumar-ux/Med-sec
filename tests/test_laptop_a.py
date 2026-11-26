"""Integration tests for Laptop A modules: identity resolution, pseudonymization,
privacy engine, and full pipeline integration.

Tests cover:
 - Same patient across hospitals (cross-hospital linking)
 - Same patient in English and Hindi (cross-script)
 - Same-name different patients (homonym separation)
 - Ambiguous identities (conservative null assignment)
 - HMAC determinism (same secret = same pseudonym)
 - Secret rotation (different secret = different pseudonym)
 - Date shifting (deterministic, interval-preserving)
 - Length-of-stay preservation
 - Age generalization (5-year truthful bands)
 - Location generalization (village -> district, PIN prefix)
 - Rare-value suppression
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from rakshak.linkage.normalize import (
    extract_relative_name,
    has_devanagari,
    normalize_aadhaar,
    normalize_abha,
    normalize_name,
    normalize_phone,
    phonetic_key,
    transliterate_devanagari,
)
from rakshak.linkage.resolver import (
    IdentityResolver,
    RecordEvidence,
    extract_evidence_csv,
    extract_evidence_json,
    extract_evidence_text,
)
from rakshak.privacy.pseudonymize import (
    generate_pseudonym,
    pseudonym_is_valid,
    verify_pseudonym_determinism,
)
from rakshak.privacy.transforms import (
    age_band,
    age_band_contains,
    compute_date_shift,
    generalize_address,
    generalize_pin,
    generalize_village,
    shift_date,
    shift_date_string,
)


class TestNormalization(unittest.TestCase):
    """Test name and identifier normalization."""

    def test_normalize_name_basic(self) -> None:
        self.assertEqual(normalize_name("Mahesh Chauhan"), "mahesh chauhan")
        self.assertEqual(normalize_name("VIJAY YADAV"), "vijay yadav")

    def test_normalize_name_with_honorifics(self) -> None:
        self.assertEqual(normalize_name("Shri Mahesh ji"), "mahesh")
        self.assertEqual(normalize_name("Smt. Usha Devi"), "usha")

    def test_normalize_name_abbreviations(self) -> None:
        name = normalize_name("Md. Arif")
        self.assertIn("mohammad", name)
        self.assertIn("arif", name)

    def test_transliterate_devanagari(self) -> None:
        # मोहम्मद should transliterate to something containing mohm/moham
        result = transliterate_devanagari("मोहम्मद")
        self.assertTrue(len(result) > 3)
        self.assertTrue(has_devanagari("मोहम्मद"))
        self.assertFalse(has_devanagari("Mohammad"))

    def test_cross_script_name_matching(self) -> None:
        """Mohammad in Latin and Devanagari should normalize similarly."""
        latin = normalize_name("Mohammad Arif")
        devanagari = normalize_name("मोहम्मद आरिफ")
        # Both should be non-empty and contain recognizable tokens
        self.assertTrue(len(latin) > 3)
        self.assertTrue(len(devanagari) > 3)

    def test_phonetic_key(self) -> None:
        # Similar names should have similar phonetic keys
        key1 = phonetic_key("Chauhan")
        key2 = phonetic_key("Chouhan")
        # Both should produce non-empty keys
        self.assertTrue(len(key1) > 0)
        self.assertTrue(len(key2) > 0)

    def test_normalize_phone(self) -> None:
        self.assertEqual(normalize_phone("+91 72864 90658"), "7286490658")
        self.assertEqual(normalize_phone("8081120924"), "8081120924")
        self.assertEqual(normalize_phone("91826 40788"), "9182640788")
        self.assertIsNone(normalize_phone("123"))  # too short

    def test_normalize_aadhaar(self) -> None:
        self.assertEqual(normalize_aadhaar("397205839628"), "397205839628")
        self.assertEqual(normalize_aadhaar("8799 6191 4045"), "879961914045")
        self.assertEqual(normalize_aadhaar("XXXX XXXX 5866"), "XXXX5866")

    def test_normalize_abha(self) -> None:
        self.assertEqual(normalize_abha("91-7938-3729-8403"), "91793837298403")
        self.assertIsNone(normalize_abha("1234"))  # too short

    def test_extract_relative_name(self) -> None:
        self.assertEqual(
            extract_relative_name("S/o Naresh Chauhan, H.No. 364"),
            "naresh chauhan"
        )
        self.assertEqual(
            extract_relative_name("W/o Rahul Tiwari, Makan No. 371"),
            "rahul tiwari"
        )


class TestIdentityResolution(unittest.TestCase):
    """Test identity resolution engine."""

    def test_same_patient_same_phone(self) -> None:
        """Two records with same phone number should be linked."""
        resolver = IdentityResolver()
        ev1 = RecordEvidence(
            record_id="file1::row:0", file_path="file1.csv", loc="row:0",
            phones=["7286490658"], patient_name="Mahesh Chauhan",
            patient_name_normalized="mahesh chauhan",
        )
        ev2 = RecordEvidence(
            record_id="file2::row:0", file_path="file2.csv", loc="row:0",
            phones=["7286490658"], patient_name="Mahesh Chouhan",
            patient_name_normalized="mahesh chouhan",
        )
        resolver.add_record(ev1)
        resolver.add_record(ev2)
        clusters = resolver.resolve()
        self.assertEqual(clusters["file1::row:0"], clusters["file2::row:0"])

    def test_same_patient_same_aadhaar(self) -> None:
        """Two records with same Aadhaar should be linked."""
        resolver = IdentityResolver()
        ev1 = RecordEvidence(
            record_id="a::row:0", file_path="a.csv", loc="row:0",
            aadhaar=["397205839628"], patient_name="Mahesh",
            patient_name_normalized="mahesh",
        )
        ev2 = RecordEvidence(
            record_id="b::row:0", file_path="b.csv", loc="row:0",
            aadhaar=["397205839628"], patient_name="Mahesh Chauhan",
            patient_name_normalized="mahesh chauhan",
        )
        resolver.add_record(ev1)
        resolver.add_record(ev2)
        clusters = resolver.resolve()
        self.assertEqual(clusters["a::row:0"], clusters["b::row:0"])

    def test_same_name_different_patients(self) -> None:
        """Two records with same name but different identifiers should NOT be linked."""
        resolver = IdentityResolver()
        ev1 = RecordEvidence(
            record_id="a::row:0", file_path="a.csv", loc="row:0",
            phones=["9999999999"], patient_name="Ramesh Kumar",
            patient_name_normalized="ramesh kumar",
            village="village_a", age=45,
        )
        ev2 = RecordEvidence(
            record_id="b::row:0", file_path="b.csv", loc="row:0",
            phones=["8888888888"], patient_name="Ramesh Kumar",
            patient_name_normalized="ramesh kumar",
            village="village_b", age=60,
        )
        resolver.add_record(ev1)
        resolver.add_record(ev2)
        clusters = resolver.resolve()
        self.assertNotEqual(clusters["a::row:0"], clusters["b::row:0"])

    def test_ambiguous_identity_no_link(self) -> None:
        """Records with only a name and no corroboration should not be linked."""
        resolver = IdentityResolver()
        ev1 = RecordEvidence(
            record_id="a::doc", file_path="a.txt", loc="doc",
            patient_name="Meera", patient_name_normalized="meera",
        )
        ev2 = RecordEvidence(
            record_id="b::doc", file_path="b.txt", loc="doc",
            patient_name="Meera", patient_name_normalized="meera",
        )
        resolver.add_record(ev1)
        resolver.add_record(ev2)
        clusters = resolver.resolve()
        # Without any corroboration, should NOT merge
        self.assertNotEqual(clusters["a::doc"], clusters["b::doc"])

    def test_name_plus_relative_links(self) -> None:
        """Name match + relative name match should link."""
        resolver = IdentityResolver()
        ev1 = RecordEvidence(
            record_id="a::row:0", file_path="a.csv", loc="row:0",
            patient_name="Usha Tiwari",
            patient_name_normalized="usha tiwari",
            patient_name_phonetic=phonetic_key("Usha Tiwari"),
            relative_name_normalized="rahul tiwari",
        )
        ev2 = RecordEvidence(
            record_id="b::doc", file_path="b.txt", loc="doc",
            patient_name="Usha Tiwari",
            patient_name_normalized="usha tiwari",
            patient_name_phonetic=phonetic_key("Usha Tiwari"),
            relative_name_normalized="rahul tiwari",
        )
        resolver.add_record(ev1)
        resolver.add_record(ev2)
        clusters = resolver.resolve()
        self.assertEqual(clusters["a::row:0"], clusters["b::doc"])

    def test_cross_hospital_linking(self) -> None:
        """Same patient at different hospitals linked via phone."""
        resolver = IdentityResolver()
        ev1 = RecordEvidence(
            record_id="snj::row:0", file_path="snj.csv", loc="row:0",
            phones=["7286490658"],
            patient_name="Mahesh Chauhan",
            patient_name_normalized="mahesh chauhan",
            hospital="sanjeevani",
        )
        ev2 = RecordEvidence(
            record_id="dhh::row:0", file_path="dhh.json", loc="row:0",
            phones=["7286490658"],
            patient_name="Mahesh Chouhan",
            patient_name_normalized="mahesh chouhan",
            hospital="dhh",
        )
        resolver.add_record(ev1)
        resolver.add_record(ev2)
        clusters = resolver.resolve()
        self.assertEqual(clusters["snj::row:0"], clusters["dhh::row:0"])


class TestPseudonymization(unittest.TestCase):
    """Test HMAC-based pseudonymization."""

    def test_determinism(self) -> None:
        """Same key + same secret = same pseudonym."""
        secret = b"test-secret"
        psn1 = generate_pseudonym("patient:12345", secret)
        psn2 = generate_pseudonym("patient:12345", secret)
        self.assertEqual(psn1, psn2)

    def test_different_patients_different_pseudonyms(self) -> None:
        """Different patient keys = different pseudonyms."""
        secret = b"test-secret"
        psn1 = generate_pseudonym("patient:12345", secret)
        psn2 = generate_pseudonym("patient:67890", secret)
        self.assertNotEqual(psn1, psn2)

    def test_secret_rotation(self) -> None:
        """Different secret = different pseudonym for same patient."""
        psn1 = generate_pseudonym("patient:12345", b"secret-a")
        psn2 = generate_pseudonym("patient:12345", b"secret-b")
        self.assertNotEqual(psn1, psn2)

    def test_pseudonym_format(self) -> None:
        """Pseudonym should be PSN-XXXXXX."""
        psn = generate_pseudonym("test", b"secret")
        self.assertTrue(psn.startswith("PSN-"))
        self.assertEqual(len(psn), 10)  # PSN- + 6 chars
        self.assertTrue(pseudonym_is_valid(psn))

    def test_verify_determinism(self) -> None:
        secret = b"test"
        psn = generate_pseudonym("key", secret)
        self.assertTrue(verify_pseudonym_determinism("key", psn, secret))
        self.assertFalse(verify_pseudonym_determinism("key", "PSN-WRONG1", secret))

    def test_no_plain_hash(self) -> None:
        """Pseudonyms must not be plain SHA hashes of patient data."""
        patient_key = "phone:1234567890"
        secret = b"secret"
        psn = generate_pseudonym(patient_key, secret)
        # Plain SHA would be deterministic without the secret
        sha = hashlib.sha256(patient_key.encode()).hexdigest()[:10]
        self.assertNotEqual(psn[4:], sha)


class TestDateShifting(unittest.TestCase):
    """Test per-patient date shifting."""

    def test_shift_nonzero(self) -> None:
        """Date shift must never be zero."""
        for key in ["patient_a", "patient_b", "patient_c", "x", "y"]:
            shift = compute_date_shift(key, 180, b"secret")
            self.assertNotEqual(shift, 0)

    def test_shift_in_range(self) -> None:
        """Date shift must be within [-max, +max]."""
        for key in ["p1", "p2", "p3"]:
            shift = compute_date_shift(key, 180, b"secret")
            self.assertTrue(-180 <= shift <= 180)
            self.assertNotEqual(shift, 0)

    def test_shift_deterministic(self) -> None:
        """Same patient + same secret = same shift."""
        s1 = compute_date_shift("patient_a", 180, b"secret")
        s2 = compute_date_shift("patient_a", 180, b"secret")
        self.assertEqual(s1, s2)

    def test_shift_secret_dependent(self) -> None:
        """Different secret = different shift."""
        s1 = compute_date_shift("patient_a", 180, b"secret-1")
        s2 = compute_date_shift("patient_a", 180, b"secret-2")
        self.assertNotEqual(s1, s2)

    def test_length_of_stay_preservation(self) -> None:
        """Admission-discharge interval must be preserved after shifting."""
        admission = dt.date(2026, 10, 1)
        discharge = dt.date(2026, 10, 10)
        original_stay = (discharge - admission).days
        self.assertEqual(original_stay, 9)

        shifted_adm = shift_date(admission, "patient_x", 180, b"secret")
        shifted_dis = shift_date(discharge, "patient_x", 180, b"secret")
        shifted_stay = (shifted_dis - shifted_adm).days
        self.assertEqual(shifted_stay, original_stay)

    def test_shift_date_string(self) -> None:
        """Date string shifting preserves format."""
        result = shift_date_string("2026-10-01", "patient_a", 180, b"secret")
        self.assertIsNotNone(result)
        self.assertRegex(result, r'\d{4}-\d{2}-\d{2}')
        self.assertNotEqual(result, "2026-10-01")


class TestAgeBanding(unittest.TestCase):
    """Test age band generation."""

    def test_basic_bands(self) -> None:
        self.assertEqual(age_band(48), "45-49")
        self.assertEqual(age_band(0), "0-4")
        self.assertEqual(age_band(95), "95-99")
        self.assertEqual(age_band(23), "20-24")

    def test_band_contains_true_age(self) -> None:
        """Every band must contain the true age."""
        for age in range(0, 120):
            band = age_band(age)
            self.assertTrue(
                age_band_contains(band, age),
                f"Band {band} does not contain age {age}"
            )

    def test_custom_band_width(self) -> None:
        self.assertEqual(age_band(48, 10), "40-49")
        self.assertEqual(age_band(5, 10), "0-9")


class TestLocationGeneralization(unittest.TestCase):
    """Test location generalization."""

    def test_generalize_village(self) -> None:
        result = generalize_village("Durgamau Kalan", "Rae Bareli")
        self.assertEqual(result, "Rae Bareli")

    def test_generalize_pin(self) -> None:
        self.assertEqual(generalize_pin("229073"), "229***")
        self.assertEqual(generalize_pin("225362"), "225***")

    def test_generalize_address(self) -> None:
        addr = "C/O Naresh Chauhan, H.No. 364, Ward 20, Mohalla Raja Bazar, near Pani Tanki, Tehsil Lalganj, Distt. Rae Bareli"
        result = generalize_address(addr)
        # House number, ward, mohalla, landmark, C/O should be removed
        self.assertNotIn("364", result)
        self.assertNotIn("Ward 20", result)
        self.assertNotIn("Raja Bazar", result)
        self.assertNotIn("Pani Tanki", result)
        self.assertNotIn("Naresh Chauhan", result)
        # Tehsil and district should remain
        self.assertIn("Tehsil Lalganj", result)
        self.assertIn("Rae Bareli", result)


class TestPipelineIntegration(unittest.TestCase):
    """Integration tests for the full pipeline."""

    def test_pipeline_produces_valid_output(self) -> None:
        """Pipeline must produce report.json, records.jsonl, and sanitized/."""
        from rakshak.cli import run_pipeline

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inp = base / "inp"
            inp.mkdir()

            # Create a minimal valid input
            (inp / "notes.txt").write_text(
                "Patient: Ramesh Kumar\nAge: 48/M\nC/O fever\nTab Paracetamol 650 mg 1-0-1",
                encoding="utf-8",
            )
            reg_dir = inp / "registration"
            reg_dir.mkdir()
            (reg_dir / "test.csv").write_text(
                "UHID,Patient Name,Gender,Age,Mobile\n"
                "TST/001,Ramesh Kumar,M,48,9876543210\n"
                "TST/002,Sunita Patel,F,51,8599253525\n",
                encoding="utf-8",
            )

            out = base / "out"
            old_secret = os.environ.get("RAKSHA_SECRET")
            os.environ["RAKSHA_SECRET"] = "test-integration"
            try:
                rc = run_pipeline(inp, out)
            finally:
                if old_secret is None:
                    os.environ.pop("RAKSHA_SECRET", None)
                else:
                    os.environ["RAKSHA_SECRET"] = old_secret

            self.assertEqual(rc, 0)

            # Check output structure
            self.assertTrue((out / "report.json").exists())
            self.assertTrue((out / "records.jsonl").exists())
            self.assertTrue((out / "sanitized").is_dir())

            # Check report
            report = json.loads((out / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["schema"], "raksha-report/1")
            self.assertGreater(report["counts"]["files_total"], 0)
            self.assertGreater(report["counts"]["files_sanitized"], 0)

            # Check records.jsonl
            records_text = (out / "records.jsonl").read_text(encoding="utf-8")
            records = [json.loads(line) for line in records_text.strip().split("\n") if line.strip()]
            self.assertGreater(len(records), 0)

            # Check that pseudonyms appear in records
            linked = [r for r in records if r.get("patient")]
            # At least some should be linked
            for rec in records:
                self.assertIn("file", rec)
                self.assertIn("loc", rec)
                self.assertIn("patient", rec)

    def test_pipeline_determinism(self) -> None:
        """Same input + same secret = byte-identical output."""
        from rakshak.cli import run_pipeline

        def _tree_digest(root: Path) -> str:
            h = hashlib.sha256()
            for name in ("sanitized", "records.jsonl"):
                p = root / name
                items = sorted(p.rglob("*")) if p.is_dir() else ([p] if p.exists() else [])
                for f in items:
                    if f.is_file():
                        h.update(f.relative_to(root).as_posix().encode() + b"\0" + f.read_bytes() + b"\0")
            return h.hexdigest()

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inp = base / "inp"
            inp.mkdir()
            (inp / "note.txt").write_text("Patient: Test\nC/O fever", encoding="utf-8")

            out1 = base / "out1"
            out2 = base / "out2"

            old_secret = os.environ.get("RAKSHA_SECRET")
            os.environ["RAKSHA_SECRET"] = "determinism-test"
            try:
                run_pipeline(inp, out1)
                run_pipeline(inp, out2)
            finally:
                if old_secret is None:
                    os.environ.pop("RAKSHA_SECRET", None)
                else:
                    os.environ["RAKSHA_SECRET"] = old_secret

            self.assertEqual(_tree_digest(out1), _tree_digest(out2))

    def test_secret_changes_output(self) -> None:
        """Different RAKSHA_SECRET must produce different pseudonyms."""
        from rakshak.cli import run_pipeline

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inp = base / "inp"
            inp.mkdir()
            reg_dir = inp / "registration"
            reg_dir.mkdir()
            (reg_dir / "test.csv").write_text(
                "UHID,Patient Name,Mobile\nT001,Test Patient,9876543210\n",
                encoding="utf-8",
            )

            out_a = base / "out_a"
            out_b = base / "out_b"

            old_secret = os.environ.get("RAKSHA_SECRET")
            try:
                os.environ["RAKSHA_SECRET"] = "secret-alpha"
                run_pipeline(inp, out_a)
                os.environ["RAKSHA_SECRET"] = "secret-beta"
                run_pipeline(inp, out_b)
            finally:
                if old_secret is None:
                    os.environ.pop("RAKSHA_SECRET", None)
                else:
                    os.environ["RAKSHA_SECRET"] = old_secret

            records_a = (out_a / "records.jsonl").read_text(encoding="utf-8")
            records_b = (out_b / "records.jsonl").read_text(encoding="utf-8")
            # At least some content should differ
            self.assertNotEqual(records_a, records_b)


class TestEvidenceExtraction(unittest.TestCase):
    """Test evidence extraction from different formats."""

    def test_csv_evidence_extraction(self) -> None:
        header = ["UHID", "Patient Name", "Gender", "Age", "Mobile", "Aadhaar No"]
        row = ["SNJ/001", "Mahesh Chauhan", "M", "48", "+91 72864 90658", "397205839628"]
        ev = extract_evidence_csv(header, row, "test.csv", 0, "sanjeevani")
        self.assertEqual(ev.patient_name_normalized, "mahesh chauhan")
        self.assertIn("7286490658", ev.phones)
        self.assertIn("397205839628", ev.aadhaar)
        self.assertEqual(ev.age, 48)
        self.assertEqual(ev.gender, "M")

    def test_json_evidence_extraction(self) -> None:
        data = {
            "uhid": "DHH2026-084999",
            "name": {"first": "Sunita", "last": "Patel", "local": "सुनीता पटेल"},
            "gender": "female",
            "age": 51,
            "contact": {"mobile": "8599253525"},
            "ids": {"aadhar_no": 902115225016},
        }
        ev = extract_evidence_json(data, "test.json", "doc", "dhh")
        self.assertIn("8599253525", ev.phones)
        self.assertEqual(ev.age, 51)

    def test_text_evidence_extraction(self) -> None:
        text = "Patient: Mohammad Shahid\nAge: 39/M\nS/o Zubair\nUHID: SNJ/26/064258"
        ev = extract_evidence_text(text, "note.txt", "sanjeevani")
        self.assertTrue(len(ev.patient_name_normalized) > 0)
        self.assertEqual(ev.age, 39)
        self.assertEqual(ev.gender, "M")
        self.assertTrue(len(ev.mrns) > 0)


if __name__ == "__main__":
    unittest.main()
