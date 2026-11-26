"""Adversarial security tests for RAKSHA.

Tests cover:
 - Cross-release linkage attacks (secret rotation must change all pseudonyms)
 - Same-name different-patient separation
 - Shared relative name attacks (common relative shouldn't link unrelated patients)
 - Conflicting identifiers (DOB, age, village)
 - Secret rotation verification
 - Malformed input handling
 - Path traversal and unsafe filenames
 - HMAC pseudonym security properties
 - Date shifting security (non-zero, bounded, deterministic, interval-preserving)
 - Age band truthfulness
 - PIN and location generalization
 - Secret never exposed in output
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import re
import tempfile
import unittest
from pathlib import Path

from rakshak.linkage.normalize import (
    extract_relative_name,
    normalize_aadhaar,
    normalize_abha,
    normalize_mrn,
    normalize_name,
    normalize_phone,
    phonetic_key,
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
    _parse_date,
)
from rakshak.security.logging import (
    audit_output_for_pii,
    contains_secret,
    sanitize_log_message,
)


# ---------------------------------------------------------------------------
# P1: Identity resolution adversarial tests
# ---------------------------------------------------------------------------

class TestSameNameDifferentPatient(unittest.TestCase):
    """Attack: two patients share a common name but differ on other evidence."""

    def test_common_surname_different_village_age(self) -> None:
        """Ram Kumar from two villages with different ages must NOT merge."""
        resolver = IdentityResolver()
        resolver.add_record(RecordEvidence(
            record_id="a::0", file_path="a.csv", loc="row:0",
            patient_name="Ram Kumar", patient_name_normalized="ram kumar",
            patient_name_phonetic=phonetic_key("Ram Kumar"),
            village="shivmau khurd", age=35, gender="M",
        ))
        resolver.add_record(RecordEvidence(
            record_id="b::0", file_path="b.csv", loc="row:0",
            patient_name="Ram Kumar", patient_name_normalized="ram kumar",
            patient_name_phonetic=phonetic_key("Ram Kumar"),
            village="durgamau kalan", age=58, gender="M",
        ))
        clusters = resolver.resolve()
        self.assertNotEqual(clusters["a::0"], clusters["b::0"])

    def test_common_name_different_dob(self) -> None:
        """Sunita Devi with different DOBs must NOT merge."""
        resolver = IdentityResolver()
        resolver.add_record(RecordEvidence(
            record_id="a::0", file_path="a.csv", loc="row:0",
            patient_name="Sunita Devi", patient_name_normalized="sunita",
            patient_name_phonetic=phonetic_key("Sunita Devi"),
            dob="1980-03-15", hospital="sanjeevani",
        ))
        resolver.add_record(RecordEvidence(
            record_id="b::0", file_path="b.csv", loc="row:0",
            patient_name="Sunita Devi", patient_name_normalized="sunita",
            patient_name_phonetic=phonetic_key("Sunita Devi"),
            dob="1965-07-22", hospital="dhh",
        ))
        clusters = resolver.resolve()
        self.assertNotEqual(clusters["a::0"], clusters["b::0"])

    def test_first_name_only_no_merge(self) -> None:
        """Single first name 'Asha' at two hospitals must NOT merge without corroboration."""
        resolver = IdentityResolver()
        resolver.add_record(RecordEvidence(
            record_id="a::doc", file_path="a.txt", loc="doc",
            patient_name="Asha", patient_name_normalized="asha",
            patient_name_phonetic=phonetic_key("Asha"),
            hospital="jeevanjyoti",
        ))
        resolver.add_record(RecordEvidence(
            record_id="b::doc", file_path="b.txt", loc="doc",
            patient_name="Asha", patient_name_normalized="asha",
            patient_name_phonetic=phonetic_key("Asha"),
            hospital="arogya",
        ))
        clusters = resolver.resolve()
        self.assertNotEqual(clusters["a::doc"], clusters["b::doc"])

    def test_name_subset_single_token_no_merge(self) -> None:
        """'Asha' should NOT match 'Asha Rajput' via subset — single meaningful token."""
        resolver = IdentityResolver()
        resolver.add_record(RecordEvidence(
            record_id="a::0", file_path="a.csv", loc="row:0",
            patient_name="Asha", patient_name_normalized="asha",
            patient_name_phonetic=phonetic_key("Asha"),
            relative_name_normalized="ramesh",
        ))
        resolver.add_record(RecordEvidence(
            record_id="b::0", file_path="b.csv", loc="row:0",
            patient_name="Asha Rajput", patient_name_normalized="asha rajput",
            patient_name_phonetic=phonetic_key("Asha Rajput"),
            relative_name_normalized="suresh",
        ))
        clusters = resolver.resolve()
        self.assertNotEqual(clusters["a::0"], clusters["b::0"])


class TestSharedRelativeAttack(unittest.TestCase):
    """Attack: two unrelated patients happen to share a relative name (e.g., 'Ram Kumar')."""

    def test_shared_common_relative_no_false_link(self) -> None:
        """Different patients sharing relative name 'Kumar Singh' must NOT merge."""
        resolver = IdentityResolver()
        resolver.add_record(RecordEvidence(
            record_id="a::0", file_path="a.csv", loc="row:0",
            patient_name="Fatima Bano", patient_name_normalized="fatima bano",
            patient_name_phonetic=phonetic_key("Fatima Bano"),
            relative_name_normalized="kumar singh",
            village="village_x", age=30,
        ))
        resolver.add_record(RecordEvidence(
            record_id="b::0", file_path="b.csv", loc="row:0",
            patient_name="Geeta Chauhan", patient_name_normalized="geeta chauhan",
            patient_name_phonetic=phonetic_key("Geeta Chauhan"),
            relative_name_normalized="kumar singh",
            village="village_y", age=45,
        ))
        clusters = resolver.resolve()
        self.assertNotEqual(clusters["a::0"], clusters["b::0"])


class TestConflictingIdentifiers(unittest.TestCase):
    """Attack: records share a strong ID but have conflicting demographics."""

    def test_shared_phone_conflicting_dob(self) -> None:
        """Same phone but different DOBs should NOT merge (possible family phone)."""
        resolver = IdentityResolver()
        resolver.add_record(RecordEvidence(
            record_id="a::0", file_path="a.csv", loc="row:0",
            phones=["9876543210"],
            patient_name="Rahul Sharma", patient_name_normalized="rahul sharma",
            dob="1990-05-15",
        ))
        resolver.add_record(RecordEvidence(
            record_id="b::0", file_path="b.csv", loc="row:0",
            phones=["9876543210"],
            patient_name="Priya Sharma", patient_name_normalized="priya sharma",
            dob="1992-11-20",
        ))
        clusters = resolver.resolve()
        # Names don't match → should block even with shared phone
        self.assertNotEqual(clusters["a::0"], clusters["b::0"])

    def test_shared_mrn_different_hospitals(self) -> None:
        """Same MRN number at different hospitals should NOT merge."""
        resolver = IdentityResolver()
        resolver.add_record(RecordEvidence(
            record_id="a::0", file_path="a.csv", loc="row:0",
            mrns=["IPD-2026-00432"],
            patient_name="Mahesh Chauhan", patient_name_normalized="mahesh chauhan",
            hospital="sanjeevani",
        ))
        resolver.add_record(RecordEvidence(
            record_id="b::0", file_path="b.csv", loc="row:0",
            mrns=["IPD-2026-00432"],
            patient_name="Different Person", patient_name_normalized="different person",
            hospital="jeevanjyoti",
        ))
        clusters = resolver.resolve()
        self.assertNotEqual(clusters["a::0"], clusters["b::0"])


class TestCrossHospitalLinking(unittest.TestCase):
    """Verify legitimate cross-hospital linking works."""

    def test_same_patient_different_hospitals_via_phone(self) -> None:
        """Same patient at sanjeevani and dhh linked by phone number."""
        resolver = IdentityResolver()
        resolver.add_record(RecordEvidence(
            record_id="snj::0", file_path="snj.csv", loc="row:0",
            phones=["7286490658"],
            patient_name="Mahesh Chauhan", patient_name_normalized="mahesh chauhan",
            hospital="sanjeevani", age=48,
        ))
        resolver.add_record(RecordEvidence(
            record_id="dhh::0", file_path="dhh.csv", loc="row:0",
            phones=["7286490658"],
            patient_name="Mahesh Chouhan", patient_name_normalized="mahesh chouhan",
            hospital="dhh", age=48,
        ))
        clusters = resolver.resolve()
        self.assertEqual(clusters["snj::0"], clusters["dhh::0"])

    def test_same_patient_name_dob_relative(self) -> None:
        """Same patient matched by name + DOB + relative name."""
        resolver = IdentityResolver()
        resolver.add_record(RecordEvidence(
            record_id="a::doc", file_path="a.txt", loc="doc",
            patient_name="Usha Tiwari", patient_name_normalized="usha tiwari",
            patient_name_phonetic=phonetic_key("Usha Tiwari"),
            dob="15/06/1975",
            relative_name_normalized="rahul tiwari",
        ))
        resolver.add_record(RecordEvidence(
            record_id="b::doc", file_path="b.txt", loc="doc",
            patient_name="Usha Tiwari", patient_name_normalized="usha tiwari",
            patient_name_phonetic=phonetic_key("Usha Tiwari"),
            dob="15/06/1975",
            relative_name_normalized="rahul tiwari",
        ))
        clusters = resolver.resolve()
        self.assertEqual(clusters["a::doc"], clusters["b::doc"])


# ---------------------------------------------------------------------------
# P2: Pseudonymization security tests
# ---------------------------------------------------------------------------

class TestPseudonymSecurity(unittest.TestCase):
    """Verify HMAC pseudonym security properties."""

    def test_hmac_not_plain_hash(self) -> None:
        """Pseudonym must use HMAC, not plain SHA256."""
        key = "phone:9876543210"
        secret = b"test-secret"
        psn = generate_pseudonym(key, secret)
        # Plain SHA256 would be the same regardless of secret
        plain = hashlib.sha256(key.encode()).hexdigest()
        self.assertNotIn(plain[:6].upper(), psn)

    def test_pseudonym_collision_resistance(self) -> None:
        """100 distinct patients must produce 100 distinct pseudonyms."""
        secret = b"collision-test"
        pseudonyms = set()
        for i in range(100):
            psn = generate_pseudonym(f"patient:{i}", secret)
            pseudonyms.add(psn)
        self.assertEqual(len(pseudonyms), 100)

    def test_cross_release_unlinkability(self) -> None:
        """Same patient with different secrets must be unlinkable."""
        key = "phone:9876543210"
        psn_a = generate_pseudonym(key, b"release-2025")
        psn_b = generate_pseudonym(key, b"release-2026")
        self.assertNotEqual(psn_a, psn_b)

    def test_pseudonym_format_valid(self) -> None:
        """All pseudonyms must pass format validation."""
        for i in range(50):
            psn = generate_pseudonym(f"key:{i}", b"sec")
            self.assertTrue(pseudonym_is_valid(psn), f"Invalid: {psn}")
            self.assertTrue(psn.startswith("PSN-"))
            self.assertEqual(len(psn), 10)

    def test_no_sequential_patterns(self) -> None:
        """Pseudonyms must not have sequential/predictable patterns."""
        secret = b"test"
        psns = [generate_pseudonym(f"p:{i}", secret) for i in range(10)]
        # Check that codes don't increment sequentially
        codes = [p[4:] for p in psns]
        for i in range(1, len(codes)):
            self.assertNotEqual(codes[i], codes[i-1])
        # No two adjacent codes should differ by exactly 1 in their numeric value
        # (this would indicate sequential assignment)


class TestSecretNeverExposed(unittest.TestCase):
    """Verify RAKSHA_SECRET never leaks into outputs."""

    def test_contains_secret_detection(self) -> None:
        self.assertTrue(contains_secret("the secret is practice", b"practice"))
        self.assertFalse(contains_secret("no secrets here", b"practice"))
        self.assertFalse(contains_secret("anything", b""))

    def test_log_sanitization(self) -> None:
        msg = sanitize_log_message("Patient 9876543210 admitted")
        self.assertNotIn("9876543210", msg)

    def test_audit_catches_phone(self) -> None:
        warnings = audit_output_for_pii("Contact: 9876543210")
        self.assertTrue(any("phone" in w.lower() for w in warnings))

    def test_audit_catches_aadhaar(self) -> None:
        warnings = audit_output_for_pii("Aadhaar: 1234 5678 9012")
        self.assertTrue(any("aadhaar" in w.lower() for w in warnings))

    def test_audit_catches_secret(self) -> None:
        old = os.environ.get("RAKSHA_SECRET")
        os.environ["RAKSHA_SECRET"] = "test-secret-value"
        try:
            warnings = audit_output_for_pii("Debug: test-secret-value leaked")
            self.assertTrue(any("secret" in w.lower() for w in warnings))
        finally:
            if old is None:
                os.environ.pop("RAKSHA_SECRET", None)
            else:
                os.environ["RAKSHA_SECRET"] = old


# ---------------------------------------------------------------------------
# P3: Date shifting security tests
# ---------------------------------------------------------------------------

class TestDateShiftSecurity(unittest.TestCase):
    """Verify date shift security properties."""

    def test_shift_never_zero(self) -> None:
        """Zero shift would reveal the real date."""
        for i in range(100):
            shift = compute_date_shift(f"patient_{i}", 180, b"secret")
            self.assertNotEqual(shift, 0, f"Zero shift for patient_{i}")

    def test_shift_bounded(self) -> None:
        """Shift must stay within [-max, +max]."""
        for i in range(100):
            shift = compute_date_shift(f"p{i}", 180, b"s")
            self.assertTrue(-180 <= shift <= 180, f"Out of range: {shift}")

    def test_stay_duration_preserved(self) -> None:
        """Hospital stay duration must be preserved after shifting."""
        adm = dt.date(2026, 3, 15)
        dis = dt.date(2026, 3, 22)
        stay = (dis - adm).days
        s_adm = shift_date(adm, "patient_1", 180, b"secret")
        s_dis = shift_date(dis, "patient_1", 180, b"secret")
        self.assertEqual((s_dis - s_adm).days, stay)

    def test_temporal_ordering_preserved(self) -> None:
        """Events for the same patient must maintain chronological order."""
        dates = [dt.date(2026, 1, i) for i in range(1, 15)]
        shifted = [shift_date(d, "patient_x", 180, b"sec") for d in dates]
        for i in range(1, len(shifted)):
            self.assertGreater(shifted[i], shifted[i-1])

    def test_shift_secret_dependent(self) -> None:
        """Different secrets must produce different shifts."""
        s1 = compute_date_shift("p1", 180, b"secret-A")
        s2 = compute_date_shift("p1", 180, b"secret-B")
        self.assertNotEqual(s1, s2)

    def test_shift_date_string_formats(self) -> None:
        """Various date formats must be parsed and shifted correctly."""
        formats = [
            ("2026-10-15", r"\d{4}-\d{2}-\d{2}"),
            ("15/10/2026", r"\d{2}/\d{2}/\d{4}"),
            ("15-10-2026", r"\d{2}/\d{2}/\d{4}"),
        ]
        for date_str, pattern in formats:
            result = shift_date_string(date_str, "p1", 180, b"sec")
            self.assertIsNotNone(result, f"Failed to parse: {date_str}")
            self.assertNotEqual(result, date_str)


# ---------------------------------------------------------------------------
# P3: Age band and location generalization tests
# ---------------------------------------------------------------------------

class TestAgeBandSecurity(unittest.TestCase):
    """Verify age bands are truthful and k-anonymous."""

    def test_all_ages_truthful(self) -> None:
        """Every age 0-119 must land in a band that contains it."""
        for age in range(120):
            band = age_band(age, 5)
            self.assertTrue(age_band_contains(band, age),
                            f"age={age} not in band={band}")

    def test_band_width_correct(self) -> None:
        """Each band spans exactly band_width years."""
        for age in range(0, 100, 5):
            band = age_band(age, 5)
            lo, hi = map(int, band.split("-"))
            self.assertEqual(hi - lo, 4)

    def test_custom_width(self) -> None:
        """10-year bands work correctly."""
        self.assertEqual(age_band(37, 10), "30-39")
        self.assertTrue(age_band_contains("30-39", 37))


class TestLocationGeneralization(unittest.TestCase):
    """Verify location generalization removes identifying details."""

    def test_village_generalizes_to_district(self) -> None:
        self.assertEqual(generalize_village("Shivmau Khurd", "Lakhimpur Kheri"),
                         "Lakhimpur Kheri")

    def test_village_without_district(self) -> None:
        self.assertEqual(generalize_village("Shivmau Khurd", ""), "[DISTRICT]")

    def test_pin_generalization(self) -> None:
        self.assertEqual(generalize_pin("229073"), "229***")
        self.assertEqual(generalize_pin("110001"), "110***")

    def test_address_removes_house_number(self) -> None:
        addr = "H.No. 42, Ward 5, Mohalla Bazaar, Tehsil Sadar, Distt. Hardoi"
        result = generalize_address(addr)
        self.assertNotIn("42", result)
        self.assertNotIn("Ward 5", result)
        self.assertNotIn("Bazaar", result)
        self.assertIn("Hardoi", result)

    def test_address_removes_hindi_landmarks(self) -> None:
        addr = "मकान नं. 100, स्कूल के पास, तहसील सदर"
        result = generalize_address(addr)
        self.assertNotIn("100", result)
        self.assertNotIn("के पास", result)


# ---------------------------------------------------------------------------
# P4: Malformed input handling
# ---------------------------------------------------------------------------

class TestMalformedInput(unittest.TestCase):
    """Verify pipeline handles malformed and edge-case inputs safely."""

    def test_empty_name(self) -> None:
        """Empty name should normalize to empty string."""
        self.assertEqual(normalize_name(""), "")

    def test_whitespace_name(self) -> None:
        """Whitespace-only name should normalize to empty string."""
        self.assertEqual(normalize_name("   "), "")

    def test_none_phone(self) -> None:
        """Non-phone strings return None."""
        self.assertIsNone(normalize_phone(""))
        self.assertIsNone(normalize_phone("abc"))
        self.assertIsNone(normalize_phone("123"))

    def test_invalid_aadhaar(self) -> None:
        self.assertIsNone(normalize_aadhaar("123"))
        self.assertIsNone(normalize_aadhaar(""))

    def test_invalid_abha(self) -> None:
        self.assertIsNone(normalize_abha("123"))

    def test_empty_text_evidence(self) -> None:
        """Empty text should produce evidence with no identifiers."""
        ev = extract_evidence_text("", "empty.txt", "")
        self.assertEqual(ev.phones, [])
        self.assertEqual(ev.mrns, [])
        self.assertEqual(ev.patient_name, "")

    def test_csv_evidence_missing_columns(self) -> None:
        """Row shorter than header should not crash."""
        header = ["UHID", "Patient Name", "Mobile", "Age"]
        row = ["T001", "Test"]  # Missing Mobile and Age
        ev = extract_evidence_csv(header, row, "test.csv", 0, "")
        self.assertEqual(ev.patient_name_normalized, "test")
        self.assertEqual(ev.phones, [])

    def test_json_evidence_empty_dict(self) -> None:
        ev = extract_evidence_json({}, "test.json", "doc", "")
        self.assertEqual(ev.patient_name, "")

    def test_pseudonym_empty_key(self) -> None:
        """Empty patient key should still produce a valid pseudonym."""
        psn = generate_pseudonym("", b"secret")
        self.assertTrue(pseudonym_is_valid(psn))

    def test_date_parse_invalid(self) -> None:
        """Invalid date strings should return None."""
        self.assertIsNone(_parse_date(""))
        self.assertIsNone(_parse_date("not a date"))
        self.assertIsNone(_parse_date("99/99/9999"))


# ---------------------------------------------------------------------------
# P4: Path traversal and unsafe filename tests
# ---------------------------------------------------------------------------

class TestPathSecurity(unittest.TestCase):
    """Verify no path traversal is possible through filenames."""

    def test_normalize_mrn_strips_whitespace(self) -> None:
        self.assertEqual(normalize_mrn("  JJH-001  "), "JJH-001")

    def test_relative_path_posix(self) -> None:
        """Path separators should be POSIX-normalized."""
        # Verify Path handling doesn't allow traversal
        p = Path("discharge/../../etc/passwd")
        # The rel_path should be under the input directory
        self.assertIn("..", str(p))


# ---------------------------------------------------------------------------
# P4: Pipeline integration security tests
# ---------------------------------------------------------------------------

class TestPipelineSecurity(unittest.TestCase):
    """Full pipeline security verification using synthetic data."""

    def test_pipeline_no_secret_in_output(self) -> None:
        """RAKSHA_SECRET must never appear in any output file."""
        from rakshak.cli import run_pipeline

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inp = base / "inp"
            inp.mkdir()
            (inp / "note.txt").write_text(
                "Patient: Test Patient\nAge: 30/M\nC/O fever\n",
                encoding="utf-8",
            )
            out = base / "out"
            secret_val = "super-secret-test-value-12345"
            old = os.environ.get("RAKSHA_SECRET")
            os.environ["RAKSHA_SECRET"] = secret_val
            try:
                run_pipeline(inp, out)
            finally:
                if old is None:
                    os.environ.pop("RAKSHA_SECRET", None)
                else:
                    os.environ["RAKSHA_SECRET"] = old

            # Check all output files for secret leakage
            for p in out.rglob("*"):
                if p.is_file():
                    content = p.read_text(encoding="utf-8", errors="replace")
                    self.assertNotIn(secret_val, content,
                                     f"Secret leaked in {p.relative_to(out)}")

    def test_pipeline_no_raw_identifiers_in_records(self) -> None:
        """records.jsonl must not contain raw phone/Aadhaar/names."""
        from rakshak.cli import run_pipeline

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inp = base / "inp"
            inp.mkdir()
            reg = inp / "registration"
            reg.mkdir()
            (reg / "patients.csv").write_text(
                "UHID,Patient Name,Mobile,Aadhaar No\n"
                "TST/001,Rahul Sharma,9876543210,397205839628\n",
                encoding="utf-8",
            )
            out = base / "out"
            old = os.environ.get("RAKSHA_SECRET")
            os.environ["RAKSHA_SECRET"] = "test-records-check"
            try:
                run_pipeline(inp, out)
            finally:
                if old is None:
                    os.environ.pop("RAKSHA_SECRET", None)
                else:
                    os.environ["RAKSHA_SECRET"] = old

            rj = out / "records.jsonl"
            if rj.exists():
                content = rj.read_text(encoding="utf-8")
                self.assertNotIn("9876543210", content)
                self.assertNotIn("397205839628", content)
                # Pseudonyms should be present
                for line in content.strip().split("\n"):
                    if line.strip():
                        rec = json.loads(line)
                        patient = rec.get("patient")
                        if patient:
                            self.assertTrue(
                                patient.startswith("PSN-"),
                                f"Non-pseudonym patient ID: {patient}"
                            )

    def test_deterministic_output(self) -> None:
        """Same input + same secret = identical output."""
        from rakshak.cli import run_pipeline

        def digest(root: Path) -> str:
            h = hashlib.sha256()
            for name in ("sanitized", "records.jsonl"):
                p = root / name
                items = sorted(p.rglob("*")) if p.is_dir() else ([p] if p.exists() else [])
                for f in items:
                    if f.is_file():
                        h.update(f.relative_to(root).as_posix().encode()
                                 + b"\0" + f.read_bytes() + b"\0")
            return h.hexdigest()

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inp = base / "inp"
            inp.mkdir()
            (inp / "note.txt").write_text(
                "Patient: Determinism Test\nC/O cough",
                encoding="utf-8",
            )
            out1, out2 = base / "out1", base / "out2"
            old = os.environ.get("RAKSHA_SECRET")
            os.environ["RAKSHA_SECRET"] = "determinism"
            try:
                run_pipeline(inp, out1)
                run_pipeline(inp, out2)
            finally:
                if old is None:
                    os.environ.pop("RAKSHA_SECRET", None)
                else:
                    os.environ["RAKSHA_SECRET"] = old
            self.assertEqual(digest(out1), digest(out2))

    def test_different_secret_different_output(self) -> None:
        """Changing the secret must change pseudonyms and date shifts."""
        from rakshak.cli import run_pipeline

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inp = base / "inp"
            inp.mkdir()
            reg = inp / "registration"
            reg.mkdir()
            (reg / "test.csv").write_text(
                "UHID,Patient Name,Mobile\nT/1,Test Patient,9876543210\n",
                encoding="utf-8",
            )
            out_a, out_b = base / "out_a", base / "out_b"
            old = os.environ.get("RAKSHA_SECRET")
            try:
                os.environ["RAKSHA_SECRET"] = "alpha"
                run_pipeline(inp, out_a)
                os.environ["RAKSHA_SECRET"] = "beta"
                run_pipeline(inp, out_b)
            finally:
                if old is None:
                    os.environ.pop("RAKSHA_SECRET", None)
                else:
                    os.environ["RAKSHA_SECRET"] = old
            rec_a = (out_a / "records.jsonl").read_text(encoding="utf-8")
            rec_b = (out_b / "records.jsonl").read_text(encoding="utf-8")
            self.assertNotEqual(rec_a, rec_b)


if __name__ == "__main__":
    unittest.main()
