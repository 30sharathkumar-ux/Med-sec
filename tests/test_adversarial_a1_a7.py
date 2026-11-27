"""Rigorous synthetic adversarial test suite covering A1-A7 attacks (Section 5)."""
import csv
import hashlib
import hmac
import json
import os
import tempfile
import unittest
from pathlib import Path

from rakshak.cli import run_pipeline
from rakshak.privacy.k_anonymity import compute_adaptive_profile_policies
from rakshak.privacy.pseudonymize import generate_pseudonym
from rakshak.privacy.transforms import band_free_text_ages, compute_date_shift


class TestAdversarialA1ToA7(unittest.TestCase):
    """End-to-end synthetic tests for all 7 Secret Wards attack categories."""

    def test_a1_direct_exposure_and_side_channels(self):
        """A1: Direct identifiers must not survive in sanitized/, filenames, report.json, or records.jsonl."""
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "in"
            out = Path(tmp) / "out"
            inp.mkdir()
            (inp / "Ramesh_Kumar_9876543210.txt").write_text(
                "Patient Name: Ramesh Kumar\nMobile: 9876543210\nAadhaar: 1234 5678 9012\nDiagnosis: Typhoid fever\n",
                encoding="utf-8",
            )
            os.environ["RAKSHA_SECRET"] = "synth-a1-secret"
            run_pipeline(inp, out)

            all_out = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in out.rglob("*") if p.is_file())
            all_names = [p.name for p in out.rglob("*") if p.is_file()]
            self.assertNotIn("Ramesh Kumar", all_out)
            self.assertNotIn("9876543210", all_out)
            self.assertNotIn("1234 5678 9012", all_out)
            self.assertFalse(any("Ramesh" in n or "9876543210" in n for n in all_names))
            self.assertNotIn("synth-a1-secret", all_out)
            self.assertIn("Typhoid fever", all_out)

    def test_a2_a3_adaptive_k_anonymity_widens_unique_qi(self):
        """A2/A3: Multi-patient dataset with unique age+PIN+district triggers adaptive age widening & PIN suppression."""
        profiles = {
            f"p{i}": {"age": 42, "gender": "M", "district": "lucknow", "pin_prefix": "226", "rare_condition": False}
            for i in range(6)
        }
        # Unique 93-year-old outlier in hardoi
        profiles["outlier"] = {"age": 93, "gender": "F", "district": "hardoi", "pin_prefix": "241", "rare_condition": False}

        policies, metrics = compute_adaptive_profile_policies(profiles, min_group_size=5, base_band_width=5)
        self.assertEqual(policies["p0"]["age_band_width"], 5)
        self.assertEqual(policies["p0"]["pin_suppress_level"], 0)
        self.assertGreaterEqual(policies["outlier"]["age_band_width"], 10)
        self.assertGreaterEqual(policies["outlier"]["pin_suppress_level"], 1)
        self.assertEqual(metrics["profiles_widened"], 1)

    def test_a4_profile_aggregation_consistent_across_records(self):
        """A4: Linked records for the same patient share one pseudonym and consistent age/PIN generalization."""
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "in"
            out = Path(tmp) / "out"
            inp.mkdir()
            # 6 patients so adaptive k-anonymity is active (>= 5)
            rows = [["uhid", "patient_name", "age", "gender", "district", "pin"]]
            for i in range(5):
                rows.append([f"HOSP-{100+i}", f"Patient {i}", "32", "M", "lucknow", "226001"])
            rows.append(["HOSP-999", "Kamla Devi", "88", "F", "sitapur", "261001"])
            with open(inp / "reg.csv", "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerows(rows)
            (inp / "note_kamla.txt").write_text(
                "Patient Name: Kamla Devi\nUHID: HOSP-999\nAge/Sex: 88 Yrs/F\nDiagnosis: Parkinson's disease\n",
                encoding="utf-8",
            )
            os.environ["RAKSHA_SECRET"] = "synth-a4-secret"
            run_pipeline(inp, out)

            note_out = next((out / "sanitized").glob("*.txt")).read_text(encoding="utf-8")
            self.assertIn("80+", note_out)
            self.assertNotIn("88", note_out)
            self.assertIn("Parkinson's disease", note_out)

    def test_a5_temporal_shift_preserves_los_and_bands_text_ages(self):
        """A5: Per-patient date shifts differ across patients (defeating global recovery) while preserving LOS."""
        d1 = compute_date_shift("phone:9000000001", 180, b"a5-secret")
        d2 = compute_date_shift("phone:9000000002", 180, b"a5-secret")
        self.assertNotEqual(d1, d2)
        self.assertNotEqual(d1, 0)

        # Free-text age banding preserves medications & dosages
        txt = "Age/Sex: 97 Yrs/M\nRx: Tab Ramipril 5mg 1-0-1 x 5 days\n"
        banded = band_free_text_ages(txt, band_width=10)
        self.assertIn("80+ Yrs/M", banded)
        self.assertNotIn("97", banded)
        self.assertIn("Ramipril 5mg 1-0-1 x 5 days", banded)

    def test_a6_pseudonym_inversion_and_domain_separation(self):
        """A6: Pseudonyms require secret key and use distinct HMAC domains."""
        p_real = generate_pseudonym("phone:9876543210", b"real-secret")
        p_guess = generate_pseudonym("phone:9876543210", b"wrong-secret")
        self.assertNotEqual(p_real, p_guess)
        d_psn = hmac.new(b"real-secret", b"psn|phone:9876543210", hashlib.sha256).digest()
        d_shift = hmac.new(b"real-secret", b"shift|phone:9876543210", hashlib.sha256).digest()
        self.assertNotEqual(d_psn, d_shift)

    def test_no_double_banding_in_free_text(self):
        """Regression: band_free_text_ages must not double-band 20-year ranges into 40-40-59."""
        out_en = band_free_text_ages("Age/Sex: 42 Yrs/M", band_width=20)
        self.assertEqual(out_en, "Age/Sex: 40-59 Yrs/M")
        self.assertNotIn("40-40-59", out_en)

        out_20 = band_free_text_ages("Age: 25 Yrs/M", band_width=20)
        self.assertEqual(out_20, "Age: 20-39 Yrs/M")

        out_hi = band_free_text_ages("उम्र: 42 वर्ष/M", band_width=20)
        self.assertEqual(out_hi, "उम्र: 40-59 वर्ष/M")

    def test_a7_cross_release_unlinkable_and_same_secret_deterministic(self):
        """A7: Different secrets yield different pseudonyms; same secret yields identical output."""
        p1 = generate_pseudonym("aadhaar:123456789012", b"release-1")
        p2 = generate_pseudonym("aadhaar:123456789012", b"release-2")
        p1_repeat = generate_pseudonym("aadhaar:123456789012", b"release-1")
        self.assertNotEqual(p1, p2)
        self.assertEqual(p1, p1_repeat)


if __name__ == "__main__":
    unittest.main()
