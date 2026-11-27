"""Adversarial A5 tests: temporal shift recovery, LOS, rare-condition & repeated-visit attacks."""
import csv
import datetime as dt
import os
import tempfile
import unittest
from pathlib import Path

from rakshak.cli import run_pipeline
from rakshak.privacy.transforms import _parse_date, band_free_text_ages, compute_date_shift, shift_date_string


class TestAdversarialA5(unittest.TestCase):
    """A5: Targeted temporal and rare-condition re-identification resistance."""

    def test_global_date_shift_recovery_defeated_by_per_patient_shifts(self):
        """A5.A: Distinct patients get distinct HMAC offsets, preventing global shift recovery."""
        patients = [f"phone:98000000{i:02d}" for i in range(10)]
        shifts = [compute_date_shift(p, max_days=180, secret=b"a5-test-key") for p in patients]
        self.assertGreater(len(set(shifts)), 5, "Shifts must vary per patient")
        self.assertNotIn(0, shifts)

    def test_los_and_admission_discharge_chronology_preserved(self):
        """A5.C/D: Per-patient shifting preserves exact LOS and admission <= discharge across visits."""
        pkey = "phone:9811112222"
        adm1 = shift_date_string("2026-03-01", pkey, 180, b"a5-los-key")
        dis1 = shift_date_string("2026-03-07", pkey, 180, b"a5-los-key")
        adm2 = shift_date_string("2026-05-10", pkey, 180, b"a5-los-key")
        d_a1, d_d1, d_a2 = _parse_date(adm1), _parse_date(dis1), _parse_date(adm2)
        self.assertEqual((d_d1 - d_a1).days, 6)
        self.assertGreaterEqual(d_d1, d_a1)
        self.assertEqual((d_a2 - d_a1).days, 70)

    def test_rare_condition_and_extreme_age_trigger_adaptive_generalization(self):
        """A5.B/E: Rare diagnosis + senior age widens age band to 80+ and suppresses PIN."""
        with tempfile.TemporaryDirectory() as tmp:
            inp, out = Path(tmp) / "in", Path(tmp) / "out"
            inp.mkdir()
            rows = [["uhid", "patient_name", "age", "gender", "district", "pin", "diagnosis"]]
            for i in range(6):
                rows.append([f"H-{i}", f"Pat {i}", "42", "M", "lucknow", "226001", "Hypertension"])
            rows.append(["H-99", "Gopal Verma", "92", "M", "hardoi", "241001", "Visceral leishmaniasis"])
            with open(inp / "reg.csv", "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerows(rows)
            (inp / "note_gopal.txt").write_text(
                "Patient Name: Gopal Verma\nUHID: H-99\nAge/Sex: 92 Yrs/M\nDiagnosis: Visceral leishmaniasis\n",
                encoding="utf-8",
            )
            os.environ["RAKSHA_SECRET"] = "a5-rare-secret"
            run_pipeline(inp, out)

            txt_out = next((out / "sanitized").glob("*.txt")).read_text(encoding="utf-8")
            self.assertIn("80+ Yrs/M", txt_out)
            self.assertNotIn("92", txt_out)
            self.assertIn("Visceral leishmaniasis", txt_out)

            with open(out / "sanitized" / "reg.csv", encoding="utf-8") as f:
                out_rows = list(csv.DictReader(f))
            rare_row = [r for r in out_rows if "Visceral leishmaniasis" in r["diagnosis"]][0]
            self.assertEqual(rare_row["age"], "80+")
            self.assertEqual(rare_row["pin"], "[PIN]")

    def test_free_text_age_banding_preserves_clinical_doses(self):
        """A5: Free-text age banding must not corrupt doses or vitals."""
        sample = "Age/Sex: 85 Yrs/F\nBP 130/80 mmHg\nTab Ramipril 5mg 1-0-1 x 10 days\n"
        res = band_free_text_ages(sample, band_width=10)
        self.assertIn("80+ Yrs/F", res)
        self.assertIn("130/80 mmHg", res)
        self.assertIn("Ramipril 5mg 1-0-1 x 10 days", res)


if __name__ == "__main__":
    unittest.main()
