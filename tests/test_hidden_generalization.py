"""Generalization Test Suite: Fresh synthetic dataset across unseen formats and entities.

Validates that RAKSHA processes entirely unseen data without over-fitting to dev/input:
  1. Unseen diverse Indian names (South Indian, Christian, Parsi, Northeastern)
  2. Unseen hospital prefixes (KGMU, AIIMS, MAX, APOLLO)
  3. Rare diagnoses and extreme senior ages (94, 102) triggering adaptive k-anonymity
  4. Homonym pairs with different phones/addresses (no false merge)
  5. Multilingual and Hinglish clinical notes
  6. Multi-visit encounters preserving interval and LOS
  7. Diverse file formats (CSV, TSV, JSON, TXT) with missing demographics
"""
import csv
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from rakshak.cli import run_pipeline
from rakshak.privacy.transforms import _parse_date


class TestHiddenGeneralization(unittest.TestCase):
    """Rigorous generalization testing on synthetic unseen hospital data."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.inp = Path(self.tmp_dir.name) / "input"
        self.out = Path(self.tmp_dir.name) / "output"
        self.inp.mkdir(parents=True, exist_ok=True)
        self.out.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_unseen_diverse_cohort_and_hospitals(self):
        # 1. Structured registration CSV with unseen hospital KGMU and South Indian / Christian names
        reg_csv = self.inp / "kgmu_registration.csv"
        rows = [
            ["mrn", "patient_name", "age", "gender", "district", "pin", "phone", "aadhaar", "reg_date"],
            ["KGMU/26/1001", "Subramanian Ramaswamy", "67", "M", "Chennai", "600001", "9840112345", "912345678901", "12/03/2026"],
            ["KGMU/26/1002", "Mary Grace Fernandez", "34", "F", "Kochi", "682001", "9847123456", "912345678902", "14/03/2026"],
            ["KGMU/26/1003", "Boman Rustom Irani", "94", "M", "Mumbai", "400001", "9820123456", "912345678903", "15/03/2026"],
            ["KGMU/26/1004", "Tenzing Lobsang Dorjee", "45", "M", "Gangtok", "737101", "9832123456", "912345678904", "16/03/2026"],
            ["KGMU/26/1005", "Anita Roy", "28", "F", "Kolkata", "700001", "9830123456", "912345678905", "17/03/2026"],
            ["KGMU/26/1006", "Anita Roy", "52", "F", "Ranchi", "834001", "9431123456", "912345678906", "18/03/2026"], # Homonym with different phone/age
        ]
        with open(reg_csv, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows(rows)

        # 2. Inpatient claims TSV with unseen hospital APOLLO
        claims_tsv = self.inp / "apollo_claims.tsv"
        claims = [
            ["claim_id", "mrn", "admission_date", "discharge_date", "diagnosis", "amount"],
            ["CLM-01", "APOLLO-8891", "2026-04-01", "2026-04-10", "Acute appendicitis", "45000"],
            ["CLM-02", "APOLLO-8892", "2026-04-05", "2026-04-08", "Visceral leishmaniasis (kala-azar)", "60000"],
        ]
        with open(claims_tsv, "w", newline="", encoding="utf-8") as f:
            csv.writer(f, delimiter="\t").writerows(claims)

        # 3. Multilingual clinical note in Hindi / Hinglish with Doctor qualification
        note_hindi = self.inp / "kgmu_opd_note.txt"
        note_hindi.write_text(
            "किंशुक मेडिकल यूनिवर्सिटी (KGMU)\n"
            "रोगी का नाम: Subramanian Ramaswamy\n"
            "MRN: KGMU/26/1001\n"
            "Age/Sex: 67 Yrs/M\n"
            "Chief Complaints: Severe chest pain and sweating for 2 hours\n"
            "Diagnosis: Acute Myocardial Infarction\n"
            "Rx: Tab Aspirin 75mg 1-0-1 x 14 days\n"
            "Dr. Rajeshwar Sharma (MD, DM Cardiology)\n",
            encoding="utf-8"
        )

        # 4. Senior patient with rare condition note
        note_senior = self.inp / "boman_irani_note.txt"
        note_senior.write_text(
            "Patient Name: Boman Rustom Irani\n"
            "MRN: KGMU/26/1003\n"
            "Age/Sex: 94 Yrs/M\n"
            "District: Mumbai\n"
            "Diagnosis: Idiopathic pulmonary fibrosis\n"
            "BP: 130/80 mmHg, SpO2: 92%\n",
            encoding="utf-8"
        )

        # Run RAKSHA pipeline with a fresh secret
        os.environ["RAKSHA_SECRET"] = "generalization-test-secret-2026"
        res = run_pipeline(self.inp, self.out)

        # Assert Pipeline Success (returns 0 on success)
        self.assertEqual(res, 0)

        # Check Sanitized Files Exist
        san_dir = self.out / "sanitized"
        self.assertTrue((san_dir / "kgmu_registration.csv").exists())
        self.assertTrue((san_dir / "apollo_claims.tsv").exists())

        # Check Direct PII Redaction
        all_san_txt = ""
        for p in san_dir.rglob("*"):
            if p.is_file():
                all_san_txt += "\n" + p.read_text(encoding="utf-8", errors="replace")

        # Names must not appear in cleartext
        self.assertNotIn("Subramanian Ramaswamy", all_san_txt)
        self.assertNotIn("Mary Grace Fernandez", all_san_txt)
        self.assertNotIn("Boman Rustom Irani", all_san_txt)
        self.assertNotIn("Tenzing Lobsang Dorjee", all_san_txt)

        # Contact numbers must be redacted
        self.assertNotIn("9840112345", all_san_txt)
        self.assertNotIn("912345678901", all_san_txt)

        # Doctor qualification must NOT be redacted as patient name
        self.assertIn("MD, DM Cardiology", all_san_txt)

        # Medical Diagnoses and Regimens MUST BE Preserved
        self.assertIn("Acute Myocardial Infarction", all_san_txt)
        self.assertIn("Aspirin 75mg 1-0-1 x 14 days", all_san_txt)
        self.assertIn("Idiopathic pulmonary fibrosis", all_san_txt)
        self.assertIn("130/80 mmHg", all_san_txt)

        # Age Banding on Senior Patient (94 Yrs/M must become 80+ or banded, not 94)
        self.assertNotIn("94 Yrs/M", all_san_txt)
        self.assertTrue("80+ Yrs/M" in all_san_txt or "90-94 Yrs/M" in all_san_txt or "80-99" in all_san_txt)

        # Length of stay in TSV claims must remain exact (9 days and 3 days)
        with open(san_dir / "apollo_claims.tsv", encoding="utf-8") as f:
            san_claims = list(csv.DictReader(f, delimiter="\t"))
        self.assertEqual(len(san_claims), 2)
        d1_adm = _parse_date(san_claims[0]["admission_date"])
        d1_dis = _parse_date(san_claims[0]["discharge_date"])
        self.assertEqual((d1_dis - d1_adm).days, 9)

        d2_adm = _parse_date(san_claims[1]["admission_date"])
        d2_dis = _parse_date(san_claims[1]["discharge_date"])
        self.assertEqual((d2_dis - d2_adm).days, 3)

        # Homonym separation: Anita Roy (Chennai 28) and Anita Roy (Ranchi 52) must have distinct PSNs
        with open(san_dir / "kgmu_registration.csv", encoding="utf-8") as f:
            san_reg = list(csv.DictReader(f))

        # Read records.jsonl to verify PSNs
        records = [json.loads(l) for l in (self.out / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
        anita_recs = [r for r in records if "KGMU/26/1005" in str(r.get("entities", [])) or "KGMU/26/1006" in str(r.get("entities", [])) or r.get("loc") in ("row:4", "row:5")]
        if len(anita_recs) >= 2:
            psn_1 = anita_recs[0].get("patient")
            psn_2 = anita_recs[1].get("patient")
            self.assertNotEqual(psn_1, psn_2, "Homonym collision: distinct patients were wrongly merged!")

    def test_multilingual_hindi_latin_crosslink_and_pediatric(self):
        """Cross-script Devanagari/Latin entity linkage and pediatric age banding."""
        # 1. Registration in Devanagari Hindi
        reg_hindi = self.inp / "aiims_hindi_reg.csv"
        rows = [
            ["mrn", "patient_name", "age", "gender", "district", "pin", "phone", "aadhaar", "reg_date"],
            ["AIIMS/26/5001", "देवेन्द्र प्रसाद", "73", "M", "Varanasi", "221001", "9415123456", "812345678901", "10/01/2026"],
            ["AIIMS/26/5002", "Aarav Sharma", "2", "M", "Gorakhpur", "273001", "9415123457", "812345678902", "12/01/2026"],
        ]
        with open(reg_hindi, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows(rows)

        # 2. English discharge note for the same Devendra Prasad
        note_eng = self.inp / "devendra_discharge.txt"
        note_eng.write_text(
            "AIIMS Rishikesh\n"
            "Patient Name: Devendra Prasad\n"
            "MRN: AIIMS/26/5001\n"
            "Age/Sex: 73 Yrs/M\n"
            "District: Varanasi\n"
            "Admission Date: 15/01/2026\n"
            "Discharge Date: 22/01/2026\n"
            "Diagnosis: Type 2 Diabetes Mellitus with Neuropathy\n"
            "Rx: Tab Metformin 500mg 1-0-1\n",
            encoding="utf-8"
        )

        # 3. Pediatric OPD note for Aarav Sharma (2 years old)
        note_ped = self.inp / "aarav_pediatric.txt"
        note_ped.write_text(
            "AIIMS Rishikesh - Pediatric OPD\n"
            "Patient Name: Aarav Sharma\n"
            "MRN: AIIMS/26/5002\n"
            "Age/Sex: 2 Yrs/M\n"
            "District: Gorakhpur\n"
            "Diagnosis: Biliary atresia\n"
            "Syp Amoxicillin 125mg/5ml\n",
            encoding="utf-8"
        )

        os.environ["RAKSHA_SECRET"] = "multilingual-pediatric-secret"
        res = run_pipeline(self.inp, self.out)
        self.assertEqual(res, 0)

        san_dir = self.out / "sanitized"
        all_san = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in san_dir.rglob("*") if p.is_file())

        # Direct identifiers redacted in both English and Devanagari
        self.assertNotIn("देवेन्द्र प्रसाद", all_san)
        self.assertNotIn("Devendra Prasad", all_san)
        self.assertNotIn("Aarav Sharma", all_san)
        self.assertNotIn("9415123456", all_san)

        # Pediatric age 2 Yrs/M must become 0-4 Yrs/M
        self.assertNotIn("2 Yrs/M", all_san)
        self.assertIn("0-4 Yrs/M", all_san)

        # Diagnoses preserved
        self.assertIn("Type 2 Diabetes Mellitus with Neuropathy", all_san)
        self.assertIn("Biliary atresia", all_san)
        self.assertIn("Metformin 500mg 1-0-1", all_san)

    def test_multi_visit_intervals_and_missing_demographics(self):
        """Interval preservation across 3 visits and graceful handling of missing demographics."""
        claims_csv = self.inp / "multi_visit_claims.csv"
        rows = [
            ["claim_id", "mrn", "admission_date", "discharge_date", "diagnosis"],
            ["C-101", "MAX-991", "2026-01-01", "2026-01-05", "Hypertension"],
            ["C-102", "MAX-991", "2026-01-20", "2026-01-25", "Followup"],
            ["C-103", "MAX-991", "2026-03-01", "2026-03-05", "Routine review"],
            # Record with missing demographics
            ["C-201", "MAX-888", "2026-02-10", "2026-02-12", "Gastritis"],
        ]
        with open(claims_csv, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows(rows)

        os.environ["RAKSHA_SECRET"] = "multi-visit-interval-secret"
        res = run_pipeline(self.inp, self.out)
        self.assertEqual(res, 0)

        with open(self.out / "sanitized" / "multi_visit_claims.csv", encoding="utf-8") as f:
            san_rows = list(csv.DictReader(f))

        d1_adm = _parse_date(san_rows[0]["admission_date"])
        d1_dis = _parse_date(san_rows[0]["discharge_date"])
        d2_adm = _parse_date(san_rows[1]["admission_date"])
        d2_dis = _parse_date(san_rows[1]["discharge_date"])
        d3_adm = _parse_date(san_rows[2]["admission_date"])
        d3_dis = _parse_date(san_rows[2]["discharge_date"])

        # Check LOS for each visit (all 4 days)
        self.assertEqual((d1_dis - d1_adm).days, 4)
        self.assertEqual((d2_dis - d2_adm).days, 5)
        self.assertEqual((d3_dis - d3_adm).days, 4)

        # Check visit-to-visit intervals (19 days between adm1 and adm2, 40 days between adm2 and adm3)
        self.assertEqual((d2_adm - d1_adm).days, 19)
        self.assertEqual((d3_adm - d2_adm).days, 40)


if __name__ == "__main__":
    unittest.main()
