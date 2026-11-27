"""Clinical utility regression tests: diagnoses, drugs, doses, labs, LOS, and FHIR R4."""
import csv
import json
import os
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from rakshak.cli import _clean_text_full, run_pipeline
from rakshak.privacy.fhir_validator import validate_fhir_output


class TestClinicalUtility(unittest.TestCase):
    """Verify clinical facts, medications, labs, LOS, and FHIR structure survive privacy transforms."""

    def test_clinical_probes_preserved_in_free_text(self):
        """Diagnoses, medications, dosages, frequencies, labs, and doctor credentials survive."""
        note = (
            "Patient Name: Suresh Kumar\n"
            "Age/Sex: 54 Yrs/M\n"
            "Consultant: Dr. Anil Kumar MD Cardiology\n"
            "Diagnosis: Parkinson's disease (G20); Essential hypertension (I10)\n"
            "Course: BP 138/86 mmHg, Haemoglobin 11.4 g/dL, HbA1c 7.2 %\n"
            "Rx:\n"
            " 1. Tab Ramipril 5mg 1-0-1 x 30 days\n"
            " 2. Tab Dolo 650 BD x 5 days\n"
        )
        out = _clean_text_full(note, Counter(), age_band_width=5)
        for probe in (
            "Dr. Anil Kumar MD Cardiology",
            "Parkinson's disease (G20)",
            "Essential hypertension (I10)",
            "BP 138/86 mmHg",
            "Haemoglobin 11.4 g/dL",
            "Ramipril 5mg 1-0-1 x 30 days",
            "Dolo 650 BD x 5 days",
            "50-54 Yrs/M",
        ):
            self.assertIn(probe, out)
        self.assertNotIn("Suresh Kumar", out)

    def test_fhir_bundle_structure_and_clinical_codes_preserved(self):
        """FHIR R4 Bundle remains structurally valid with LOINC/ICD codes intact after sanitization."""
        with tempfile.TemporaryDirectory() as tmp:
            inp, out = Path(tmp) / "in", Path(tmp) / "out"
            inp.mkdir()
            bundle = {
                "resourceType": "Bundle",
                "type": "collection",
                "entry": [
                    {"resource": {"resourceType": "Patient", "name": [{"text": "Kavita Devi"}], "gender": "female", "birthDate": "1980-05-12"}},
                    {"resource": {"resourceType": "Condition", "code": {"coding": [{"system": "http://hl7.org/fhir/sid/icd-10", "code": "E11.9", "display": "Type 2 diabetes"}]}}},
                    {"resource": {"resourceType": "Observation", "code": {"coding": [{"system": "http://loinc.org", "code": "718-7", "display": "Haemoglobin"}]}, "valueQuantity": {"value": 10.8, "unit": "g/dL"}}},
                ],
            }
            (inp / "bundle.json").write_text(json.dumps(bundle), encoding="utf-8")
            os.environ["RAKSHA_SECRET"] = "fhir-util-secret"
            run_pipeline(inp, out)

            san_bundle = json.loads((out / "sanitized" / "bundle.json").read_text(encoding="utf-8"))
            self.assertTrue(validate_fhir_output(san_bundle))
            raw_str = json.dumps(san_bundle)
            self.assertNotIn("Kavita Devi", raw_str)
            self.assertIn("E11.9", raw_str)
            self.assertIn("718-7", raw_str)
            self.assertIn("10.8", raw_str)


if __name__ == "__main__":
    unittest.main()
