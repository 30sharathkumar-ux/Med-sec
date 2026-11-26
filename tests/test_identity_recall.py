"""Regression tests for identity resolution recall improvements."""
import unittest

from rakshak.linkage.resolver import (
    IdentityResolver,
    RecordEvidence,
    extract_evidence_csv,
    extract_evidence_text,
    extract_issuer_prefix,
)


class TestIdentityRecallImprovements(unittest.TestCase):
    """Verify recall fixes without introducing false merges."""

    def test_registration_date_not_extracted_as_mrn(self):
        """'Registration Date' column must not be treated as an MRN."""
        header = ["Reg No", "Naam", "Registration Date"]
        row = ["JJH-0076928", "Rina Nishad", "30-08-2026"]
        ev = extract_evidence_csv(header, row, "sanitized/reg.tsv", 0, "jeevanjyoti")
        self.assertEqual(ev.mrns, ["JJH-0076928"])
        self.assertNotIn("30-08-2026", ev.mrns)

    def test_age_sex_column_parsed(self):
        """'age_sex' column like '65/F' should populate both age and gender."""
        header = ["patient_name", "age_sex", "uhid"]
        row = ["Rina Nishad", "65/F", "JJH-0076928"]
        ev = extract_evidence_csv(header, row, "sanitized/lab.csv", 0, "")
        self.assertEqual(ev.age, 65)
        self.assertEqual(ev.gender, "F")

    def test_mrn_cross_lab_and_phonetic_variants_merge(self):
        """Records sharing a hospital-prefixed MRN across different lab files and
        spelling/transliteration variants must merge into one cluster."""
        r = IdentityResolver()
        ev1 = extract_evidence_csv(
            ["Reg No", "Naam"], ["JJH-0076928", "Rina Nishad"],
            "sanitized/registration/jeevanjyoti_patients.tsv", 0, "jeevanjyoti",
        )
        ev2 = extract_evidence_csv(
            ["patient_name", "uhid"], ["Reena Nishad", "JJH-0076928"],
            "sanitized/lab/sanjeevani_results.csv", 0, "sanjeevani",
        )
        ev3 = RecordEvidence(
            record_id="sanitized/discharge/ds.txt::doc",
            file_path="sanitized/discharge/ds.txt",
            loc="doc",
            hospital="jeevanjyoti",
            mrns=["JJH-0076928"],
            patient_name="रीना निषाद",
            patient_name_normalized="riinaa nishaada",
            patient_name_phonetic="rn nsd",
        )
        r.add_record(ev1)
        r.add_record(ev2)
        r.add_record(ev3)
        clusters = r.resolve()
        self.assertEqual(len(set(clusters.values())), 1)

    def test_note_name_before_relation_extracted(self):
        """Clinical note '<Name>, W/o <Relative>' without 'Patient:' label must extract name."""
        text = "Discharge note\n\nZainab, W/o Salim, discharged in stable condition.\n"
        ev = extract_evidence_text(text, "sanitized/discharge/note_0015.txt")
        self.assertEqual(ev.patient_name, "Zainab")
        self.assertEqual(ev.relative_name_normalized, "salim")

    def test_dynamic_issuer_prefix_generalizes_to_unseen_hospitals(self):
        """Dynamic issuer-prefix extractor handles arbitrary unseen hospital prefixes."""
        self.assertEqual(extract_issuer_prefix("KGMU-2026-001"), "KGMU")
        self.assertEqual(extract_issuer_prefix("APO/26/00912"), "APO")
        self.assertEqual(extract_issuer_prefix("MED-99881"), "MED")
        self.assertIsNone(extract_issuer_prefix("UHID-12345"))
        self.assertIsNone(extract_issuer_prefix("IPD-2026-00454"))

        # Cross-lab merge with unseen hospital prefix KGMU-
        r = IdentityResolver()
        ev1 = extract_evidence_csv(
            ["uhid", "patient_name"], ["KGMU-00421", "Kavita Verma"],
            "sanitized/reg/kgmu_reg.csv", 0, "kgmu",
        )
        ev2 = extract_evidence_csv(
            ["uhid", "patient_name"], ["KGMU-00421", "Kavita Verma"],
            "sanitized/lab/external_lab.csv", 0, "external_lab",
        )
        r.add_record(ev1)
        r.add_record(ev2)
        clusters = r.resolve()
        self.assertEqual(len(set(clusters.values())), 1)


if __name__ == "__main__":
    unittest.main()
