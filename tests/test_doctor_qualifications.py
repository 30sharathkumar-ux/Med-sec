"""Regression tests for doctor qualification preservation vs genuine Md./MD PII."""
import unittest
from collections import Counter

from rakshak.cli import _clean_text_full


class TestDoctorQualificationPreservation(unittest.TestCase):
    """Ensure medical qualifications on doctors are preserved while Md. patient names are redacted."""

    def test_1_doctor_parenthetical_md_medicine_preserved(self):
        """1. 'Dr. Ramesh Srivastava (MD Medicine)' must remain intact even when patient is Mohammad Shahid."""
        text = (
            "Patient Name: Mohammad Shahid\n"
            "Consultant: Dr. Ramesh Srivastava (MD Medicine)\n"
            "Shahid sahab ki condition ab stable hai.\n"
        )
        out = _clean_text_full(text, Counter())
        self.assertIn("Consultant: Dr. Ramesh Srivastava (MD Medicine)", out)
        self.assertNotIn("Mohammad", out)
        self.assertNotIn("Shahid", out)

    def test_2_doctor_no_punctuation_md_cardiology_preserved(self):
        """2. 'Dr. Anil Kumar MD Cardiology' without punctuation must preserve qualification."""
        text = (
            "Patient Name: Md. Irfan\n"
            "Consultant: Dr. Anil Kumar MD Cardiology\n"
        )
        out = _clean_text_full(text, Counter())
        self.assertIn("Dr. Anil Kumar MD Cardiology", out)
        self.assertNotIn("Irfan", out)

    def test_3_doctor_comma_md_cardiology_preserved(self):
        """3. 'Dr. Anil Kumar, MD, Cardiology' must preserve doctor name and qualification."""
        text = (
            "Patient Name: Mohammad Irfan\n"
            "Reviewed by Dr. Anil Kumar, MD, Cardiology.\n"
        )
        out = _clean_text_full(text, Counter())
        self.assertIn("Dr. Anil Kumar, MD, Cardiology", out)
        self.assertNotIn("Irfan", out)

    def test_4_genuine_patient_md_name_still_detected(self):
        """4. Genuine patient/relative occurrences of 'Md.' must still be redacted."""
        text = (
            "Patient Name: Md. Shahid\n"
            "S/o Md. Zubair\n"
            "Follow-up: Md. Shahid advised rest.\n"
        )
        out = _clean_text_full(text, Counter())
        self.assertNotIn("Md. Shahid", out)
        self.assertNotIn("Zubair", out)
        self.assertIn("[PATIENT_NAME]", out)
        self.assertIn("[RELATIVE_NAME]", out)

    def test_5_doctor_vs_patient_named_ramesh(self):
        """5. Doctor Ramesh stays intact while patient named Ramesh is redacted."""
        text = (
            "Patient Name: Ramesh Kumar\n"
            "Dr. Ramesh Srivastava examined Ramesh Kumar.\n"
        )
        out = _clean_text_full(text, Counter())
        self.assertIn("Dr. Ramesh Srivastava", out)
        self.assertNotIn("Patient Name: Ramesh Kumar", out)
        self.assertIn("examined [PATIENT_NAME]", out)

    def test_6_doctor_vs_relative_named_ramesh(self):
        """6. Doctor Ramesh stays intact while relative named Ramesh is redacted."""
        text = (
            "Patient Name: Kavita Devi\n"
            "W/o Ramesh Patel\n"
            "Dr. Ramesh Srivastava advised follow-up with Ramesh Patel.\n"
        )
        out = _clean_text_full(text, Counter())
        self.assertIn("Dr. Ramesh Srivastava", out)
        self.assertNotIn("Ramesh Patel", out)
        self.assertIn("[RELATIVE_NAME]", out)

    def test_7_co_context_traps(self):
        """7. C/O complaint ('C/O fever') preserved while 'C/O Ramesh' relative is redacted."""
        text = (
            "Patient Name: Sunita Verma\n"
            "C/O Ramesh Verma\n"
            "Presenting complaints: C/O fever for 3 days, generalised weakness.\n"
        )
        out = _clean_text_full(text, Counter())
        self.assertIn("C/O fever for 3 days", out)
        self.assertNotIn("Ramesh Verma", out)

    def test_8_mixed_english_hindi_hinglish_contexts(self):
        """8. Mixed English/Hindi/Hinglish preserves Dr. qualification and redacts patient/relative."""
        text = (
            "मरीज का नाम: मोहम्मद शाहिद\n"
            "Consultant: Dr. Anil Kumar MD Cardiology\n"
            "डॉ. रमेश श्रीवास्तव ने बताया कि Shahid ki tabiyat ab theek hai.\n"
        )
        out = _clean_text_full(text, Counter())
        self.assertIn("Dr. Anil Kumar MD Cardiology", out)
        self.assertIn("डॉ. रमेश श्रीवास्तव", out)
        self.assertNotIn("मोहम्मद शाहिद", out)
        self.assertNotIn("Shahid", out)


if __name__ == "__main__":
    unittest.main()
