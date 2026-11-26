"""Tests for k-anonymity enforcement module."""
import unittest

from rakshak.privacy.k_anonymity import (
    compute_equivalence_classes,
    compute_k_anonymity_metrics,
    identify_at_risk_records,
    suppress_pin,
    widen_age_band,
)


class TestKAnonymity(unittest.TestCase):
    """Verify k-anonymity computation and enforcement."""

    def _make_records(self):
        """Generate synthetic records with known equivalence classes."""
        # Group A: 6 records with same QI → safe at k=5
        group_a = [
            {"age": "45-49", "gender": "M", "village": "bahadurpur", "district": "sultanpur", "pin": "228***"}
            for _ in range(6)
        ]
        # Group B: 3 records with same QI → at-risk at k=5
        group_b = [
            {"age": "20-24", "gender": "F", "village": "jalalpur", "district": "sultanpur", "pin": "228***"}
            for _ in range(3)
        ]
        # Group C: 1 unique record → at-risk at k=5
        group_c = [
            {"age": "90-94", "gender": "M", "village": "mustafamau", "district": "hardoi", "pin": "241***"}
        ]
        return group_a + group_b + group_c

    def test_equivalence_classes_count(self):
        """Should identify 3 distinct QI groups."""
        records = self._make_records()
        classes = compute_equivalence_classes(records)
        self.assertEqual(len(classes), 3)

    def test_k_achieved(self):
        """Minimum equivalence class size should be 1 (the unique record)."""
        records = self._make_records()
        metrics = compute_k_anonymity_metrics(records, min_group_size=5)
        self.assertEqual(metrics["k_achieved"], 1)
        self.assertTrue(metrics["suppression_needed"])

    def test_at_risk_records(self):
        """Group B (3) + Group C (1) = 4 at-risk records."""
        records = self._make_records()
        at_risk = identify_at_risk_records(records, min_group_size=5)
        self.assertEqual(len(at_risk), 4)
        # Group A indices 0-5 should NOT be at risk
        for i in range(6):
            self.assertNotIn(i, at_risk)
        # Group B indices 6-8 and Group C index 9 should be at risk
        for i in range(6, 10):
            self.assertIn(i, at_risk)

    def test_no_risk_all_safe(self):
        """When all classes >= k, no records at risk."""
        records = [
            {"age": "30-34", "gender": "M", "village": "v1", "district": "d1", "pin": "123***"}
            for _ in range(10)
        ]
        at_risk = identify_at_risk_records(records, min_group_size=5)
        self.assertEqual(len(at_risk), 0)
        metrics = compute_k_anonymity_metrics(records, min_group_size=5)
        self.assertFalse(metrics["suppression_needed"])
        self.assertEqual(metrics["k_achieved"], 10)

    def test_empty_records(self):
        """Empty dataset should not error."""
        metrics = compute_k_anonymity_metrics([], min_group_size=5)
        self.assertEqual(metrics["total_records"], 0)
        self.assertFalse(metrics["suppression_needed"])

    def test_widen_age_band(self):
        """5-year bands should widen to 10-year bands."""
        self.assertEqual(widen_age_band("45-49"), "40-49")
        self.assertEqual(widen_age_band("40-44"), "40-49")
        self.assertEqual(widen_age_band("0-4"), "0-9")
        self.assertEqual(widen_age_band("95-99"), "90-99")
        # Non-band strings pass through
        self.assertEqual(widen_age_band("unknown"), "unknown")

    def test_suppress_pin(self):
        """PIN suppression should mask further."""
        self.assertEqual(suppress_pin("229***"), "22****")
        self.assertEqual(suppress_pin("123456"), "12****")

    def test_qi_extraction_case_insensitive(self):
        """QI keys should be matched case-insensitively."""
        records = [
            {"Age": "30-34", "Gender": "Male", "Village": "V1", "District": "D1", "PIN": "123***"},
            {"age": "30-34", "gender": "Male", "village": "v1", "district": "d1", "pin": "123***"},
        ]
        classes = compute_equivalence_classes(records)
        # Both should map to the same QI group (gender normalised to first char upper)
        self.assertEqual(len(classes), 1)


if __name__ == "__main__":
    unittest.main()
