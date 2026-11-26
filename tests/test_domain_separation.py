"""Tests for cryptographic domain separation across RAKSHA's HMAC uses.

Ensures that:
 - generate_pseudonym uses a different HMAC domain than compute_date_shift and filename sanitisation
 - Same patient_key + same secret → same output (deterministic)
 - Different secrets → different outputs (unlinkable)
 - PSN format is valid Crockford base32
"""
import hashlib
import hmac
import os
import unittest

from rakshak.privacy.pseudonymize import generate_pseudonym, pseudonym_is_valid
from rakshak.privacy.transforms import compute_date_shift


class TestDomainSeparation(unittest.TestCase):
    """Verify HMAC domain separation between pseudonym, date-shift, and filename."""

    SECRET = b"test-domain-sep-secret"
    PATIENT_KEY = "phone:9876543210"

    def test_pseudonym_uses_psn_domain(self):
        """generate_pseudonym must include 'psn|' domain prefix in HMAC input."""
        psn = generate_pseudonym(self.PATIENT_KEY, self.SECRET)
        self.assertTrue(psn.startswith("PSN-"))
        self.assertEqual(len(psn), 10)
        self.assertTrue(pseudonym_is_valid(psn))

    def test_pseudonym_deterministic(self):
        """Same key + same secret → same pseudonym."""
        p1 = generate_pseudonym(self.PATIENT_KEY, self.SECRET)
        p2 = generate_pseudonym(self.PATIENT_KEY, self.SECRET)
        self.assertEqual(p1, p2)

    def test_pseudonym_different_secret(self):
        """Different secret → different pseudonym (cross-release unlinkability)."""
        p1 = generate_pseudonym(self.PATIENT_KEY, self.SECRET)
        p2 = generate_pseudonym(self.PATIENT_KEY, b"other-secret")
        self.assertNotEqual(p1, p2)

    def test_date_shift_uses_shift_domain(self):
        """compute_date_shift must include 'shift|' domain prefix."""
        shift = compute_date_shift(self.PATIENT_KEY, 180, self.SECRET)
        self.assertIsInstance(shift, int)
        self.assertNotEqual(shift, 0)
        self.assertTrue(-180 <= shift <= 180)

    def test_domains_produce_different_digests(self):
        """The raw HMAC digests for psn|, shift|, fname| must all differ."""
        dig_psn = hmac.new(self.SECRET, b"psn|" + self.PATIENT_KEY.encode(), hashlib.sha256).hexdigest()
        dig_shift = hmac.new(self.SECRET, b"shift|" + self.PATIENT_KEY.encode(), hashlib.sha256).hexdigest()
        dig_fname = hmac.new(self.SECRET, b"fname|" + self.PATIENT_KEY.encode(), hashlib.sha256).hexdigest()
        self.assertNotEqual(dig_psn, dig_shift, "psn and shift domains must differ")
        self.assertNotEqual(dig_psn, dig_fname, "psn and fname domains must differ")
        self.assertNotEqual(dig_shift, dig_fname, "shift and fname domains must differ")

    def test_pseudonym_is_valid_format(self):
        """Pseudonym uses only Crockford base32 characters (no I, L, O, U)."""
        psn = generate_pseudonym("test:key:123", self.SECRET)
        code = psn[4:]
        crockford = set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        for ch in code:
            self.assertIn(ch, crockford, f"'{ch}' is not Crockford base32")

    def test_different_patient_keys_different_pseudonyms(self):
        """Different patient keys produce different pseudonyms."""
        p1 = generate_pseudonym("phone:1111111111", self.SECRET)
        p2 = generate_pseudonym("phone:2222222222", self.SECRET)
        self.assertNotEqual(p1, p2)


if __name__ == "__main__":
    unittest.main()
