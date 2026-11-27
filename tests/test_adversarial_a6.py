"""Adversarial A6 tests: cryptographic pseudonym inversion, domain separation, and secret hygiene."""
import hashlib
import hmac
import json
import os
import tempfile
import unittest
from pathlib import Path

from rakshak.cli import run_pipeline
from rakshak.privacy.pseudonymize import generate_pseudonym, pseudonym_is_valid


class TestAdversarialA6(unittest.TestCase):
    """A6: Keyed HMAC pseudonym inversion resistance and secret-leakage prevention."""

    def test_known_and_chosen_identifier_cannot_invert_without_secret(self):
        """A6.1/2: Knowing the algorithm and patient key does not reveal PSN without RAKSHA_SECRET."""
        target = generate_pseudonym("aadhaar:123456789012", b"prod-secret-xyz")
        self.assertTrue(pseudonym_is_valid(target))
        for guess in (b"", b"practice", b"secret", b"123456", b"admin", b"raksha"):
            self.assertNotEqual(generate_pseudonym("aadhaar:123456789012", guess), target)

    def test_dictionary_attack_over_candidate_identifiers(self):
        """A6.3: Candidate phone/name dictionary with wrong key produces 0 collisions."""
        secret = b"real-key-991"
        target = generate_pseudonym("phone:9876543210", secret)
        for i in range(100):
            cand = f"phone:9876543{i:03d}"
            self.assertNotEqual(generate_pseudonym(cand, b"attacker-key"), target)

    def test_cross_domain_separation_psn_shift_fname(self):
        """A6.6: psn|, shift|, and fname| domains produce distinct HMAC digests."""
        sec = b"domain-key"
        key = "phone:9988776655"
        d_psn = hmac.new(sec, b"psn|" + key.encode(), hashlib.sha256).digest()
        d_shift = hmac.new(sec, b"shift|" + key.encode(), hashlib.sha256).digest()
        d_fname = hmac.new(sec, b"fname|" + key.encode(), hashlib.sha256).digest()
        self.assertEqual(len({d_psn, d_shift, d_fname}), 3)

    def test_secret_never_exposed_in_outputs_or_metadata(self):
        """A6.4/7: Secret string must never appear in sanitized/, report.json, or records.jsonl."""
        with tempfile.TemporaryDirectory() as tmp:
            inp, out = Path(tmp) / "in", Path(tmp) / "out"
            inp.mkdir()
            (inp / "note.txt").write_text("Patient Name: Asha Devi\nMobile: 9876543210\n", encoding="utf-8")
            secret = "super-secret-token-42"
            old = os.environ.get("RAKSHA_SECRET")
            try:
                os.environ["RAKSHA_SECRET"] = secret
                run_pipeline(inp, out)
            finally:
                if old is None:
                    os.environ.pop("RAKSHA_SECRET", None)
                else:
                    os.environ["RAKSHA_SECRET"] = old

            for p in out.rglob("*"):
                if p.is_file():
                    self.assertNotIn(secret, p.read_text(encoding="utf-8", errors="replace"))


if __name__ == "__main__":
    unittest.main()
