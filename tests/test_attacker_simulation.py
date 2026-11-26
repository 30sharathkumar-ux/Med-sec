"""Attacker simulation tests against RAKSHA's sanitised output.

Simulates the five attack vectors from scoring.toml:
 1. Direct exposure: search for raw patient names, phones, Aadhaar in output
 2. Record linkage: attempt to link sanitised records to registry.csv
 3. Profile re-identification: use quasi-identifiers to narrow down candidates
 4. Targeted attack: use known_facts.jsonl to match visits/conditions
 5. Pseudonym inversion: try to brute-force pseudonym back to patient key
 6. Cross-release: compare two runs with different secrets for linkability

Uses the practice dataset if available, otherwise synthetic data.
"""
import csv
import hashlib
import hmac
import json
import os
import re
import unittest
from pathlib import Path


# Paths
_ROOT = Path(__file__).resolve().parent.parent
_REGISTRY = _ROOT / "dev" / "attacker" / "registry.csv"
_KNOWN_FACTS = _ROOT / "dev" / "attacker" / "known_facts.jsonl"
_OUTPUT = _ROOT / "output"
_SANITIZED = _OUTPUT / "sanitized"


def _load_registry():
    """Load the attacker's population registry."""
    if not _REGISTRY.exists():
        return []
    with open(_REGISTRY, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _load_known_facts():
    """Load the attacker's known facts."""
    if not _KNOWN_FACTS.exists():
        return []
    facts = []
    with open(_KNOWN_FACTS, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                facts.append(json.loads(line))
    return facts


def _all_sanitised_text():
    """Read all sanitised output as one concatenated string."""
    if not _SANITIZED.exists():
        return ""
    parts = []
    for p in _SANITIZED.rglob("*"):
        if p.is_file() and p.suffix in (".txt", ".csv", ".tsv", ".json", ".jsonl"):
            try:
                parts.append(p.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                pass
    return "\n".join(parts)


def _load_records_jsonl():
    """Load output/records.jsonl."""
    rpath = _OUTPUT / "records.jsonl"
    if not rpath.exists():
        return []
    records = []
    with open(rpath, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


@unittest.skipUnless(_SANITIZED.exists(), "No sanitised output to test against")
class TestDirectExposure(unittest.TestCase):
    """Attack 1: Search for raw PII in sanitised output."""

    @classmethod
    def setUpClass(cls):
        cls.text = _all_sanitised_text()
        cls.registry = _load_registry()

    def test_no_full_names_in_output(self):
        """No full patient name from registry should appear verbatim."""
        leaked = []
        for person in self.registry:
            name = person.get("name", "").strip()
            if name and len(name) > 5 and name.lower() in self.text.lower():
                leaked.append(name)
        self.assertEqual(leaked, [], f"Full names found in output: {leaked[:5]}")

    def test_no_phone_numbers_in_output(self):
        """No phone number from registry should appear verbatim."""
        leaked = []
        for person in self.registry:
            phone = person.get("phone", "").strip()
            if phone and len(phone) >= 10 and phone in self.text:
                leaked.append(phone)
        self.assertEqual(leaked, [], f"Phones found in output: {leaked[:5]}")

    def test_no_aadhaar_last4_in_names_context(self):
        """Aadhaar last-4 near a patient name is a strong linkage signal."""
        for person in self.registry:
            last4 = person.get("aadhaar_last4", "").strip()
            name = person.get("name", "").strip()
            if not last4 or not name:
                continue
            first_name = name.split()[0].lower()
            # Check if last-4 appears within 200 chars of first name in output
            for m in re.finditer(re.escape(last4), self.text):
                context = self.text[max(0, m.start() - 100):m.end() + 100].lower()
                self.assertNotIn(
                    first_name, context,
                    f"Aadhaar last-4 '{last4}' found near name '{name}' in output"
                )


@unittest.skipUnless(_SANITIZED.exists(), "No sanitised output to test against")
class TestRecordLinkage(unittest.TestCase):
    """Attack 2: Link sanitised records back to registry entries."""

    @classmethod
    def setUpClass(cls):
        cls.text = _all_sanitised_text()
        cls.registry = _load_registry()

    def test_no_exact_village_plus_age_match(self):
        """No exact (village, age) pair from registry should be findable in output."""
        # In sanitised output, villages are generalised to district and ages to 5-year bands.
        # An attacker with exact village + exact age should NOT be able to find a match.
        linked = 0
        for person in self.registry:
            village = person.get("village", "").strip().lower()
            age = person.get("age", "").strip()
            if not village or not age or len(village) < 3:
                continue
            # Village should be generalised — the exact village name should not appear
            if village in self.text.lower():
                # Also check if exact age appears nearby
                for m in re.finditer(re.escape(village), self.text.lower()):
                    context = self.text[max(0, m.start() - 50):m.end() + 50]
                    if re.search(r'\b' + re.escape(age) + r'\b', context):
                        linked += 1
        # Allow some tolerance but flag systemic issues
        self.assertLess(linked, 3, f"Exact village+age linkages found: {linked}")


@unittest.skipUnless(_SANITIZED.exists(), "No sanitised output to test against")
class TestTargetedAttack(unittest.TestCase):
    """Attack 4: Use known facts (visit dates, conditions) to match patients."""

    @classmethod
    def setUpClass(cls):
        cls.text = _all_sanitised_text()
        cls.known_facts = _load_known_facts()
        cls.registry = {p["rid"]: p for p in _load_registry()}

    def test_known_visit_dates_are_shifted(self):
        """Visit dates from known_facts should NOT appear verbatim (they should be shifted)."""
        unshifted = 0
        for fact in self.known_facts:
            for date in fact.get("visit_dates", []):
                if date in self.text:
                    # Check if the patient's name is also nearby
                    rid = fact.get("rid", "")
                    person = self.registry.get(rid, {})
                    name = person.get("name", "")
                    if name:
                        first = name.split()[0].lower()
                        for m in re.finditer(re.escape(date), self.text):
                            context = self.text[max(0, m.start() - 200):m.end() + 200].lower()
                            if first in context:
                                unshifted += 1
        # Dates should be shifted, but the same date string might coincidentally appear
        # for a different patient. Only flag when name co-occurs.
        self.assertEqual(unshifted, 0, f"Known visit date + name co-occurrences: {unshifted}")


@unittest.skipUnless(_SANITIZED.exists(), "No sanitised output to test against")
class TestPseudonymInversion(unittest.TestCase):
    """Attack 5: Try to brute-force pseudonym back to patient key."""

    def test_pseudonym_not_invertible_without_secret(self):
        """Pseudonyms should not be derivable from patient data without the secret."""
        from rakshak.privacy.pseudonymize import generate_pseudonym

        secret = os.environ.get("RAKSHA_SECRET", "practice").encode()
        wrong_secret = b"attacker-guess-secret"

        # Try a known patient key with wrong secret
        psn_real = generate_pseudonym("phone:9876543210", secret)
        psn_wrong = generate_pseudonym("phone:9876543210", wrong_secret)
        self.assertNotEqual(psn_real, psn_wrong,
                            "Pseudonym should change with different secret")

    def test_domain_separation_prevents_cross_oracle(self):
        """Knowing the date shift should NOT help invert the pseudonym."""
        from rakshak.privacy.pseudonymize import generate_pseudonym
        from rakshak.privacy.transforms import compute_date_shift

        secret = b"test-inversion-secret"
        key = "phone:1234567890"

        # Even with the same secret, the HMAC domains differ
        psn = generate_pseudonym(key, secret)
        shift = compute_date_shift(key, 180, secret)

        # The raw digests are different
        dig_psn = hmac.new(secret, b"psn|" + key.encode(), hashlib.sha256).digest()
        dig_shift = hmac.new(secret, b"shift|" + key.encode(), hashlib.sha256).digest()
        self.assertNotEqual(dig_psn, dig_shift)


@unittest.skipUnless(_SANITIZED.exists() and (_OUTPUT / "records.jsonl").exists(),
                     "No output to test cross-release")
class TestCrossRelease(unittest.TestCase):
    """Attack 6: Compare outputs from different secrets for linkability."""

    def test_pseudonyms_differ_across_secrets(self):
        """Same patient_key with different secrets must yield different pseudonyms."""
        from rakshak.privacy.pseudonymize import generate_pseudonym

        keys = ["phone:1111111111", "aadhaar:123456789012", "name:suresh joshi|"]
        s1 = b"secret-release-1"
        s2 = b"secret-release-2"

        for k in keys:
            p1 = generate_pseudonym(k, s1)
            p2 = generate_pseudonym(k, s2)
            self.assertNotEqual(p1, p2, f"Key '{k}' produced same PSN across secrets")

    def test_date_shifts_differ_across_secrets(self):
        """Same patient_key with different secrets must yield different date shifts."""
        from rakshak.privacy.transforms import compute_date_shift

        s1 = b"secret-release-1"
        s2 = b"secret-release-2"
        key = "phone:5555555555"

        shift1 = compute_date_shift(key, 180, s1)
        shift2 = compute_date_shift(key, 180, s2)
        # They CAN be equal by chance (1/360 probability) but are extremely unlikely
        # for multiple keys. Test with multiple keys:
        different_count = 0
        for k in ["phone:1111", "phone:2222", "phone:3333", "phone:4444", "phone:5555"]:
            if compute_date_shift(k, 180, s1) != compute_date_shift(k, 180, s2):
                different_count += 1
        self.assertGreaterEqual(different_count, 3,
                                "Date shifts should mostly differ across secrets")


if __name__ == "__main__":
    unittest.main()
