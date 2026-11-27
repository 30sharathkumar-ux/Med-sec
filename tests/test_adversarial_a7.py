"""Adversarial A7 tests: cross-release unlinkability across 3 releases (A, B, C)."""
import csv
import json
import os
import tempfile
import unittest
from pathlib import Path

from rakshak.cli import run_pipeline


class TestAdversarialA7(unittest.TestCase):
    """A7: Cross-release unlinkability across different secrets and determinism within same secret."""

    def _run_release(self, inp: Path, out: Path, secret: str):
        old = os.environ.get("RAKSHA_SECRET")
        try:
            os.environ["RAKSHA_SECRET"] = secret
            run_pipeline(inp, out)
        finally:
            if old is None:
                os.environ.pop("RAKSHA_SECRET", None)
            else:
                os.environ["RAKSHA_SECRET"] = old

    def test_three_releases_a_b_c_pseudonym_and_filename_unlinkability(self):
        """A7: Release A (key A) vs B (key B) have 0 pseudonym/filename overlap; A vs C (key A) match 100%."""
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "in"
            inp.mkdir()
            rows = [
                ["uhid", "patient_name", "phone", "age", "gender", "district", "admission_date", "discharge_date"],
                ["H1", "Ramesh Patel", "9876543210", "45", "M", "lucknow", "2026-04-01", "2026-04-05"],
                ["H2", "Sunita Devi", "9876543211", "52", "F", "sitapur", "2026-04-10", "2026-04-14"],
                ["H3", "Mohan Lal", "9876543212", "61", "M", "hardoi", "2026-05-01", "2026-05-06"],
            ]
            with open(inp / "Ramesh_Patel_visits.csv", "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerows(rows)

            out_a, out_b, out_c = Path(tmp) / "a", Path(tmp) / "b", Path(tmp) / "c"
            self._run_release(inp, out_a, "release-key-alpha")
            self._run_release(inp, out_b, "release-key-beta")
            self._run_release(inp, out_c, "release-key-alpha")

            def _psns(d: Path):
                return [json.loads(l)["patient"] for l in (d / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]

            psn_a, psn_b, psn_c = _psns(out_a), _psns(out_b), _psns(out_c)
            self.assertEqual(set(psn_a) & set(psn_b), set(), "Different secrets must yield disjoint pseudonyms")
            self.assertEqual(psn_a, psn_c, "Same secret must yield identical pseudonyms")

            # Filenames renamed due to PII must also differ across A and B, and match across A and C
            fn_a = sorted(p.name for p in (out_a / "sanitized").iterdir())
            fn_b = sorted(p.name for p in (out_b / "sanitized").iterdir())
            fn_c = sorted(p.name for p in (out_c / "sanitized").iterdir())
            self.assertNotEqual(fn_a, fn_b)
            self.assertEqual(fn_a, fn_c)

            # Shifted dates must differ across A and B
            csv_a = next((out_a / "sanitized").glob("*.csv")).read_text(encoding="utf-8")
            csv_b = next((out_b / "sanitized").glob("*.csv")).read_text(encoding="utf-8")
            csv_c = next((out_c / "sanitized").glob("*.csv")).read_text(encoding="utf-8")
            self.assertNotEqual(csv_a, csv_b)
            self.assertEqual(csv_a, csv_c)


if __name__ == "__main__":
    unittest.main()
