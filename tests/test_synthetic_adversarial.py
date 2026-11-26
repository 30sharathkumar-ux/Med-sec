"""Phase 6 synthetic adversarial validation tests (unseen data, not in dev/input).

Tests:
- Unseen patient names, cross-script Devanagari/Latin transliterations
- Unusual MRN / phone / DOB formats & missing identifiers
- Cross-hospital identity resolution without false merges
- Rare diagnoses & unusual stay durations preservation
- Cross-release unlinkability under secret rotation
- Malformed / oversized / path-traversal inputs
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from rakshak.cli import run_pipeline
from rakshak.linkage.resolver import IdentityResolver, extract_evidence_text


class SyntheticAdversarialTests(unittest.TestCase):
    def _run(self, files: dict[str, bytes | str], secret: str) -> tuple[Path, dict, list[dict]]:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        inp = root / "in"
        out = root / "out"
        inp.mkdir()
        for rel, content in files.items():
            p = inp / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                p.write_bytes(content)
            else:
                p.write_text(content, encoding="utf-8")

        old = os.environ.get("RAKSHA_SECRET")
        os.environ["RAKSHA_SECRET"] = secret
        try:
            rc = run_pipeline(inp, out)
        finally:
            if old is None:
                os.environ.pop("RAKSHA_SECRET", None)
            else:
                os.environ["RAKSHA_SECRET"] = old

        self.assertEqual(rc, 0)
        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        records = [
            json.loads(line)
            for line in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        return out, report, records

    def test_cross_script_and_cross_hospital_unseen_patient(self) -> None:
        files = {
            "hosp_a/reg.csv": (
                "patient_name,phone,uhid,village,age\n"
                "Zorawar Qureshi,+91 98111 22334,HOSP-A-9901,Rampur Kalan,52\n"
            ),
            "hosp_b/rx_note.txt": (
                "नाम: ज़ोरावर क़ुरैशी   आयु: 52 वर्ष\n"
                "ग्राम: रामपुर कलां\n"
                "Diagnosis: Takayasu arteritis. Stay duration: 47 days.\n"
                "Rx: Tab Prednisolone 40 mg OD\n"
            ),
        }
        out, report, records = self._run(files, "synth-secret-1")
        self.assertEqual(report["counts"]["files_sanitized"], 2)

        # Both records should link to the same pseudonym
        patients = {r["patient"] for r in records if r.get("patient")}
        self.assertEqual(len(patients), 1, f"Expected 1 linked pseudonym, got {patients}")

        # Raw PII must not leak; rare diagnosis & unusual stay duration must survive
        all_sanitized = "\n".join(
            p.read_text(encoding="utf-8") for p in (out / "sanitized").rglob("*") if p.is_file()
        )
        self.assertNotIn("Zorawar", all_sanitized)
        self.assertNotIn("ज़ोरावर", all_sanitized)
        self.assertNotIn("98111", all_sanitized)
        self.assertIn("Takayasu arteritis", all_sanitized)
        self.assertIn("47 days", all_sanitized)

    def test_cross_release_unlinkability_on_secret_rotation(self) -> None:
        files = {
            "note.txt": (
                "Patient Name: Devendra Chauhan\n"
                "UHID: SNJ/26/998877\n"
                "DOB: 14-03-1980\n"
                "Phone: 9876501234\n"
                "Diagnosis: Guillain-Barre syndrome\n"
            )
        }
        _, _, rec_a = self._run(files, "release-secret-alpha")
        _, _, rec_b = self._run(files, "release-secret-beta")
        psn_a = {r["patient"] for r in rec_a if r.get("patient")}
        psn_b = {r["patient"] for r in rec_b if r.get("patient")}
        self.assertTrue(psn_a and psn_b)
        self.assertNotEqual(psn_a, psn_b)

    def test_homonym_different_dob_never_merged(self) -> None:
        ev1 = extract_evidence_text(
            "Patient Name: Meena Kumari\nDOB: 01/01/1975\nVillage: Chandpur\n",
            "sanitized/a.txt",
        )
        ev2 = extract_evidence_text(
            "Patient Name: Meena Kumari\nDOB: 12/09/1992\nVillage: Chandpur\n",
            "sanitized/b.txt",
        )
        res = IdentityResolver()
        res.add_record(ev1)
        res.add_record(ev2)
        clusters = res.resolve()
        self.assertNotEqual(clusters["sanitized/a.txt::doc"], clusters["sanitized/b.txt::doc"])

    def test_unusual_mrn_and_missing_dob_preserved_and_linked(self) -> None:
        files = {
            "ward/nursing_ipd-2026-88421.txt": (
                "NURSING NOTES - Ward 3 - IPD-2026-88421\n"
                "Patient: Bhupendra Lodhi, Age: 61 yrs\n"
                "K/C/O Wegener granulomatosis. Admitted for 29 days.\n"
            ),
            "ward/discharge_88421.txt": (
                "Discharge Summary\n"
                "Patient Name: Bhupendra Lodhi\n"
                "IPD No: IPD-2026-88421\n"
                "Age: 61 yrs\n"
                "Diagnosis: Wegener granulomatosis\n"
            ),
        }
        out, _, records = self._run(files, "synth-secret-2")
        patients = {r["patient"] for r in records if r.get("patient")}
        self.assertEqual(len(patients), 1)
        all_sanitized = "\n".join(
            p.read_text(encoding="utf-8") for p in (out / "sanitized").rglob("*") if p.is_file()
        )
        self.assertNotIn("Bhupendra", all_sanitized)
        self.assertNotIn("IPD-2026-88421", all_sanitized)
        self.assertIn("Wegener granulomatosis", all_sanitized)
        self.assertIn("29 days", all_sanitized)

    def test_camelcase_json_key_and_csv_header_pii_sanitized(self) -> None:
        files = {
            "reg.csv": (
                "patient_name,uhid,HdrZorawarTag_col\n"
                "Zorawar Qureshi,HOSP-9901,safe_value\n"
            ),
            "nested.json": json.dumps({
                "patient": {"name": "Zorawar Qureshi", "uhid": "HOSP-9901"},
                "KeyZorawarTag_meta": "Zorawar Qureshi",
                "clinical": {"diagnosis": "Takayasu arteritis"},
            }),
        }
        out, _, _ = self._run(files, "synth-secret-keyhdr")
        all_sanitized = "\n".join(
            p.read_text(encoding="utf-8") for p in (out / "sanitized").rglob("*") if p.is_file()
        )
        self.assertNotIn("Zorawar", all_sanitized)
        self.assertNotIn("KeyZorawarTag", all_sanitized)
        self.assertNotIn("HdrZorawarTag", all_sanitized)
        self.assertIn("Takayasu arteritis", all_sanitized)

    def test_long_single_line_linear_performance(self) -> None:
        import time
        from rakshak.detection.addresses import detect_address_spans
        from rakshak.detection.identifiers import detect_identifier_spans

        for size in (5_000, 20_000, 100_000):
            txt = "Diagnosis: Fever. " + ("X" * size)
            t0 = time.perf_counter()
            detect_identifier_spans(txt)
            detect_address_spans(txt)
            elapsed = time.perf_counter() - t0
            self.assertLess(elapsed, 2.0, f"Single-line {size} chars took {elapsed:.2f}s (possible ReDoS)")


if __name__ == "__main__":
    unittest.main()
