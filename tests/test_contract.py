"""Contract and determinism tests for the RAKSHA pipeline."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from rakshak.cli import run_pipeline


def _tree_digest(root: Path) -> str:
    h = hashlib.sha256()
    for name in ("sanitized", "records.jsonl"):
        p = root / name
        items = sorted(p.rglob("*")) if p.is_dir() else ([p] if p.exists() else [])
        for f in items:
            if f.is_file():
                h.update(f.relative_to(root).as_posix().encode() + b"\0" + f.read_bytes() + b"\0")
    return h.hexdigest()


class ContractTests(unittest.TestCase):
    def test_pipeline_contract_quarantine_and_determinism(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inp = base / "inp"
            inp.mkdir()
            (inp / "notes.txt").write_text("C/O fever. Tab Paracetamol 650 mg.", encoding="utf-8")
            (inp / "bad.pdf").write_bytes(b"%PDF-1.5 binary")
            (inp / "mislabeled.csv").write_text('{"x": 1}', encoding="utf-8")
            (inp / "deep.json").write_text('{"a":' * 200 + "1" + "}" * 200, encoding="utf-8")

            out1 = base / "out1"
            out2 = base / "out2"
            old_secret = os.environ.get("RAKSHA_SECRET")
            os.environ["RAKSHA_SECRET"] = "test-secret-unit"
            try:
                self.assertEqual(run_pipeline(inp, out1), 0)
                self.assertEqual(run_pipeline(inp, out2), 0)
            finally:
                if old_secret is None:
                    os.environ.pop("RAKSHA_SECRET", None)
                else:
                    os.environ["RAKSHA_SECRET"] = old_secret

            self.assertEqual(_tree_digest(out1), _tree_digest(out2))
            rep = json.loads((out1 / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(rep["schema"], "raksha-report/1")
            self.assertEqual(rep["counts"]["files_total"], 4)
            self.assertEqual(rep["counts"]["files_sanitized"], 1)
            self.assertEqual(rep["counts"]["files_quarantined"], 3)
            self.assertFalse((out1 / "sanitized" / "bad.pdf").exists())
            self.assertFalse((out1 / "sanitized" / "mislabeled.csv").exists())
            self.assertFalse((out1 / "sanitized" / "deep.json").exists())


if __name__ == "__main__":
    unittest.main()
