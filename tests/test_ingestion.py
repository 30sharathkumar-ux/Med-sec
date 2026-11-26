"""Unit tests for encoding detection, format sniffing, bounded parsing, and quarantine."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rakshak.encoding import decode_bytes
from rakshak.ingestion import IngestionError, check_json_depth, ingest_file, sniff_format
from rakshak.processors.quarantine import make_quarantine_entry


class EncodingTests(unittest.TestCase):
    def test_utf8_and_bom_and_utf16(self) -> None:
        d1, e1 = decode_bytes("नमस्ते".encode("utf-8"))
        self.assertIsNone(e1)
        self.assertEqual(d1.encoding, "utf-8")
        self.assertEqual(d1.text, "नमस्ते")

        d2, e2 = decode_bytes(b"\xef\xbb\xbfhello")
        self.assertIsNone(e2)
        self.assertEqual(d2.encoding, "utf-8-bom")
        self.assertEqual(d2.text, "hello")

        d3, e3 = decode_bytes("कमला".encode("utf-16"))
        self.assertIsNone(e3)
        self.assertEqual(d3.encoding, "utf-16")
        self.assertEqual(d3.text, "कमला")

    def test_cp1252_legacy_accepted_but_corrupt_bytes_rejected(self) -> None:
        # Legitimate cp1252 temperature symbol + en-dash
        raw_ok = b"Temp 101.2\xb0F on arrival \x96 stable."
        dec, err = decode_bytes(raw_ok)
        self.assertIsNone(err)
        self.assertEqual(dec.encoding, "cp1252")
        self.assertIn("101.2°F", dec.text)

        # Embedded BOM / corrupt byte run must be quarantined
        raw_bad = b"OPD note for Patient. \xff\xfe\xc3( Mobile 9999999999.\n"
        dec_bad, err_bad = decode_bytes(raw_bad)
        self.assertIsNone(dec_bad)
        self.assertEqual(err_bad, "corrupt_encoding")

    def test_binary_signatures_rejected(self) -> None:
        for sig in (b"%PDF-1.4\n...", b"\xff\xd8\xff\xe1Exif", b"abc\x00def"):
            dec, err = decode_bytes(sig)
            self.assertIsNone(dec)
            self.assertEqual(err, "binary_payload")


class IngestionTests(unittest.TestCase):
    def test_bounded_json_depth(self) -> None:
        nested = '{"a":' * 200 + "1" + "}" * 200
        with self.assertRaises(IngestionError) as ctx:
            check_json_depth(nested, max_depth=128)
        self.assertEqual(ctx.exception.reason, "excessive_nesting")

        # Braces inside strings do not count toward depth
        ok = '{"msg": "{{{{{{{{{{{{{{{{{{{{", "v": 1}'
        self.assertEqual(check_json_depth(ok, max_depth=5), 1)

    def test_mislabeled_json_in_csv_and_whatsapp_txt(self) -> None:
        with self.assertRaises(IngestionError) as ctx:
            sniff_format(".csv", '{"patient": "Test", "id": 1}')
        self.assertEqual(ctx.exception.reason, "format_mismatch")

        # WhatsApp forwards begin with '[date, time]' and must still be accepted as text
        wa = "[30/05/26, 9:32 pm] Forwarded\nDolo 650 BD x 5 days"
        self.assertEqual(sniff_format(".txt", wa), "text")

    def test_ingest_quarantines_unsupported_and_empty_and_preserves_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "empty.csv").write_bytes(b"")
            (root / "bad.xml").write_text("<ClinicalDocument/>", encoding="utf-8")
            (root / "trunc.json").write_text('{"visits": [{"a": 1', encoding="utf-8")
            (root / "ok.csv").write_text("col1,col2\na,b\n", encoding="utf-8")

            ing_e, meta_e = ingest_file(root / "empty.csv", root)
            self.assertIsNone(ing_e)
            self.assertEqual(meta_e["reason"], "empty_file")

            ing_x, meta_x = ingest_file(root / "bad.xml", root)
            self.assertIsNone(ing_x)
            self.assertEqual(meta_x["reason"], "unsupported_format")

            ing_j, meta_j = ingest_file(root / "trunc.json", root)
            self.assertIsNone(ing_j)
            self.assertEqual(meta_j["reason"], "JSONDecodeError")

            ing_ok, _ = ingest_file(root / "ok.csv", root)
            self.assertIsNotNone(ing_ok)
            self.assertEqual(ing_ok.fmt, "csv")
            self.assertEqual(ing_ok.parsed, (["col1", "col2"], [["a", "b"]]))

    def test_quarantine_reason_sanitization(self) -> None:
        q = make_quarantine_entry("abc123", "bad/file:name")
        self.assertEqual(q["status"], "quarantined")
        self.assertIsNone(q["output"])
        self.assertEqual(q["reason"], "bad_file_name")


if __name__ == "__main__":
    unittest.main()
