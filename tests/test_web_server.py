"""Integration & acceptance tests for rakshak.web_server and frontend contract."""
from __future__ import annotations

import base64
import http.client
import io
import json
import os
import tempfile
import threading
import time
import unittest
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path

from rakshak import web_server


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


class TestWebServerAcceptance(unittest.TestCase):
    """End-to-end acceptance tests for Dataset A/B, switching, downloads, quarantine, security, and persistence."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)

        # Isolate registry and run storage to temp dir
        self._orig_runs_base = web_server.RUNS_BASE_DIR
        self._orig_datasets_dir = web_server.DATASETS_DIR
        self._orig_runs_out = web_server.RUNS_OUTPUT_DIR
        self._orig_registry_path = web_server.REGISTRY_PATH

        web_server.RUNS_BASE_DIR = base / ".raksha_ui_runs"
        web_server.DATASETS_DIR = web_server.RUNS_BASE_DIR / "datasets"
        web_server.RUNS_OUTPUT_DIR = web_server.RUNS_BASE_DIR / "runs"
        web_server.REGISTRY_PATH = web_server.RUNS_BASE_DIR / "registry.json"

        self._reset_memory_registry()

        self._old_secret = os.environ.get("RAKSHA_SECRET")
        os.environ["RAKSHA_SECRET"] = "acceptance-secret-do-not-leak"

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), web_server.RakshaHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        web_server.RUNS_BASE_DIR = self._orig_runs_base
        web_server.DATASETS_DIR = self._orig_datasets_dir
        web_server.RUNS_OUTPUT_DIR = self._orig_runs_out
        web_server.REGISTRY_PATH = self._orig_registry_path
        self._reset_memory_registry()
        if self._old_secret is None:
            os.environ.pop("RAKSHA_SECRET", None)
        else:
            os.environ["RAKSHA_SECRET"] = self._old_secret

    @staticmethod
    def _reset_memory_registry() -> None:
        with web_server._LOCK:
            web_server._DATASETS.clear()
            web_server._RUNS.clear()
            web_server._ACTIVE_DATASET_ID = "practice"
            web_server._ACTIVE_RUN_ID = None
            web_server._REGISTRY_LOADED = False

    def _req(self, method: str, path: str, body: dict | None = None) -> tuple[int, bytes, dict]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        headers = {}
        raw = None
        if body is not None:
            raw = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=raw, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        resp_headers = dict(resp.getheaders())
        conn.close()
        return resp.status, data, resp_headers

    def _json(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        status, data, _ = self._req(method, path, body)
        return status, json.loads(data.decode("utf-8"))

    def _wait_for_run(self, run_id: str, timeout_s: float = 20.0) -> dict:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            st, payload = self._json("GET", f"/api/runs/status?run_id={run_id}")
            self.assertEqual(st, 200)
            if payload["status"] != "processing":
                return payload
            time.sleep(0.1)
        self.fail(f"Run {run_id} did not finish within {timeout_s}s")

    def test_dataset_ab_switching_downloads_quarantine_and_persistence(self) -> None:
        # 1. Upload Dataset A (2 sanitized + 1 quarantined unsupported .pdf)
        st, up_a = self._json("POST", "/api/datasets/upload", {
            "dataset_name": "Dataset A",
            "files": [
                {
                    "name": "reg/patients_a.csv",
                    "content_base64": _b64(
                        "UHID,Patient Name,Mobile,Age,Diagnosis\n"
                        "UHID-101,Aarav Sharma,9876543210,42,Dengue\n"
                    ),
                },
                {
                    "name": "notes/Discharge_Summary_Aarav_Sharma_UHID-101.txt",
                    "content_base64": _b64(
                        "Patient Name: Aarav Sharma\nUHID: UHID-101\nDiagnosis: Dengue\nRx: Dolo 650 BD\n"
                    ),
                },
                {
                    "name": "scans/raw_scan.pdf",
                    "content_base64": _b64("%PDF-1.4 fake binary"),
                },
            ],
        })
        self.assertEqual(st, 200)
        ds_a = up_a["dataset_id"]

        # Verify PII filename is masked in pre-processing inspection
        insp_names = [f["masked_name"] for f in up_a["inspection"]["files"]]
        self.assertFalse(any("Aarav_Sharma" in n for n in insp_names))

        # 2. Process Dataset A (Run 1)
        st, run_a1_start = self._json("POST", "/api/runs/start", {"dataset_id": ds_a})
        self.assertEqual(st, 200)
        run_a1_id = run_a1_start["run"]["run_id"]
        run_a1 = self._wait_for_run(run_a1_id)
        self.assertEqual(run_a1["status"], "completed")
        self.assertTrue(run_a1["contract"]["ok"])

        st, ov_a1 = self._json("GET", "/api/overview")
        self.assertEqual(st, 200)
        self.assertEqual(ov_a1["active_dataset"]["id"], ds_a)
        self.assertEqual(ov_a1["counts"]["files_total"], 3)
        self.assertEqual(ov_a1["counts"]["files_sanitized"], 2)
        self.assertEqual(ov_a1["counts"]["files_quarantined"], 1)
        self.assertGreater(ov_a1["resources"]["peak_rss_mb"], 0)

        # Security check: no secret or raw PII in overview, files, linkage
        for endpoint in ("/api/overview", "/api/files?page_size=50", "/api/linkage?page_size=50"):
            _, raw_bytes, _ = self._req("GET", endpoint)
            text = raw_bytes.decode("utf-8")
            self.assertNotIn("acceptance-secret-do-not-leak", text)
            self.assertNotIn("9876543210", text)
            self.assertNotIn("Aarav Sharma", text)

        # Quarantine check: sanitized download works, quarantined target is 403
        _, files_a = self._json("GET", "/api/files?status=all&page_size=50")
        sanitized_item = next(f for f in files_a["files"] if f["status"] == "sanitized")
        quarantined_item = next(f for f in files_a["files"] if f["status"] == "quarantined")
        self.assertIsNotNone(quarantined_item["reason"])

        dl_ok, _, _ = self._req("GET", f"/api/reports/download?target={sanitized_item['output_path']}")
        self.assertEqual(dl_ok, 200)
        dl_q, _, _ = self._req("GET", "/api/reports/download?target=sanitized/scans/raw_scan.pdf")
        self.assertEqual(dl_q, 403)

        # Report & bundle downloads
        dl_rep, rep_bytes, _ = self._req("GET", "/api/reports/download?target=report.json")
        self.assertEqual(dl_rep, 200)
        self.assertNotIn("acceptance-secret-do-not-leak", rep_bytes.decode("utf-8"))

        dl_zip, zip_bytes, _ = self._req("GET", "/api/reports/bundle")
        self.assertEqual(dl_zip, 200)
        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            names = set(zf.namelist())
            self.assertIn("report.json", names)
            self.assertIn("records.jsonl", names)
            self.assertFalse(any("raw_scan.pdf" in n for n in names))

        # 3. Upload Dataset B (1 file, different counts)
        st, up_b = self._json("POST", "/api/datasets/upload", {
            "dataset_name": "Dataset B",
            "files": [
                {
                    "name": "ward/note_b.txt",
                    "content_base64": _b64(
                        "Patient Name: Sunita Devi\nPhone: 9123456789\nDiagnosis: Typhoid\n"
                    ),
                },
            ],
        })
        self.assertEqual(st, 200)
        ds_b = up_b["dataset_id"]

        # Switching to Dataset B before any run must show has_output=False (no stale A metrics)
        _, ov_b_empty = self._json("GET", "/api/overview")
        self.assertFalse(ov_b_empty["has_output"])
        self.assertEqual(ov_b_empty["active_dataset"]["id"], ds_b)

        # Process Dataset B
        st, run_b1_start = self._json("POST", "/api/runs/start", {"dataset_id": ds_b})
        self.assertEqual(st, 200)
        run_b1 = self._wait_for_run(run_b1_start["run"]["run_id"])
        self.assertEqual(run_b1["status"], "completed")

        _, ov_b1 = self._json("GET", "/api/overview")
        self.assertTrue(ov_b1["has_output"])
        self.assertEqual(ov_b1["counts"]["files_total"], 1)
        self.assertEqual(ov_b1["counts"]["files_quarantined"], 0)

        # 4. Dataset switching back to Dataset A restores Dataset A's metrics
        st, sel_a = self._json("POST", "/api/datasets/select", {"dataset_id": ds_a})
        self.assertEqual(st, 200)
        self.assertEqual(sel_a["active_run_id"], run_a1_id)
        _, ov_back_a = self._json("GET", "/api/overview")
        self.assertEqual(ov_back_a["counts"]["files_total"], 3)
        self.assertEqual(ov_back_a["active_run"]["run_id"], run_a1_id)

        # 5. Multiple runs on Dataset A
        st, run_a2_start = self._json("POST", "/api/runs/start", {"dataset_id": ds_a})
        self.assertEqual(st, 200)
        run_a2_id = run_a2_start["run"]["run_id"]
        self.assertNotEqual(run_a2_id, run_a1_id)
        run_a2 = self._wait_for_run(run_a2_id)
        self.assertEqual(run_a2["status"], "completed")

        # 6. Registry persistence across simulated server restart
        self._reset_memory_registry()
        _, ds_after = self._json("GET", "/api/datasets")
        _, runs_after = self._json("GET", "/api/runs")
        ds_ids = {d["id"] for d in ds_after["datasets"]}
        run_ids = {r["run_id"] for r in runs_after["runs"]}
        self.assertIn(ds_a, ds_ids)
        self.assertIn(ds_b, ds_ids)
        self.assertIn(run_a1_id, run_ids)
        self.assertIn(run_a2_id, run_ids)
        self.assertIn(run_b1["run_id"], run_ids)
        self.assertEqual(runs_after["active_run_id"], run_a2_id)

    def test_frontend_memory_never_shows_zero_mb(self) -> None:
        app_js = (Path(__file__).resolve().parent.parent / "frontend" / "app.js").read_text(encoding="utf-8")
        self.assertIn("Unavailable on this platform", app_js)
        self.assertIn("Not measured", app_js)
        self.assertIn("rawRss > 0", app_js)


if __name__ == "__main__":
    unittest.main()
