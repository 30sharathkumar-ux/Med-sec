"""Web Application & API Security Red-Team Suite against http://127.0.0.1:8080."""
from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:8080"
AUDIT_DIR = Path(__file__).resolve().parent


def req(method: str, path: str, body: bytes | None = None, content_type: str | None = "application/json"):
    headers = {}
    if content_type:
        headers["Content-Type"] = content_type
    r = urllib.request.Request(BASE + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def main() -> None:
    checks = []

    def rec(tid: str, ok: bool, detail: str) -> None:
        checks.append({"id": tid, "status": "PASS" if ok else "FAIL", "detail": detail})
        print(f"[{'PASS' if ok else 'FAIL'}] {tid}: {detail}")

    # 1. Security headers & static routes
    st, hdrs, _ = req("GET", "/", content_type=None)
    rec("API-01", st == 200 and hdrs.get("X-Content-Type-Options") == "nosniff", f"GET / status={st}, nosniff={hdrs.get('X-Content-Type-Options')}")

    # 2. Path & directory traversal
    for i, bad in enumerate([
        "/api/reports/download?target=../config/policy.yaml",
        "/api/reports/download?target=..\\..\\raksha.toml",
        "/api/reports/download?target=sanitized/../report.json",
        "/styles.css/../rakshak/web_server.py",
    ], 1):
        st_t, _, _ = req("GET", bad, content_type=None)
        rec(f"API-TRAV-{i}", st_t in (400, 403, 404), f"{bad} -> {st_t}")

    # 3. Malformed JSON & unexpected content type
    st_mj, _, _ = req("POST", "/api/datasets/upload", b"{broken json")
    rec("API-02", st_mj == 400, f"malformed JSON -> {st_mj}")

    st_ct, _, _ = req("POST", "/api/datasets/upload", b"plain text", content_type="text/plain")
    rec("API-03", st_ct == 400, f"unexpected content-type -> {st_ct}")

    # 4. Empty & invalid base64 upload
    st_emp, _, _ = req("POST", "/api/datasets/upload", json.dumps({"files": []}).encode())
    rec("API-04", st_emp == 400, f"empty upload -> {st_emp}")

    st_b64, _, _ = req("POST", "/api/datasets/upload", json.dumps({"files": [{"name": "a.txt", "content_base64": "!!!not_b64!!!"}]}).encode())
    rec("API-05", st_b64 == 400, f"invalid base64 -> {st_b64}")

    # 5. Invalid filename traversal in upload (server normalizes safely, never writes outside)
    st_fn, _, raw_fn = req("POST", "/api/datasets/upload", json.dumps({
        "dataset_name": "SecTestSet",
        "files": [
            {"name": "../../evil.txt", "content_base64": base64.b64encode(b"Patient: Test\n").decode()},
            {"name": "bad.exe", "content_base64": base64.b64encode(b"MZbinary").decode()},
        ]
    }).encode())
    up_j = json.loads(raw_fn.decode()) if st_fn == 200 else {}
    ds_id = up_j.get("dataset_id", "")
    rec("API-06", st_fn == 200 and not any(".." in f["masked_name"] for f in up_j.get("inspection", {}).get("files", [])), f"traversal filename sanitized -> {st_fn}")

    # 6. Run custom dataset & verify quarantined download blocked + no secret in responses
    _, _, st_run = req("POST", "/api/runs/start", json.dumps({"dataset_id": ds_id}).encode())
    rid = json.loads(st_run.decode())["run"]["run_id"]
    for _ in range(30):
        _, _, sr = req("GET", f"/api/runs/status?run_id={rid}", content_type=None)
        if json.loads(sr.decode())["status"] in ("completed", "failed"):
            break
        time.sleep(0.2)
    _, _, ov_raw = req("GET", "/api/overview", content_type=None)
    ov_j = json.loads(ov_raw.decode())
    rec("API-07", "practice" not in json.dumps(ov_j.get("system", {})), "RAKSHA_SECRET absent from /api/overview")
    rec("API-08", ov_j["counts"]["files_total"] == 2 and ov_j["counts"]["files_quarantined"] == 1, f"custom run counts={ov_j['counts']}")

    _, _, fl_raw = req("GET", "/api/files", content_type=None)
    q_file = next(f for f in json.loads(fl_raw.decode())["files"] if f["status"] == "quarantined")
    st_qd, _, _ = req("GET", f"/api/reports/download?target=sanitized/{q_file['display_name']}", content_type=None)
    rec("API-09", st_qd == 403, f"quarantined download blocked -> {st_qd}")

    # 7. Switch back to practice-baseline
    st_sw, _, _ = req("POST", "/api/runs/select", json.dumps({"run_id": "practice-baseline"}).encode())
    _, _, ov_p = req("GET", "/api/overview", content_type=None)
    rec("API-10", st_sw == 200 and json.loads(ov_p.decode())["counts"]["files_total"] == 200, "cross-run switch restored practice-baseline")

    (AUDIT_DIR / "api_security_results.json").write_text(json.dumps(checks, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
