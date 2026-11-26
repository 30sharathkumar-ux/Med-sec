# RAKSHA — Web Application & API Security Audit

**Target:** `http://127.0.0.1:8080` ([rakshak/web_server.py](file:///d:/RAKSHA/rakshak/web_server.py))  
**Tooling:** Custom Python HTTP security suite ([api_security_test.py](file:///d:/RAKSHA/artifacts/redteam_audit/api_security_test.py)). `zapv2` (OWASP ZAP) is `NOT_INSTALLED`.

## Results (`14 / 14` Passed)

- **API-01 (`PASS`):** `GET /` returned `200` with `X-Content-Type-Options: nosniff`.
- **API-TRAV-1..4 (`PASS`):** Path traversal attempts (`../config/policy.yaml`, `..\..\raksha.toml`, `sanitized/../report.json`, `/styles.css/../rakshak/web_server.py`) blocked with `400`/`403`/`404`.
- **API-02..05 (`PASS`):** Malformed JSON (`400`), `text/plain` unexpected content type (`400`), empty upload (`400`), and invalid base64 (`400`) all rejected cleanly.
- **API-06 (`PASS`):** Upload with `../../evil.txt` stripped traversal segments safely (`[REDACTED_NAME_...]` / flat basename).
- **API-07 (`PASS`):** `RAKSHA_SECRET` absent from `/api/overview`.
- **API-08 (`PASS`):** Custom 2-file run (`evil.txt` + `bad.exe`) reported `files_total=2, files_quarantined=1`.
- **API-09 (`PASS`):** Quarantined file download blocked with `403`.
- **API-10 (`PASS`):** Switching back to `practice-baseline` cleanly restored `files_total=200` with zero cross-run leakage.

## Notes
- No authentication layer exists because RAKSHA UI binds strictly to `127.0.0.1` for single-operator local execution.
- OWASP ZAP passive/active scan: `NOT VERIFIED` (`zapv2` not installed).
