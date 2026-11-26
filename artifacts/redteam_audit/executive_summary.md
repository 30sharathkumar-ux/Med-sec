# RAKSHA — Executive Red-Team & Competition Readiness Summary

**Audit Date:** 2026-11-27  
**Repository:** `https://github.com/30sharathkumar-ux/Med-sec.git` (`main` @ `2bc1c2b`, clean working tree)  
**Target:** Yugaantar DevForge Track 3 — *Secret Wards*  

## Overall Verdict: **NEEDS FIXES**

While RAKSHA demonstrates strong baseline performance on the practice dataset (`0/3230` PII leaked, `0/4` canaries, `4854/4855` medical preservation, `1.00` linking precision, `0` wrong merges) and passes `147/147` unit tests, **independent adversarial red-teaming uncovered 4 concrete issues** that should be addressed before final submission:

1. **[HIGH] Single-Line ReDoS / Super-Linear Performance Stall (`>120s`):** A 100,000-character single-line text file (`long_line.txt`) stalled the pipeline for `>120s`, whereas reducing the line to 5,000 characters completed in `3.552s` total.
2. **[HIGH] CamelCase / Compound PII in JSON Keys & CSV Headers (`hidden_surfaces.py:272-275, 314-318`):** `CANARY-JSON_KEY_PII` and `CANARY-CSV_HEADER_PII` leaked when embedded in camelCase/compound identifiers (e.g., `Key..._meta`, `Hdr..._col`), because `sanitize_csv_header` and `sanitize_json_key` do not split camelCase and do not match Latin `extra_names`.
3. **[MEDIUM] `check_submission.py --repo . --run` Fails on Windows (`shlex.quote` quoting bug):** `check_submission.py` passes literal single quotes around Windows temp paths into `os.mkdir`, causing `[WinError 123]` (Linux evaluation unaffected, but Windows pre-submission verification fails). Also `rapidfuzz` is listed in `requirements.txt` but `NOT_INSTALLED` in the current Python environment.
4. **[LOW / NOT VERIFIED] Unverified Browser & External Privacy Libraries:** `playwright`, `selenium`, `anonymeter`, `pycanon`, and `zapv2` are not installed in this environment, and Chrome remote debugging (`DevToolsActivePort`) was unavailable, so live browser UI rendering and screenshots could not be independently verified.

## Summary Counts
- **Existing Backend Tests (`pytest tests/`):** `147 / 147` passed (`2.99s`)
- **Practice Self-Check (`check_dev.py`):** `0/3230` PII leaked, `0/4` canaries, `4854/4855` (`100.0%`) medical kept, `P=1.00 / R=0.71 / F0.5=0.93`, `0` wrong merges
- **Synthetic Red-Team Suite (`run_audit.py`):** `44 / 46` passed, `2` failed (`CANARY-JSON_KEY_PII`, `CANARY-CSV_HEADER_PII`)
- **Web API Security Suite (`api_security_test.py`):** `14 / 14` passed
- **Real Browser / ZAP / Anonymeter / pyCANON:** `NOT VERIFIED` (missing dependencies / Chrome DevTools port)
