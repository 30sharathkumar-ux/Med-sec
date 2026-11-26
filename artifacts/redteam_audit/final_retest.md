# RAKSHA — Final Red-Team Retest & Verification Report

**Date:** 2026-11-27  
**Branch:** `main` (uncommitted fixes pending user review; not pushed)

---

## 1. Root Cause of Every Issue & Exact Files Changed

### Issue 1 (`HIGH`): CamelCase & Latin `extra_names` PII Leaked in JSON Keys and CSV Headers
- **Root Cause:** `sanitize_csv_header` and `sanitize_json_key` split only on `[^A-Za-z]+` (missing camelCase/PascalCase boundaries like `KeyZorawarTag_meta` / `HdrZorawarTag_col`) and checked `extra_names` only for Devanagari tokens, not Latin tokens.
- **Fix Applied:** Added `_SAFE_SCHEMA_TOKENS` and `_extra_latin_keys()` in [rakshak/detection/hidden_surfaces.py](file:///d:/RAKSHA/rakshak/detection/hidden_surfaces.py#L60-L92), updated `sanitize_csv_header` ([L291-L343](file:///d:/RAKSHA/rakshak/detection/hidden_surfaces.py#L291-L343)) and `sanitize_json_key` ([L346-L378](file:///d:/RAKSHA/rakshak/detection/hidden_surfaces.py#L346-L378)) to split camelCase tokens via `_split_unicode_tokens`, match Latin `extra_names` exact/phonetic tokens, and preserve legitimate clinical/FHIR schema keys.

### Issue 2 (`HIGH`): `>120s` ReDoS / Quadratic Stall on Long Single-Line Text
- **Root Cause:** Profiling a `15,000`-character single-line string revealed `addresses.py` (`7.8020s`) and `identifiers.py` (`1.3376s`) suffered from $O(N^2)$ unanchored scanning on:
  1. `_LANDMARK_RE` Hindi branch (`[^\s,;|]+...` without a leading token boundary) in [rakshak/detection/addresses.py](file:///d:/RAKSHA/rakshak/detection/addresses.py#L30-L36)
  2. `_EMAIL_RE` (`[\w.+-]+@...` without a negative lookbehind) in [rakshak/detection/identifiers.py](file:///d:/RAKSHA/rakshak/detection/identifiers.py#L28)
- **Fix Applied:** Added negative lookbehinds and bounded token lengths (`(?<![^\s,;|])[^\s,;|]{1,40}...` and `(?<![\w.+-])[\w.+-]{1,64}@...`) so both regexes execute in strictly linear $O(N)$ time.

### Issue 3 (`MEDIUM`): `check_submission.py --repo . --run` Windows `WinError 123`
- **Root Cause:** Organizer script [check_submission.py](file:///d:/RAKSHA/check_submission.py#L85) uses POSIX `shlex.quote()` on Windows paths, passing literal single quotes into `os.mkdir`. Not our code; organizer script left untouched per rules.

### Regression Tests Added
- [tests/test_synthetic_adversarial.py](file:///d:/RAKSHA/tests/test_synthetic_adversarial.py#L147-L179): Added `test_camelcase_json_key_and_csv_header_pii_sanitized` and `test_long_single_line_linear_performance` (`5 KB`, `20 KB`, `100 KB`).

---

## 2. Tests Before vs. After

| Suite | Before Fixes | After Fixes | Notes |
|---|---|---|---|
| `pytest tests/` | `147 / 147` (`2.99s`) | **`149 / 149` (`2.29s`)** | +2 new regression tests |
| `validate_output.py` (practice) | `CONTRACT OK` (4 CRLF warns) | **`CONTRACT OK` (4 CRLF warns)** | 0 errors |
| `check_dev.py` (practice) | `0/3230` leaked, `4854/4855` med, `P=1.00/R=0.71/F0.5=0.93` | **`0/3230` leaked, `4854/4855` med, `P=1.00/R=0.71/F0.5=0.93`** | Zero regression |
| `run_audit.py` (synthetic) | `44 / 46` (2 canary fails, 100KB line stalled `>120s`) | **`46 / 46` (`0` failed)** | All 22 canaries `PASS` |
| `api_security_test.py` | `14 / 14` | **`14 / 14`** | All path traversal/quarantine/secret checks pass |

---

## 3. Actual Performance Benchmark Results
- **Single-line scaling (post-fix):**
  - `5,000` chars: `0.0184s`
  - `20,000` chars: `0.0680s`
  - `100,000` chars: `0.3055s` (down from `>120s`)
- **2-CPU Core Affinity (`psutil.cpu_affinity`):**
  - 8-file synthetic dataset: `0.059s` (`0.042s` repeat)
  - 15-file robustness suite (including `5 KB`, `20 KB`, `100 KB` single-line files + `100 KB` multi-line + UTF-16/CP1252/BOM/broken JSON/FHIR): **`3.572s`**
  - Process RSS: **`28.03 MB`** (well below 4 GB RAM / 15 min limits)

---

## 4. Remaining Unverified / Blocked Items
1. **Linux / WSL `check_submission.py --repo . --run`:** Blocked in this sandbox (`wsl --list` returned `Wsl/E_ACCESSDENIED`); Windows fails due to `check_submission.py:85` `shlex.quote()`.
2. **`rapidfuzz` in active local Python env:** Listed in `requirements.txt`, currently `NOT_INSTALLED` locally (`resolver.py` falls back safely, but `pip install -r requirements.txt` should be run in the Linux evaluation env).
3. **Real Browser / Playwright / OWASP ZAP / Anonymeter / pyCANON:** `playwright`, `selenium`, `zapv2`, `anonymeter`, and `pycanon` are `NOT_INSTALLED`, and Chrome `DevToolsActivePort` was unavailable, so live browser screenshots remain **`NOT VERIFIED`**.

---

## 5. Updated Conservative Competition Score & Verdict

| Category | Weight | Before | After | Evidence |
|---|---|---|---|---|
| Privacy Against Attacks | 25 | 21 / 25 | **21 / 25** | `0/4` practice canaries, `0` raw copies, deterministic HMAC & secret rotation (`anonymeter`/`pycanon` not installed) |
| Personal Data Detection | 20 | 17 / 20 | **20 / 20** | `0/3230` practice + **`22/22` synthetic canaries PASS** |
| Medical Data Preservation | 20 | 19.5 / 20 | **19.5 / 20** | `4854/4855` (`100.0%`) practice + `13/13` clinical traps |
| Patient Identity Consistency | 15 | 13.5 / 15 | **13.5 / 15** | `P=1.00, R=0.71, F0.5=0.93`, `0` wrong merges |
| Output Quality & Validity | 10 | 9 / 10 | **9 / 10** | `CONTRACT OK` on practice & synthetic |
| Speed & Reliability | 10 | 6 / 10 | **9.5 / 10** | `100 KB` ReDoS fixed (`>120s` → `0.3055s`), `3.572s` robustness, `28.03 MB` RSS on 2 cores |
| **TOTAL** | **100** | **86.0 / 100** | **92.5 / 100** | Evidence-backed; remaining deductions reflect unverified external tools |

### Verdict: **READY FOR DEMO / SUBMISSION (Pending Linux `check_submission.py --repo . --run` Verification)**
All confirmed code defects (camelCase/Latin key/header leaks and $O(N^2)$ regex ReDoS) are fixed and verified with passing regression tests (`149/149` pytest, `46/46` synthetic audit, `14/14` API security, `0/3230` practice leakage). Awaiting your review before committing/pushing.
