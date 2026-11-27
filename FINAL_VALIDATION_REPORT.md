# RAKSHA — Final Competition Validation Report

**Date:** 2026-11-27

**Repository:** `d:\RAKSHA` (`30sharathkumar-ux/Med-sec`, branches `main` and `master`)

**Validated Code Commit:** `d576f178cf4e000bd5a917cac48258434c393f9b` (`d576f17` — includes all hardened code changes in `rakshak/cli.py`, `rakshak/detection/context_rules.py`, and `tests/test_doctor_qualifications.py`)

**Later Metadata / Documentation Commits:** `3cec0ec` (`raksha.toml` team name `POINT_BLANK`), `fe93e90` (updated `README.md` and `brief/PROJECT_BRIEF.pdf`)

---

## 1. Executive Result: **PARTIAL** (Submission-Ready on All Available Official Checks)

RAKSHA passes **all** bundled official practice, contract, and submission checks:
- `check_submission.py --repo . --run` → **`READY TO SUBMIT`**
- `validate_output.py` → **`CONTRACT OK`** (`192` sanitized + `8` quarantined = `200/200`)
- `check_dev.py` → **`0 / 3,230` PII leaked (`0.0%`)**, **`0 / 4` canaries**, **`4,855 / 4,855` medical values kept (`100.0%`)**, **`Precision 1.00 / Recall 1.00 / F0.5 1.00`** (`0` wrong merges)
- `pytest tests/` → **`199 passed in 10.47s`**

It is rated **PARTIAL** rather than full `PASS` for two honest reasons:
1. **Official `raksha_eval` A1–A7 scorer not bundled:** Exact official A1–A7 attack probabilities and `B³ F1` require the organizer's `raksha_eval` package (not present in this repository). Proxy tests are reported separately and never substituted for official scores.
2. **Adaptive k-anonymity enforcement not active in export:** `rakshak/privacy/k_anonymity.py` provides risk-measurement and widening/suppression helpers, and `report.json` logs summary metadata, but record-level age widening/PIN suppression is **not actively enforced** on `sanitized/` files to preserve clinical utility.

---

## 2. Official Scoring Categories & Verified Evidence

| Official Category (Weight) | Measured / Observed Result | Evidence Source |
|---|---|---|
| **1. Multilingual PII Detection (20%)** | **`0 / 3,230` leaked (`0.0%`)** across all 16 PII types, 3 scripts (`latin`, `deva`, `hinglish`), and 6 channels (`content`, `filename`, `base64`, `metadata`, `key`, `header`) | `check_dev.py` (Windows & WSL2 `taskset -c 0,1`) |
| **2. Cross-Document Identity Resolution (15%)** | **Precision `1.00`, Recall `1.00`, F0.5 `1.00`**, `0` wrong merges (`775` linked records). Official `B³ F1` requires `raksha_eval` | `check_dev.py`, `report.json` |
| **3. Adversarial Privacy (25%)** | **Not evaluated by official `raksha_eval`** (package not in repo). Proxy checks against `dev/attacker/` show `A1`: `0` registry names/phones/emails exposed; `A2/A3`: `0/240` registry villages surviving; `A5`: per-patient HMAC date shifting; `A6/A7`: domain-separated HMAC (`psn\|`, `shift\|`, `fname\|`) | `run_final_validation.py`, `test_attacker_simulation.py`, `test_domain_separation.py` |
| **4. Clinical Utility Preservation (20%)** | **`4,855 / 4,855` (`100.0%`)** official probes survived; all 7 targeted probes (`Dr. Ramesh Srivastava (MD Medicine)`, `Dr. Anil Kumar MD Cardiology`, `Dr. Anil Kumar, MD, Cardiology`, `Ramipril 5mg`, `Dolo 650 BD x 5 days`, `1-0-1`, `Parkinson's disease`) preserved; `LOS` (`5, 12, 10` days) `100%` preserved; `27/27` CSV age bands, villages, and PINs truthfully generalized | `check_dev.py`, `run_final_validation.py`, `test_doctor_qualifications.py` |
| **5. Data Integrity & Secure Export (10%)** | **`CONTRACT OK`**, `192` sanitized + `8` quarantined = `200/200`, `0` raw copies, UTF-8, deterministic | `validate_output.py`, `check_submission.py` |
| **6. CPU Efficiency & Reliability (10%)** | Exit `0` under 2-CPU `taskset -c 0,1` (WSL2), `6.64s` single-run (Windows), `31.0 MB` peak RSS (limit `900s`, `4,096 MB`) | `report.json`, WSL2 `taskset -c 0,1` run |

---

## 3. Exact Commands Executed (After Final Code Edit)

1. `RAKSHA_SECRET=practice python -m pytest tests/ -q --tb=short --ignore=lib64 --ignore=lib --ignore=bin` → **`199 passed in 10.47s`**
2. `RAKSHA_SECRET=practice python main.py --input dev/input --output output` → **`files 200 sanitized 192 quarantined 8 records 816 linked 775 generalized 677`**
3. `python check_dev.py --output output --truth dev/truth/truth.json` → **`0/3230` leaked, `0/4` canaries, `4855/4855` medical (`100.0%`), `P=1.00, R=1.00, F0.5=1.00`, `0` wrong merges, `0` raw copies**
4. `python validate_output.py --input dev/input --output output` → **`CONTRACT OK`**
5. `python artifacts/optimization/run_final_validation.py` → All 7 targeted medical probes `preserved=True`, genuine `Md.` patient `redacted=True`, `0` A1 exposures, `0/240` surviving registry villages, `RAKSHA_SECRET` absent from `output/`
6. `wsl -d Ubuntu` under `taskset -c 0,1`: `main.py`, `validate_output.py` (`CONTRACT OK`), `check_dev.py` (`0/3230`, `0/4`, `4855/4855`, `P=1.00/R=1.00/F0.5=1.00`), and `check_submission.py --repo . --run` (`READY TO SUBMIT`)
7. `python artifacts/optimization/build_project_brief.py` → **`Generated D:\RAKSHA\brief\PROJECT_BRIEF.pdf with 2 page(s)`**

---

## 4. Hardening Fixes & Compliance Audit

- **P0 Doctor Qualification Fix (`rakshak/detection/context_rules.py`):** Extended `"DOCTOR"` protected span to preserve both punctuated (`(MD Medicine)`, `, MD, Cardiology`) and unpunctuated (`Dr. Anil Kumar MD Cardiology`) qualifications attached to `Dr.`/`डॉ.` names without globally whitelisting `MD`. Added 8 regression tests in `tests/test_doctor_qualifications.py`.
- **Section 8 Hospital Detection Generalization (`rakshak/cli.py`):** Replaced hardcoded practice hospital aliases (`sanjeevani`, `jeevanjyoti`, `arogya`, `dhhardoi`) in `_detect_hospital()` with dynamic filename-stem token extraction.
- **CPU-Only / Offline / Zero-LLM Compliance:** Confirmed (`check_submission.py`: `requirements.txt has no LLM / hosted-AI packages`, zero network calls at runtime).
- **Source & Evaluator Integrity:** `git diff aa7424f HEAD -- dev/ check_dev.py check_submission.py validate_output.py scoring.toml` is empty (zero modifications). `arogya_legacy_export.csv` CRLF mismatch is caused solely by Git's newline conversion on 2 quoted multiline `Notes` fields (`1441` bytes expected vs `1443` on Windows disk; zero missing records).
