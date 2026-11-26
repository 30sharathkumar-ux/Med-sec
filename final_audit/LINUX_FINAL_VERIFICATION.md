# RAKSHA — Linux Final Verification Guide

**Track 3: Secret Wards — Yugaantar DevForge**
**Date:** 2026-11-27

---

## 1. Environment Setup

```bash
# Clone the repository
git clone <your-repo-url> raksha
cd raksha

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## 2. Full Pipeline Run

```bash
# Set secret
export RAKSHA_SECRET="practice"

# Run pipeline
python main.py --input dev/input --output output

# Expected output:
# files 200 sanitized 192 quarantined 8 records 816 linked 771 generalized 677
```

## 3. Contract Validation

```bash
python3 validate_output.py --input dev/input --output output
# Expected: CONTRACT OK
```

## 4. Self-Check

```bash
python3 check_dev.py --output output --show 30
```

### Expected Results (Linux with git-cloned files)
| Metric | Expected |
|---|---|
| PII leaks | 0/3230 (0.0%) |
| Canary leaks | 0/4 |
| Medical values | 4855/4855 (100.0%) |
| Precision | 1.00 |
| Recall | ≥ 0.70 |
| F0.5 | ≥ 0.92 |
| Wrong merges | 0 |
| Raw copies | 0 |

> **Note:** On Linux, SHA-256 hashes will match truth.json correctly, resolving the 13 filename "leaks" seen on Windows and testing all 4855 medical probes.

## 5. Submission Checker

```bash
python3 check_submission.py --repo . --run

# Expected:
# ✅ raksha.toml found
# ✅ team name: team-raksha
# ✅ run command correct
# ✅ setup command correct
# ✅ README.md found
# ✅ requirements.txt clean
# ✅ config/policy.yaml found
# ✅ Pipeline runs successfully
# ✅ CONTRACT OK
# READY TO SUBMIT
```

## 6. Determinism Test

```bash
# Run 1
rm -rf output_1
RAKSHA_SECRET="practice" python main.py --input dev/input --output output_1

# Run 2 (same secret)
rm -rf output_2
RAKSHA_SECRET="practice" python main.py --input dev/input --output output_2

# Compare sanitized directories
diff -rq output_1/sanitized output_2/sanitized
# Expected: no differences

# Compare records.jsonl
diff output_1/records.jsonl output_2/records.jsonl
# Expected: no differences

# Run 3 (different secret)
rm -rf output_3
RAKSHA_SECRET="different_secret" python main.py --input dev/input --output output_3

# Verify different output
diff -rq output_1/sanitized output_3/sanitized
# Expected: differences found (different pseudonyms and date shifts)
```

## 7. Test Suite

```bash
python3 -m pytest tests/ -v --tb=short
# Expected: 147 passed, 0 failed
```

## 8. Input Immutability Verification

```bash
# Hash input before
find dev/input -type f -exec sha256sum {} \; | sort > /tmp/before.txt

# Run pipeline
RAKSHA_SECRET="practice" python main.py --input dev/input --output output

# Hash input after
find dev/input -type f -exec sha256sum {} \; | sort > /tmp/after.txt

# Compare
diff /tmp/before.txt /tmp/after.txt
# Expected: no differences
```

## 9. Side-Channel Check

```bash
# Check for PII in report
grep -iE '(aadhaar|phone|name|address)' output/report.json | head
# Expected: only field names like "PATIENT_NAME", never actual values

# Check for temp files
ls -la /tmp/ | grep raksha
# Expected: nothing

# Check no PII in stdout/stderr
RAKSHA_SECRET="practice" python main.py --input dev/input --output output 2>&1 | grep -v "^files"
# Expected: empty (no other output)
```

## 10. Acceptance Gates

All must pass for submission:

| # | Gate | Command | Expected |
|---|---|---|---|
| 1 | Pipeline completes | `python main.py ...` | Exit code 0 |
| 2 | Contract valid | `validate_output.py` | CONTRACT OK |
| 3 | Zero content leaks | `check_dev.py` | 0 PII leaks |
| 4 | Zero canaries | `check_dev.py` | 0/4 canaries |
| 5 | 100% medical values | `check_dev.py` | 4855/4855 |
| 6 | Zero wrong merges | `check_dev.py` | 0 |
| 7 | Zero raw copies | `check_dev.py` | 0 |
| 8 | Deterministic | Diff two runs | Identical |
| 9 | Different on new secret | Diff with new secret | Different |
| 10 | Tests pass | `pytest tests/` | 125 passed |
| 11 | Submission ready | `check_submission.py --run` | READY TO SUBMIT |
| 12 | Input unmodified | SHA comparison | Identical |
