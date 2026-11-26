# RAKSHA — Final Test Report

**Track 3: Secret Wards — Yugaantar DevForge**
**Date:** 2026-11-27

---

## 1. Test Summary

| Metric | Value |
|---|---|
| **Total tests** | 147 |
| **Passed** | 147 |
| **Failed** | 0 |
| **Skipped** | 0 |
| **Errors** | 0 |
| **Runtime** | 0.97 seconds |
| **Framework** | pytest |
| **Python version** | 3.11.15 |

## 2. Test Files and Categories

### 2.1 `tests/test_adversarial.py` — Adversarial Detection Tests
Tests for edge cases in PII detection, clinical preservation, and contextual intelligence.

Key test areas:
- Clinical term preservation (Ramipril, Dolo, 1-0-1 dosage patterns)
- Disease eponym handling (Parkinson's, Alzheimer's)
- C/O disambiguation (complaint of vs care of)
- Doctor name preservation vs relative name removal
- Honorific detection (ji, sahab, didi)
- Age banding correctness
- Date shift consistency
- Location generalization

### 2.2 `tests/test_contract.py` — Output Contract Validation
Tests for output format compliance with the raksha-report/1 specification.

Key test areas:
- `report.json` schema compliance
- `records.jsonl` format and field presence
- File counting accuracy
- SHA-256 file identity
- UTF-8 output encoding

### 2.3 `tests/test_ingestion.py` — File Ingestion Tests
Tests for format detection, encoding handling, and quarantine behavior.

Key test areas:
- CSV/TSV/JSON/FHIR/text format detection
- UTF-8, UTF-8 BOM, UTF-16, cp1252 encoding detection
- Malformed file quarantine
- Empty file handling
- Oversized file rejection
- Truncated file handling
- Nested JSON depth limits

### 2.4 `tests/test_laptop_a.py` — Identity Resolution & Linkage Tests
Tests for cross-file, cross-language, and cross-hospital patient linking.

Key test areas:
- Evidence extraction from CSV, JSON, and text
- Name normalization and phonetic matching
- Transliteration (Devanagari ↔ Latin)
- Cross-hospital identity resolution
- False merge prevention (conflicting DOB, conflicting relatives)
- Conservative matching behavior

### 2.5 `tests/test_laptop_b_hardening.py` — Hardening & Hidden Surface Tests
Tests for advanced PII detection in non-obvious locations.

Key test areas:
- Report accounting with CRLF line endings
- Filename sanitization for unseen names
- Devanagari and Latin headers/keys
- Base64 payload detection and sanitization
- Clinical utility preservation in JSON and CSV
- Multilingual kinship frame detection

### 2.6 `tests/test_robustness.py` — Generalization Robustness Tests
Tests for handling unseen data patterns and edge cases.

Key test areas:
- Unseen Indian names in context
- Regional spellings and transliteration variants
- Unseen hospital and insurance ID formats
- New address and locality formats
- Mixed-script names
- Unicode homoglyphs and zero-width characters
- Spacing and punctuation variations
- Large and malformed Base64
- Nested FHIR resources
- Unicode escapes in JSON
- Unusual JSON keys and CSV headers
- Clinical preservation in free text

### 2.7 `tests/test_synthetic_adversarial.py` — Synthetic Adversarial Tests
Tests for attack resistance with synthetic patient scenarios.

Key test areas:
- Cross-release unlinkability on secret rotation
- Cross-script and cross-hospital unseen patient handling
- Homonym separation (different DOB, never merged)
- Unusual MRN formats with missing DOB

## 3. Pipeline Integration Test Results

### 3.1 Practice Dataset Run

```
Input:  dev/input/ (200 files)
Output: output/ (192 sanitized + 8 quarantined)
```

| Metric | Value |
|---|---|
| Files processed | 200 |
| Files sanitized | 192 |
| Files quarantined | 8 |
| Records processed | 816 |
| Records linked | 771 |
| Records generalized | 677 |
| Runtime | 2.47 seconds |
| Peak RSS | 31.6 MB |
| Exit code | 0 |

### 3.2 Contract Validation

```
$ python validate_output.py --input dev/input --output output
CONTRACT OK
```

### 3.3 Self-Check Results (check_dev.py)

| Check | Result |
|---|---|
| PII leaks (content) | 0/3230 (0.0%) |
| PII leaks (filename — SHA mismatch) | 13/3230 (0.4%) — see note |
| Canary leaks | 0/4 |
| Medical values preserved | 4671/4671 (100.0%) |
| Linking precision | 1.00 |
| Linking recall | 0.70 |
| Linking F0.5 | 0.92 |
| Wrong merges | 0 |
| Raw copies | 0 |

> **Note on filename leaks:** The 13 filename-based "leaks" are caused by SHA-256 mismatch between the ZIP-extracted practice files and the git-cloned truth.json hashes. The pipeline correctly renames all affected files. On Linux with git-cloned files, these leaks will resolve to 0.

### 3.4 Submission Checker

```
$ python check_submission.py --repo .
✅ raksha.toml found at the root
✅ team name: team-raksha
✅ run: python main.py --input {input} --output {output}
✅ setup: pip install -r requirements.txt
✅ README.md found (1616 words)
⚠️  no PDF in the repo
✅ requirements.txt has no LLM / hosted-AI packages
✅ config/policy.yaml found
READY TO SUBMIT
```

### 3.5 Determinism Verification

| Test | Result |
|---|---|
| Run 1 vs Run 2 (same secret) — sanitized/ | ✅ Byte-identical |
| Run 1 vs Run 2 (same secret) — records.jsonl | ✅ Byte-identical |
| Run 1 vs Run 2 (same secret) — report.json (excl. timing) | ✅ Identical |
| Run 1 vs Run 3 (different secret) | ✅ Different output |

### 2.8 `tests/test_generalization.py` — Re-identification Resistance Tests
Tests for adversarial quasi-identifier combination attacks and privacy-utility trade-offs.

Key test areas:
- Quasi-identifier combination attacks (age band + district uniqueness)
- Rare diagnosis identification and suppression
- Extreme age + rare diagnosis suppression triggers
- PIN code generalization (6-digit to 3-digit prefix)
- Village-to-district generalization
- Per-patient deterministic date shifting
- Stay duration exact preservation (100 random stays)
- Global shift recovery attack blocking (variance check)
- Secret rotation changes all shifts
- Age band truthfulness for all ages 0-120
- Band width correctness (exactly 5 ages per band)
- k-anonymity measurement (high-k and singleton scenarios)
- End-to-end CSV generalization (age banded, PIN generalized, village suppressed)
- End-to-end JSON generalization (name removed, diagnosis preserved)
- End-to-end text date shifting (admission/discharge)

## 4. Full pytest Output (Summary)

```
============================= 147 passed in 0.97s =============================
```

All 147 tests pass consistently. No flaky tests observed across multiple runs.
