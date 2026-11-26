# RAKSHA Optimization Final Scorecard

## Baseline vs Final (Measured on `dev/input` in WSL2 Ubuntu & Windows)

| Metric | Frozen Baseline | Final Measured | Delta |
|---|---:|---:|---:|
| **PII Leaked** | `0 / 3230 (0.0%)` | `0 / 3230 (0.0%)` | Maintained |
| **Canaries Leaked** | `0 / 4` | `0 / 4` | Maintained |
| **Medical Data Kept** | `4854 / 4855 (100.0%)` | `4854 / 4855 (100.0%)` | Maintained |
| **Linkage Precision** | `1.00` | `1.00` | Maintained |
| **Linkage Recall** | `0.72` | **`0.99`** | **+0.27** |
| **Linkage F0.5** | `0.93` | **`1.00`** | **+0.07** |
| **Wrong Merges** | `0` | `0` | Maintained |
| **Raw Copies** | `0` | `0` | Maintained |
| **Unit & Red-Team Tests** | `151 passed` | **`190 passed`** | **+39 tests** |
| **Linux `check_submission.py`** | `READY TO SUBMIT` | `READY TO SUBMIT` (`12.1s`) | Verified |
| **Linux `validate_output.py`** | `CONTRACT OK` | `CONTRACT OK` | Verified |

## Key Engineering Improvements Implemented

1. **Cryptographic Domain Separation (`rakshak/privacy/pseudonymize.py`)**
   - Added explicit `b"psn|"` domain prefix to `generate_pseudonym` HMAC-SHA256 input, separating pseudonym derivation from date shifting (`b"shift|"`) and filename tagging (`b"fname|"`).
2. **Identity Resolution Recall (`rakshak/linkage/resolver.py`)** — **0.72 → 0.99 recall, 1.00 precision, 0 wrong merges**
   - Fixed `_MRN_KEYS` so `Registration Date` is never misclassified as an MRN.
   - Added `age_sex` (e.g. `65/F`) parsing in `extract_evidence_csv`.
   - Replaced hardcoded MRN hospital map with dynamic `extract_issuer_prefix()` (`[A-Z]{2,6}[-/]`, excluding generic ID prefixes) so any unseen hospital prefix (`KGMU-`, `APO/`, `MED-`, etc.) groups cleanly across external lab exports.
   - Used phonetic keys when checking distinct-name collision guards so cross-script / spelling variants (`Rina Nishad`, `Reena Nishad`, `रीना निषाद`) don't abort valid MRN merges.
   - Added DOB↔age cross-matching (`_age_from_dob`), single-token phonetic name matching, and `<Name>, W/o <Relative>` note extraction.
3. **Post-Linkage k-Anonymity Module (`rakshak/privacy/k_anonymity.py`)**
   - Added equivalence-class analysis, risk scoring, age-band widening, and PIN suppression helpers, wired into `report.json` privacy metrics.
4. **FHIR R4 Structural Validation (`rakshak/privacy/fhir_validator.py`)**
   - Added structural validation for FHIR `Bundle` and `Patient` resources at ingest and export.
5. **Attacker Simulation & Regression Suite**
   - Added 39 new tests across `test_domain_separation.py`, `test_k_anonymity.py`, `test_fhir_validation.py`, `test_attacker_simulation.py`, and `test_identity_recall.py`.
