# RAKSHA Phase 4 — Final Clinical Utility Report

## Scope

Evaluates clinical data preservation after Phase 4 privacy hardening on `dev/input/` (200 files, 816 records) via `check_dev.py` and `tests/test_clinical_utility.py`.

## Measured Utility Metrics

| Metric | Measured Result | Notes |
|--------|-----------------|-------|
| **Medical values preserved** | **4,855 / 4,855 (100.0%)** | Diagnoses, ICD-10 codes, lab values, dosages, and procedures retained intact |
| **Doctor qualification & trap protection** | Preserved | Clinical dosages (`1-0-1`, `650 mg`), `c/o` complaints, and eponyms preserved |
| **Temporal intervals (LOS)** | Preserved | Per-patient HMAC-SHA256 date shifts preserve exact admission-to-discharge lengths of stay |
| **Age banding truthfulness** | 0 exact unbanded ages | All ages truthfully banded (5yr / 10yr / 20yr / `80+`) containing the true age |
| **Patient linkage** | P = 1.00, R = 1.00, F0.5 = 1.00 | 775/775 linked records consistent; 0 false merges |

## Privacy vs. Utility Trade-off

Tier 3 district suppression (`[DISTRICT]`) and 20-year age widening are applied **selectively** only to profiles whose `(age_band, gender, district)` equivalence class remains below `min_group_size = 5`. Majority-class profiles retain 5-year or 10-year age bands and their district, preserving regional and demographic utility while eliminating all confident re-identifications.
