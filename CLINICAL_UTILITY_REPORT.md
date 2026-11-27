# RAKSHA — Clinical Utility Optimization Report

**Date:** 2026-11-27
**Dataset:** `dev/input` (`200` files, `4,855` official medical probes, `21` admission/discharge LOS pairs)

---

## 1. Clinical Attribute Preservation

| Clinical Attribute | Result | Evidence |
|---|---|---|
| **Official Medical Probes (`check_dev.py`)** | **`4,855 / 4,855 (100.0%)`** | `check_dev.py` (Windows & WSL2 `taskset -c 0,1`) |
| **Diagnoses & ICD-10 Codes** | Preserved intact (including `Parkinson's disease (G20)`, `E11.9`) | `check_dev.py`, `test_clinical_utility.py` |
| **Medications & Dosages** | Preserved intact (`Ramipril 5mg`, `Dolo 650 BD x 5 days`, `1-0-1`) | `check_dev.py`, `test_adversarial_a5.py`, `test_clinical_utility.py` |
| **Doctor Credentials & Qualifications** | Preserved (`Dr. Ramesh Srivastava (MD Medicine)`, `Dr. Anil Kumar MD Cardiology`) | `check_dev.py`, `test_doctor_qualifications.py` |
| **Admission/Discharge Chronology & LOS** | **`21 / 21 (100.0%)`** exact LOS & `discharge >= admission` preserved | `phase2_eval.py`, `test_adversarial_a5.py` |
| **FHIR R4 Structure & Codes** | `Bundle` structure, `LOINC`, `ICD-10`, and `valueQuantity` preserved | `test_fhir_validation.py`, `test_clinical_utility.py` |
| **Record Retention** | `816 / 816` processed records emitted in `records.jsonl` (`0` dropped) | `report.json`, `validate_output.py` |

## 2. Joint Privacy–Utility Tradeoff (Age Generalization)

- **Baseline (`k_anonymity` v1):** All `53` profiles were widened to `20`-year bands (`371` mentions at width `20`), yielding `mean_age_generalization_score = 0.6069`.
- **Selective Optimization (`k_anonymity` v2 + Rare-Condition Detection):**
  - Only extreme-age (`>=80` or `<5`), rare-condition (`<= 2` patients), or singleton `(10yr_band, gender, district)` profiles escalate to `20`-year / `80+` + `[PIN]`.
  - Multi-member profiles retain `10`-year bands (`53` mentions at width `10`), raising `mean_age_generalization_score` from **`0.6069` → `0.6341`** while preserving **`4,855 / 4,855 (100.0%)`** medical values and **`21 / 21`** exact LOS intervals.
