# RAKSHA — Phase 2 Before & After Results

**Date:** 2026-11-27
**Dataset:** `dev/input` (`200` files, `48` ground-truth patients, `4` canaries, `4,855` medical probes)
**Honest Score Assessment:** On official practice checks, RAKSHA achieves `0/3230` leaks, `0/4` canaries, `4855/4855` medical values (`100.0%`), `P=1.00 / R=1.00 / F0.5=1.00`, `CONTRACT OK`, and `READY TO SUBMIT`. Because `raksha_eval` is not bundled locally, an exact official `90–94/100` score cannot be claimed from local runs; local A1–A7 simulations confirm strong reductions in A2–A5 linkage risk while preserving `100.0%` clinical probes.

| Metric | Baseline | Phase 2 Result | Source |
|---|---:|---:|---|
| **Exact Unbanded Ages** | `322` | **`0`** | `sim_attacker.py` |
| **A2/A3 Mean `1/\|C\|` Risk** | `0.6028` | **`0.3082`** | `sim_attacker.py` |
| **A4 Confident Re-ID (`>=0.5`)** | `35/52 (67.31%)` | **`17/52 (32.69%)`** | `sim_attacker.py` |
| **A5 LOS & Chronology** | `21/21` | **`21/21 (100.0%)`** | `phase2_eval.py` |
| **A6 Dictionary Inversions** | `0` | **`0`** | `phase2_eval.py` |
| **A7 Cross-Secret PSN Overlap** | `0/53` | **`0/53`** | `phase2_eval.py` |
| **Age Generalization Utility** | `0.6069` | **`0.6341`** | `phase2_eval.py` |
| **Medical Values Kept** | `4,855 / 4,855 (100.0%)` | **`4,855 / 4,855 (100.0%)`** | `check_dev.py` |
| **PII Leaked / Canaries** | `0 / 3,230` / `0 / 4` | **`0 / 3,230` / `0 / 4`** | `check_dev.py` |
| **Identity Linkage (P/R/F0.5)** | `1.00 / 1.00 / 1.00` | **`1.00 / 1.00 / 1.00`** | `check_dev.py` |

## Changed Files
- `rakshak/privacy/transforms.py` — `band_free_text_ages()` with `80+` cap for widened senior bands.
- `rakshak/privacy/k_anonymity.py` — `compute_adaptive_profile_policies()` with selective `10`-yr vs `20`-yr / `80+` escalation and multi-level `suppress_pin()`.
- `rakshak/cli.py` — Rare-condition extraction, `age_sex` banding, adaptive profile policy wiring, and measured `privacy.k_anonymity` reporting.
- `tests/test_adversarial_a5.py`, `tests/test_adversarial_a6.py`, `tests/test_adversarial_a7.py`, `tests/test_clinical_utility.py` — Dedicated A5, A6, A7, and clinical utility suites.
- `PRIVACY_ATTACK_AUDIT.md`, `CLINICAL_UTILITY_REPORT.md`, `BEFORE_AFTER_RESULTS.md` — Phase 2 audit and measurement reports.
