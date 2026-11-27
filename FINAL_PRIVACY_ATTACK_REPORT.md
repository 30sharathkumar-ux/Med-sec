# RAKSHA Phase 4 — Final Privacy Attack Report (A1–A7)

## Scope

Evaluates RAKSHA against the 7 Secret Wards attack categories (`docs/ATTACKS.md`) on the dev dataset (`dev/input/`, 200 files, 816 records, 52 resolved patient profiles) using `artifacts/optimization/sim_attacker.py`, `check_dev.py`, and the `tests/test_adversarial*.py` suites.

## Results Summary

| Attack | Category | Phase 3 | Phase 4 | Evidence |
|--------|----------|---------|---------|----------|
| **A1** | Direct PII Exposure | 0/240 registry hits; 0/3,230 truth leaks | **0/240 registry hits; 0/3,230 truth leaks** | `check_dev.py`, `sim_attacker.py` |
| **A2/A3** | Quasi-Identifier Linkage | Mean 1/\|C\| = 0.3082 | **Mean 1/\|C\| = 0.0337** (−89.1%) | `sim_attacker.py` |
| **A4** | Profile Aggregation Re-ID | 17/52 (32.7%) | **0/52 (0.0%)** (−100%) | `sim_attacker.py` |
| **A5** | Temporal / Known-Date Attacks | 6 coincidental date hits; 0 unbanded ages | **6 coincidental date hits; 0 unbanded ages** | `sim_attacker.py`, date inspection |
| **A6** | Pseudonym Inversion | 0/10,800 unkeyed inversions | **0/10,800 unkeyed inversions** | HMAC-SHA256 keyed |
| **A7** | Cross-Release Linkability | 0/52 cross-secret overlap | **0/52 cross-secret overlap** | `sim_attacker.py`, `test_adversarial_a7.py` |

## Key Phase 4 Hardening

1. **Free-text double-banding fix (`rakshak/privacy/transforms.py`)**: Added negative lookbehind `(?<![-\d])` to `_FREE_TEXT_AGE_UNIT_RE` so 20-year bands like `40-59 Yrs/M` are never re-banded into `40-40-59 Yrs/M`, eliminating 7 unique/confident re-identifications.
2. **Tier 3 adaptive district suppression (`rakshak/privacy/k_anonymity.py`, `rakshak/cli.py`)**: Profiles remaining in equivalence classes smaller than `min_group_size` after 20-year banding and PIN suppression now have their district replaced with `[DISTRICT]` in both CSV and JSON outputs, eliminating all remaining 13 confident re-identifications (`0/52`).
3. **A5 date analysis**: All 6 date hits in `sim_attacker.py` (`fhir/bundle_2b7ec3cf.json`, `fhir/bundle_c815a19e.json`, `lab/bulk_lab_export.json`) are coincidental collisions among 302 shifted output dates and 18 known dates (expected random overlap ~14.9).
