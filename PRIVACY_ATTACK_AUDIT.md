# RAKSHA — Phase 2 Privacy Attack Audit (A1–A7 & Clinical Utility)

**Date:** 2026-11-27
**Repository:** `https://github.com/30sharathkumar-ux/Med-sec`
**Evaluation Boundary:** The organizer's `raksha_eval` package is **not** bundled locally. Official metrics come from `check_dev.py`, `validate_output.py`, and `check_submission.py`. A1–A7 attack metrics below are from local simulations ([sim_attacker.py](file:///d:/RAKSHA/artifacts/optimization/sim_attacker.py), [phase2_eval.py](file:///d:/RAKSHA/artifacts/optimization/phase2_eval.py)) and are explicitly labeled as simulations, not official `raksha_eval` scores.

---

## 1. Phase 2 Evaluation Matrix (Required)

| Evaluation | Baseline | New Result | Test Type | Evidence |
|---|---:|---:|---|---|
| **A5 date-shift recovery** | `3/18` max offset votes (`0` global recovery) | **`3/18` max offset votes (`0` global recovery); `0` unshifted dates** | Simulation | `phase2_eval.py`, `tests/test_adversarial_a5.py` |
| **A5 rare-profile linkage** | `14/14` rare profiles (`322` unbanded ages) | **`14/14` rare profiles (`0` unbanded ages; `80+` & `[PIN]` enforced)** | Simulation | `phase2_eval.py`, `tests/test_adversarial_a5.py` |
| **A6 pseudonym inversion** | `0` dictionary inversions; 3 distinct HMAC domains | **`0` dictionary inversions; 3 distinct HMAC domains; `0` secret leaks** | Simulation / cryptographic review | `phase2_eval.py`, `tests/test_adversarial_a6.py` |
| **A7 exact pseudonym linkage** | `0/53` cross-secret overlap; `53/53` same-key match | **`0/53` cross-secret overlap; `53/53` same-key match; `0` filename overlap** | Simulation / contract | `phase2_eval.py`, `tests/test_adversarial_a7.py` |
| **A7 profile linkage** | `48/52` statistical signature matches | **`48/52` statistical signature matches** (disclosed: diagnoses+district preserved) | Simulation | `phase2_eval.py` |
| **Clinical preservation** | `4,855 / 4,855 (100.0%)` (`0.6069` age gen score) | **`4,855 / 4,855 (100.0%)` (`0.6341` age gen score)** | Official clinical probes | `check_dev.py`, `tests/test_clinical_utility.py` |
| **Temporal consistency** | `21/21` LOS preserved | **`21/21 (100.0%)` LOS & chronology preserved** | Regression | `phase2_eval.py`, `tests/test_adversarial_a5.py` |
| **Runtime** | `7.05s` (Windows) / `11.6s` (WSL2 3-run) | **`7.05s` (Windows) / `11.6s` (WSL2 3-run)** | Benchmark | `report.json`, `check_submission.py` |
| **Peak memory** | `31.1 MB` | **`31.1 MB`** | Benchmark | `report.json` |

---

## 2. Attack-by-Attack Summary (A1–A7)

| Attack | Baseline Result | Improved Result | Evidence | Remaining Risk |
|---|---|---|---|---|
| **A1** | `0/240` reg hits; `0/3230` PII | `0/240` reg hits; `0/3230` PII; `0/4` canaries | `check_dev.py`, `sim_attacker.py` | Unseen regional names without context |
| **A2** | `0.6028` mean `1/\|C\|` risk | **`0.3082`** mean `1/\|C\|` risk (**−48.9%**) | `sim_attacker.py` | Small cells when `district` is preserved |
| **A3** | `322` exact unbanded ages | **`0`** exact unbanded ages | `sim_attacker.py`, `cli.py` | Unlabeled free-text age mentions |
| **A4** | `35/52 (0.6731)` confident re-ID | **`17/52 (0.3269)`** confident re-ID (**−51.4%**) | `sim_attacker.py` | Multi-record clinical profiles with rare conditions |
| **A5** | `0` unshifted dates; exact senior ages (`91–97`) | `0` unshifted dates; `80+` + `[PIN]` on rare/senior; `21/21` LOS | `phase2_eval.py`, `test_adversarial_a5.py` | Rare diagnosis + `district` + `80+` |
| **A6** | `0` inversions; `psn\|`/`shift\|`/`fname\|` | `0` inversions; `psn\|`/`shift\|`/`fname\|` | `phase2_eval.py`, `test_adversarial_a6.py` | Requires keeping `RAKSHA_SECRET` confidential |
| **A7** | `0/53` cross-secret PSN overlap | `0/53` cross-secret PSN & filename overlap; `53/53` same-secret | `phase2_eval.py`, `test_adversarial_a7.py` | Statistical profile correlation (`48/52`) via preserved conditions |

---

## 3. Reproducible Verification Commands

```bash
RAKSHA_SECRET=practice python -m pytest tests/ -q
RAKSHA_SECRET=practice python main.py --input dev/input --output output
python validate_output.py --input dev/input --output output
python check_dev.py --output output --truth dev/truth/truth.json
python check_submission.py --repo . --run
python artifacts/optimization/sim_attacker.py
python artifacts/optimization/phase2_eval.py
```
