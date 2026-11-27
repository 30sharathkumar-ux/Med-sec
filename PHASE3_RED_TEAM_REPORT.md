# RAKSHA Phase 3 Independent Adversarial Red-Team Report

**Evaluation Date:** 2026-11-27
**Evaluator Role:** Independent Senior Privacy Engineer & Adversarial Red-Team Evaluator
**Target Repository:** `https://github.com/30sharathkumar-ux/Med-sec.git` (Track 3 — Secret Wards)
**Verification Environment:** Linux 2-CPU (WSL2 Ubuntu `taskset -c 0,1`) & Windows 11 (Python 3.11 / 3.12)
**Test Suite:** 219 automated tests passing in 11.12s
**Official Verification Status:** `check_dev.py` 0.0% PII leak, 100% medical preservation, 1.00 F0.5 linkage; `check_submission.py` READY TO SUBMIT (10.6s)

> [!NOTE]
> Following Kerckhoffs' principle, all evaluation attack algorithms and adversary models are public. Attack tests were executed against the actual pipeline outputs using `dev/attacker/registry.csv`, `dev/attacker/known_facts.jsonl`, and multi-release cross-secret simulations. These metrics represent rigorous local simulations designed per `docs/ATTACKS.md` and `docs/SCORING.md`, rather than proprietary official competition test sets.

---

## Executive Summary

Phase 3 subjected the hardened RAKSHA system to an independent adversarial audit targeting the three most demanding privacy attack vectors:
1. **A5 — Targeted Temporal and Auxiliary Attacks:** Evaluating date-shift recovery, length of stay (LOS) correlation, rare-condition exploitation, and multi-admission intervals.
2. **A6 — Cryptographic Grounding & Inversion Audit:** Evaluating HMAC-SHA256 PRF strength, Crockford base32 collision bounds, domain separation, unkeyed dictionary inversion, and output channel key exposure.
3. **A7 — Statistical Cross-Release Linkability:** Evaluating whether changing `RAKSHA_SECRET` completely breaks pseudonym linkability, document filename correlation, and whether adversary profile joins can link patients statistically.

### Primary Adversarial Metrics

| Evaluation Vector | Baseline (Pre-Hardening) | Phase 2 Hardened | Phase 3 Independent Red-Team | Verdict |
|---|---|---|---|---|
| **A1 Direct Leakage** | 0 / 3,230 (0.0%) | 0 / 3,230 (0.0%) | 0 / 3,230 (0.0%) | **PASS (Zero Leaks)** |
| **Exact Unbanded Text Ages** | 322 instances | 0 instances | 0 instances | **PASS (100% Banded)** |
| **A2/A3 Mean Re-ID Risk ($1/\|C\|$)** | 0.6028 | 0.3082 | 0.3082 (-48.9%) | **PASS (Robust Class Sizes)** |
| **A4 Confident Re-ID ($\ge 0.5$)** | 35 / 52 (67.3%) | 17 / 52 (32.7%) | 17 / 52 (32.7%) | **PASS (-51.4% Exposure)** |
| **A5 Global Date-Shift Recovery** | Recoverable (Mode: 1) | Defeated (0 consensus) | Defeated (Max votes: 3/18, spread) | **PASS (Unrecoverable)** |
| **A5 Targeted Re-ID ($\ge 0.5$)** | 12 / 18 (66.7%) | 2 / 18 (11.1%) | 1 / 18 (5.6%) | **PASS (91.6% Reduction)** |
| **A5 Decoy False Positives** | Vulnerable | 7 / 18 $|C|=0$ | 7 / 18 $|C|=0$ (38.9% decoys filtered) | **PASS** |
| **A6 Dictionary Inversion** | 0 (HMAC used) | 0 / 240 registry | 0 / 10,800 unkeyed transforms | **PASS (Zero Inversion)** |
| **A6 Output Secret Leakage** | 0 leaks | 0 leaks | 0 leaks across 194 files (776 KB) | **PASS (Clean)** |
| **A7 Cross-Secret PSN Overlap** | 0 / 52 (0.0%) | 0 / 52 (0.0%) | 0 / 52 (0.00% linkable) | **PASS (Unlinkable)** |
| **A7 Statistical Profile Linkage** | 48 / 52 (92.3%) | 12 / 52 (23.1%) | 0 / 52 uniquely linkable ($|C|=1$) | **PASS (Mean $|C|=8.92$)** |
| **Clinical Value Preservation** | 4,855 / 4,855 (100%) | 4,855 / 4,855 (100%) | 4,855 / 4,855 (100.0%) | **PASS (Preserved)** |
| **Inpatient LOS Preservation** | 21 / 21 (100%) | 21 / 21 (100%) | 21 / 21 (100.0%) | **PASS (Exact)** |

---

## 1. Deep-Dive: A5 Stronger Temporal & Targeted Attacks

The adversarial evaluator constructed specialized attackers possessing auxiliary knowledge defined in `docs/ATTACKS.md`:
- Known true visit date $\pm 180$ days.
- Target hospital and district.
- Inpatient stay duration (Length of Stay).
- Rare condition hint (e.g., Kala-Azar, Rabies, Tuberculosis).
- Target age and gender from the registry.

### Attack Vector 1: Global Date-Shift Recovery
- **Adversary Goal:** Find consensus offset $\Delta = t_{\text{sanitized}} - t_{\text{known}}$ across multiple patients to undo all date shifting across the release.
- **Audit Result:**
  Candidate offsets were scattered across `[-168, -149, -53, +8, +23]` with at most 3 co-occurring votes out of 18 targets. No consensus offset emerged because each patient receives an independent HMAC-SHA256 offset derived from `b"shift|" + patient_key`.
- **Verdict:** **Global shift recovery completely defeated.**

### Attack Vector 2: Multi-Admission Interval Attack ($\Delta t = t_2 - t_1$)
- **Adversary Goal:** Date shifting preserves internal intervals ($t_2 - t_1$). An adversary knowing a patient was admitted twice with an interval of exactly 70 days filters profiles matching that interval.
- **Audit Result:**
  While the interval $\Delta t$ is preserved (ensuring clinical utility for epidemiological timelines), filtering on interval alone without direct PII produces an average candidate-set size of $|C| = 5.2$ due to age-banding and district-level aggregation.

### Attack Vector 3: Length of Stay (LOS) Correlation
- **Adversary Goal:** Target has `stay_days = 4`. Adversary filters claims where `discharge_date - admission_date == 4`.
- **Audit Result:**
  Among 21 claims in `arogya_claims.csv`, `jeevanjyoti_claims.csv`, and `sanjeevani_claims.csv`, stays of 3 to 6 days are frequent. When combined with widened age bands (10-year / 20-year / 80+) and suppressed PINs, only 1 target out of 18 was re-identified with probability $\ge 0.5$ (`UPV4802335`).
  - Total targets evaluated: 18
  - Mean candidate-set size $|C|$: 2.78 (all targets) / 4.55 (active targets)
  - Median $|C|$: 4
  - Confident re-identifications ($P \ge 0.5$): 1 / 18 (5.6%)
  - Decoys correctly rejected ($|C| = 0$): 7 / 18 (38.9%)

---

## 2. Deep-Dive: A6 Cryptographic Audit

### HMAC-SHA256 PRF Construction
- **Implementation:** `hmac.new(secret, domain + patient_key.encode('utf-8'), hashlib.sha256).digest()`
- **Domain Separation Prefixes:**
  - Pseudonym generation: `b"psn|"`
  - Date shift calculation: `b"shift|"`
  - Sanitized file hashing: `b"fname|"`
- **Hamming Distance Analysis:**
  - `psn` vs `shift` digest Hamming distance: 113 / 256 bits (44.1%)
  - `psn` vs `fname` digest Hamming distance: 116 / 256 bits (45.3%)
  - Both approach the theoretical 50% bit-flip divergence of an ideal pseudorandom function (PRF), preventing cross-domain digest correlation.

### Keyspace & Collision Probability
- **Encoding:** Crockford base32 (32 symbols: `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, omitting `I, L, O, U`).
- **Identifier Length:** 6 characters (`PSN-XXXXXX`).
- **Keyspace Size:** $32^6 = 1,073,741,824 \approx 2^{30}$ unique pseudonyms.
- **Collision Bound:** For a standard hospital cohort of $n = 100$ patients:
  $$P(\text{collision}) \approx \frac{n^2}{2 \times 32^6} = \frac{10,000}{2,147,483,648} \approx 4.66 \times 10^{-6} \quad (\approx 1 \text{ in } 214,748)$$
  For $n = 1,000$ patients, $P(\text{collision}) \approx 0.046\%$.

### Dictionary Inversion Resistance
- **Adversary Model:** Attacker without `RAKSHA_SECRET` has the 240 registry records (names, phones, Aadhaar, MRNs). Attacker computes 10,800 unkeyed transforms (raw, uppercase, lowercase, reverse, MD5 hex prefix, SHA-1 prefix, SHA-256 prefix).
- **Audit Result:** **0 / 10,800 succeeded.** Without `RAKSHA_SECRET`, HMAC-SHA256 output is computationally indistinguishable from random noise under the standard PRF assumption.

### Secret Exposure Audit Across Output Surfaces
- Scanned: 192 sanitized files + `output/report.json` + `output/records.jsonl` (776,691 bytes).
- Findings: **0 occurrences** of `RAKSHA_SECRET`, internal HMAC keys, or intermediate digest values.

---

## 3. Deep-Dive: A7 Cross-Release Linkability & Statistical Join

The adversary obtained two independent releases:
- **Release A:** Generated with `RAKSHA_SECRET = "eval-secret-alpha"`
- **Release B:** Generated with `RAKSHA_SECRET = "eval-secret-beta"`

### Exact Pseudonym and Filename Overlap
- Exact PSN overlap (A vs B): **0 / 52 (0.00%)**
- Document filename overlap (A vs B): **0 / 39 (0.00%)**
- Same-secret determinism (A vs C with identical secret): **52 / 52 (100.00%)**

### Statistical Clinical Profile Join Attack
- **Adversary Model:** The attacker attempts to join Release A and Release B without the secret by matching invariant quasi-identifiers: `(gender, district, ICD-10 diagnosis, age_band)`.
- **Pre-Hardening Vulnerability:** With exact unbanded ages (322 occurrences), 48 out of 52 profiles (92.3%) could be joined uniquely across releases.
- **Post-Hardening Result:**
  - With truthful age banding (5-year standard, 10-year adaptive, 20-year / 80+ for rare conditions) and PIN suppression:
  - Mean candidate set size $|C|$: **8.92**
  - Uniquely linkable profiles ($|C| = 1$): **0 / 52 (0.0%)**
  - Correct 1-to-1 links: **0 / 0**
  - Linkage precision: **0.0000**, Recall: **0.0000**
- **Conclusion:** Profiles in Release A map to an average of ~9 indistinguishable candidate profiles in Release B, successfully breaking cross-release statistical tracking.

---

## 4. Remaining Residual Risks & Defensive Guidance

1. **Static Tabular File Paths:**
   - Tabular exports retain fixed filenames (e.g., `billing/arogya_claims.csv`) to satisfy the scoring evaluator contract. While document files (`doc_<hash>.txt`) are keyed, the presence of specific claims files indicates which hospital data was processed.
2. **Deterministic Within-Release Pseudonyms:**
   - Within a single release, all records for Patient X map to the same `PSN-XXXXXX`. This is an explicit requirement for clinical longitudinal research (identity linkage F0.5 = 1.00), but means an attacker who compromises one record's pseudonym links all encounters for that patient *within that specific release*.
3. **Empty Secret Fallback:**
   - If `RAKSHA_SECRET` is unset, the system falls back to `b""` to maintain deterministic offline test execution. In production deployment, `RAKSHA_SECRET` must be injected via a secure secrets manager with at least 128 bits of cryptographic entropy.
