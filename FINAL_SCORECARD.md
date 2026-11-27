# RAKSHA Phase 4 — Final Scorecard

## Measured Results (Phase 4, dev dataset)

| # | Category | Weight | Measured Evidence | Estimated Score | Points |
|---|----------|--------|-------------------|-----------------|--------|
| 1 | PII Detection | 20% | 0/3,230 leaked (0.0%), 0/4 canaries, all languages covered | ~0.99 | ~19.8 |
| 2 | Identity Resolution | 15% | P=1.00, R=1.00, F0.5=1.00, 0 false merges | ~0.96 | ~14.3 |
| 3 | Privacy Attack Resistance | 25% | A1=0, A2/A3=0.034, A4=0/52, A5=coincidental, A6/A7=0 | ~0.93 | ~23.2 |
| 4 | Clinical Utility | 20% | 4,855/4,855 medical (100%), intervals preserved | ~0.92 | ~18.3 |
| 5 | Data Integrity | 10% | CONTRACT OK, 192 sanitized + 8 quarantined, PSN 100% consistent | ~0.94 | ~9.4 |
| 6 | Performance | 10% | 14.7s / 2-CPU, ~31MB RAM, deterministic, secret-keyed | 1.00 | 10.0 |
| | **Total** | | | | **~95.0** |
| | Penalties | | 0 leaked direct IDs, 0 canaries, 0 raw copies | | **0** |

## Privacy Attack Resistance Detail

| Attack | Weight | Phase 3 | Phase 4 | Evidence |
|--------|--------|---------|---------|----------|
| A1 Direct exposure | 0.20 | 0/240 | 0/240 | No names or phones in sanitized output |
| A2/A3 Linkage risk | 0.20 | 0.3082 | **0.0337** | Sweeney-style registry filtering |
| A4 Profile aggregation | 0.20 | 17/52 (32.7%) | **0/52 (0.0%)** | No confident re-identification |
| A5 Temporal attacks | 0.20 | 6 date hits | 6 date hits | Coincidental collisions only |
| A6 Pseudonym inversion | 0.10 | 0/10,800 | 0/10,800 | HMAC-SHA256 keyed |
| A7 Cross-release linkage | 0.10 | 0/52 | 0/52 | Different secrets → different pseudonyms |

## Before/After Comparison (Full History)

| Metric | Phase 1 | Phase 2 | Phase 3 | **Phase 4** |
|--------|---------|---------|---------|-------------|
| Exact unbanded ages | 322 | 0 | 0 | **0** |
| A2/A3 linkage risk | 0.6028 | 0.3082 | 0.3082 | **0.0337** |
| A4 confident re-id | 35/52 | 15/52 | 17/52 | **0/52** |
| A5 date hits | N/A | 6 | 6 | **6 (coincidental)** |
| Medical values | 4,855 | 4,855 | 4,855 | **4,855** |
| PII leaked | 0 | 0 | 0 | **0** |
| Tests passing | 205 | 219 | 219 | **219** |

## Validation Commands (Reproducible)

```bash
# Set up
export RAKSHA_SECRET=practice

# Pipeline
python main.py --input dev/input --output output

# Self-check
python check_dev.py --output output --truth dev/truth/truth.json

# Contract validation
python validate_output.py --input dev/input --output output

# Attack simulation
python artifacts/optimization/sim_attacker.py

# Test suite
python -m pytest tests/ -q

# Submission check (Linux, 2-CPU)
taskset -c 0,1 python3 check_submission.py --repo . --run
```
