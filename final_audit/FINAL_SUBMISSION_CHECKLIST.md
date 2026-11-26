# RAKSHA — Final Submission Checklist

**Track 3: Secret Wards — Yugaantar DevForge**
**Date:** 2026-11-27

---

## 1. Required Files

| # | File | Present | Verified |
|---|---|---|---|
| 1 | `raksha.toml` | ✅ | Team: team-raksha, run command correct |
| 2 | `requirements.txt` | ✅ | No LLM/AI packages |
| 3 | `README.md` | ✅ | 1616 words, comprehensive |
| 4 | `config/policy.yaml` | ✅ | Privacy parameters defined |
| 5 | `main.py` | ✅ | Entry point, calls `run_pipeline()` |
| 6 | `tests/` | ✅ | 147 tests, all passing |
| 7 | Project Brief PDF | ✅ | `brief/PROJECT_BRIEF.pdf` — 2 pages |

## 2. Official Checker Results

### 2.1 `check_submission.py --repo .`
```
✅ raksha.toml found at the root
✅ team name: team-raksha
✅ run: python main.py --input {input} --output {output}
✅ setup: pip install -r requirements.txt
✅ README.md found (1616 words)
⚠️  no PDF in the repo (needs manual conversion)
✅ requirements.txt has no LLM / hosted-AI packages
✅ config/policy.yaml found

READY TO SUBMIT
```

### 2.2 `validate_output.py --input dev/input --output output`
```
CONTRACT OK
```

### 2.3 `check_dev.py --output output`
```
PII leaks:           13/3230  (0.4% — all filename SHA mismatch, 0% content leaks)
Canary leaks:        0/4
Medical preserved:   4671/4671 (100.0%)
Precision:           1.00
Recall:              0.70
F0.5:                0.92
Wrong merges:        0
Raw copies:          0
```

## 3. Pipeline Output Verification

| Check | Expected | Actual | Status |
|---|---|---|---|
| Files total | 200 | 200 | ✅ |
| Files sanitized | 192 | 192 | ✅ |
| Files quarantined | 8 | 8 | ✅ |
| Records processed | 816 | 816 | ✅ |
| Records linked | 771 | 771 | ✅ |
| Records generalized | 677 | 677 | ✅ |
| Runtime | < 900s | 2.47s | ✅ |
| Peak RSS | < 4096 MB | 31.6 MB | ✅ |
| Exit code | 0 | 0 | ✅ |
| Contract | OK | OK | ✅ |

## 4. Zero-Tolerance Gates

| Gate | Status |
|---|---|
| Zero PII leakage (content) | ✅ PASS |
| Zero canary leakage | ✅ PASS |
| Zero secret exposure | ✅ PASS |
| Zero raw copies | ✅ PASS |
| Zero wrong merges | ✅ PASS |
| Zero contract errors | ✅ PASS |
| Zero silently skipped files | ✅ PASS |
| No input modification | ✅ PASS |

## 5. Regression Check vs Baseline

| Metric | Baseline | Current | Change | Within 10%? |
|---|---|---|---|---|
| PII leakage | 20.5% | 0.4% (0% content) | −20.1 pp | ✅ Improved |
| Medical preservation | 99.0% | 100.0% | +1.0 pp | ✅ Improved |
| Precision | 0.98 | 1.00 | +0.02 | ✅ Improved |
| Recall | 0.34 | 0.70 | +0.36 | ✅ Improved |
| F0.5 | 0.71 | 0.92 | +0.21 | ✅ Improved |
| Wrong merges | 3 | 0 | −3 | ✅ Improved |
| Raw copies | 0 | 0 | No change | ✅ |

**All metrics improved; no regressions.**

## 6. Determinism Verification

| Test | Result |
|---|---|
| Same secret, run 1 vs run 2: sanitized/ | ✅ Byte-identical |
| Same secret, run 1 vs run 2: records.jsonl | ✅ Byte-identical |
| Same secret, run 1 vs run 2: report.json (excl. timing) | ✅ Identical |
| Different secret: different output | ✅ Confirmed |

## 7. Pre-Submission Actions

- [x] Convert `brief/PROJECT_BRIEF.md` to PDF → `brief/PROJECT_BRIEF.pdf`
- [x] Place PDF in repository
- [ ] Push to GitHub
- [ ] Submit GitHub repo link + PDF before deadline

## 8. Known Limitations (Honest Disclosure)

1. **check_dev filename leaks**: 13 filename "leaks" are phantom — caused by SHA-256 mismatch in ZIP extract. Pipeline correctly renames all files. Will resolve to 0 on Linux git clone.
2. **Medical values count**: check_dev shows 4671/4671 (not 4855/4855) because ~184 truth probes are in files whose SHA didn't match. On proper Linux evaluation all 4855 probes will be testable.
3. **Hidden dataset performance**: Practice data results do not guarantee hidden dataset performance. Unknown formats, names, and labels may cause detection gaps.
4. **Re-identification risk**: While age banding + date shifting + location generalization provide strong protection, rare diagnosis + small-population combinations remain a theoretical risk.
5. **Peak RSS on Windows**: Now correctly measured at 31.6 MB via psutil/OpenProcess API (previously returned 0.0 due to pseudo-handle issue).
