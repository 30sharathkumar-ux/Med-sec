# RAKSHA — Competition Scorecard (Out of 100)

| # | Category | Weight | Tests Executed | Passed | Failed | Not Verified | Conservative Score | Evidence |
|---|---|---|---|---|---|---|---|---|
| 1 | **Privacy Against Attacks** | 25 | 5 (`SEC-01..03`, `PRIV-01`, `check_dev` canaries/raw) | 5 | 0 | `anonymeter`, `pycanon` | **21 / 25** | `0/4` practice canaries, `0` raw copies, deterministic HMAC, secret rotation verified; `anonymeter`/`pycanon` not installed. |
| 2 | **Personal Data Detection** | 20 | 22 (`CANARY-*` + `check_dev` 3230 entities) | 20 | 2 | 0 | **17 / 20** | `0/3230` leaked on practice; `20/22` synthetic canaries passed; `2` failed on camelCase JSON key & CSV header PII. |
| 3 | **Medical Data Preservation** | 20 | 13 (`CLIN-01..13`) + `check_dev` (4855 values) | 13 | 0 | 0 | **19.5 / 20** | `4854/4855` (`100.0%`) on practice; `13/13` clinical traps (`C/O fever`, `Dr. Ramesh`, `Parkinson's`, `1-0-1`, `Ramipril 5 mg`, `Dolo 650 BD`, vitals, labs, LOS=7d, age bands) preserved. |
| 4 | **Patient Identity Consistency** | 15 | 3 (`LINK-01..03`) + `check_dev` linkage | 3 | 0 | 0 | **13.5 / 15** | `P=1.00, R=0.71, F0.5=0.93, 0 wrong merges` on practice; cross-hospital P1 linked (`PSN-5QM5RR`), homonyms separated, ambiguous Asha=`null`. |
| 5 | **Output Quality & Validity** | 10 | 2 (`PIPE-01`, `CONTRACT-01`) + `validate_output.py` | 2 | 0 | `check_submission --run` (Windows path bug) | **9 / 10** | `CONTRACT OK` on both practice and synthetic; 4 Windows CRLF warnings on practice. |
| 6 | **Speed & Reliability** | 10 | 2 (`ROBUST-01..02`) + 2-core affinity + ReDoS probe | 2 | 1 (100KB line stall) | `>10MB` full run | **6 / 10** | `0.059s` (8 files), `3.552s` (13 robust files), `28.03 MB` RSS on 2 cores; **deducted for `>120s` ReDoS/stall on 100KB single-line text**. |
| | **TOTAL** | **100** | **47+** | **45** | **3** | **External tools** | **86.0 / 100** | Conservative, evidence-backed score. |
