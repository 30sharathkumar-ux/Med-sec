# RAKSHA — Detailed Red-Team Findings

## High Severity

### F-01: Super-Linear / ReDoS Stall on Long Single-Line Text (`>120s`)
- **Category:** Speed & Reliability (Section 10 / Section 13)
- **Reproduction:** Create a `.txt` file containing `"Diagnosis: Fever. " + ("X" * 100000)` and run `run_pipeline`.
- **Observed:** Execution exceeded `120s` and had to be terminated (`task-1243`). When reduced to `5,000` `X`s, the entire 13-file robustness batch completed in `3.552s`.
- **Impact:** An adversarial or malformed single-line file well below the `50 MiB` `max_file_bytes` limit can exhaust the 15-minute competition runtime budget.
- **Recommended Fix (not applied):** Add a per-line length cap or line-chunking preprocessor in text detection, and audit multi-quantifier regexes in `rakshak/detection/names.py`, `addresses.py`, and `context_rules.py` for catastrophic backtracking.

### F-02: Compound / CamelCase PII Leaked in JSON Keys & CSV Headers
- **Category:** Personal Data Detection — Hidden Surfaces (Section 5)
- **Exact File & Lines:** [rakshak/detection/hidden_surfaces.py](file:///d:/RAKSHA/rakshak/detection/hidden_surfaces.py#L272-L275) (`sanitize_csv_header`) and [rakshak/detection/hidden_surfaces.py](file:///d:/RAKSHA/rakshak/detection/hidden_surfaces.py#L314-L318) (`sanitize_json_key`).
- **Observed:** `CANARY-JSON_KEY_PII` leaked in `sanitized/nested_record.json` (`1` hit) and `CANARY-CSV_HEADER_PII` leaked in `sanitized/hosp_alpha_reg.csv` (`1` hit).
- **Root Cause:** `re.split(r"[^A-Za-z]+", norm_key)` does not split camelCase boundaries, and Latin `extra_names` (discovered patient names) are only checked for Devanagari (`_has_deva_name_token`), not Latin tokens.
- **Recommended Fix (not applied):** Split camelCase tokens (`re.sub(r"([a-z])([A-Z])", r"\1 \2", key)`) before tokenizing, and check Latin `extra_names` tokens against key/header tokens.

## Medium Severity

### F-03: `rapidfuzz` Declared in `requirements.txt` but Missing in Active Environment
- **Exact File:** [requirements.txt](file:///d:/RAKSHA/requirements.txt) & [rakshak/linkage/resolver.py](file:///d:/RAKSHA/rakshak/linkage/resolver.py#L17-L20)
- **Observed:** `python -c "import rapidfuzz"` failed (`NOT_INSTALLED`), causing `resolver.py` to silently fall back to `_fuzz = None`.
- **Impact:** Fuzzy spelling-variant matching in `_names_match` and `_text_similar` is disabled whenever `rapidfuzz` is missing.
- **Recommended Fix (not applied):** Ensure `pip install -r requirements.txt` is run in the target/submission environment and verify `rapidfuzz` loads.

### F-04: `check_submission.py --repo . --run` Fails on Windows
- **Exact File:** [check_submission.py](file:///d:/RAKSHA/check_submission.py) + [rakshak/cli.py](file:///d:/RAKSHA/rakshak/cli.py#L748)
- **Observed:** `OSError: [WinError 123]` because `check_submission.py` wraps temp paths with `shlex.quote()` on Windows, producing literal single quotes in `out_A`.
- **Note:** `check_submission.py` is an organizer script; on Linux/POSIX this quoting works as expected.

## Low Severity / Informational

### F-05: Missing `pdf` Warning in `check_submission.py`
- `brief/PROJECT_BRIEF.pdf` exists (`5,552` bytes), while `check_submission.py` checks root or warns to submit the 2-page PDF separately alongside the repo link.

### F-06: Windows `peak_rss_mb` Reports `0.0` in `report.json`
- [rakshak/reporting/report.py](file:///d:/RAKSHA/rakshak/reporting/report.py#L42) falls back to `0.0` on Windows; `psutil` measured `28.03 MB` RSS during the synthetic audit.
