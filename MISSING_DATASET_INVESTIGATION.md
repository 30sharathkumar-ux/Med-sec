# RAKSHA — Missing Dataset & Probe Forensic Investigation

**Investigation Mode:** Read-only forensics (no source code, `dev/input/`, `dev/truth/`, or evaluator files were modified).  
**Repository:** `d:\RAKSHA` (`30sharathkumar-ux/Med-sec`, branch `main`, HEAD `945a4ba`)

---

## 1. Executive Summary & What the `4,495` Count Represents

**Honest Finding on `4,495`:**  
No dataset, archive, manifest, file, or record collection in the `RAKSHA` / `Med-sec` repository contains **4,495** entries, and **no external/original ZIP or TAR archive exists** in the repository or git history (`ba2f7ee` through `945a4ba` across all 6 branches).

- **Zero files are missing from `dev/input/`**: All **200 / 200** files listed in `dev/truth/truth.json` and `dev/dataset_manifest.json` are present on disk.
- **Zero files were deleted in Git history**: `git log --all --stat --diff-filter=D --summary` returned empty across all commits and all 6 remote branches (`dev/` has had the exact same 206 files since commit `aa7424f`).
- **However, two exact "1-missing / 1-mismatch" anomalies were confirmed inside the repository:**
  1. **1 Missing Medical Probe (`4,854 / 4,855`):** In `check_dev.py` output (`4854 of 4855 medical values survived`), **1** medical `preserve` probe out of `4,855` is missing from `output/sanitized/`:  
     `Dr. Ramesh Srivastava (MD Medicine)` in `discharge/Discharge_Summary_Shahid_Mohammad_UHID-010607.txt`.
  2. **1 File SHA-256 Mismatch (`199 / 200`):** In `dev/input/`, `registration/arogya_legacy_export.csv` fails both raw and LF-normalized SHA-256 checks against `truth.json` due to mixed CRLF/LF line endings inside quoted multiline CSV fields, even though **0 records are missing**.

If `4,495` refers to an external organizer dataset or an earlier unreleased snapshot outside this repository, that original source is **not present in `d:\RAKSHA` or its Git history** and cannot be verified from this repo alone.

---

## 2. Authoritative Repository Inventory

| Surface / File | Expected (Manifest / Truth) | Current Verified | Difference | Notes |
|---|---:|---:|---:|---|
| `dev/input/` files | 200 (`dataset_manifest.json`, `truth.json`) | 200 | 0 | Exact path set match (`truth_rels - actual_rels == ∅`) |
| `dev/input/` CSV/TSV data rows | — | 491 | — | Across all `.csv` / `.tsv` files |
| `dev/input/` JSON array records | — | 247 | — | `visits`, `results`, `patients` lists |
| `dev/input/` FHIR Bundle entries | — | 332 | — | `Bundle.entry` items |
| `dev/input/` `.txt` files | — | 101 | — | Free-text notes / protocols |
| `dev/dataset_manifest.json` `records` | 815 | 816 (`output/records.jsonl`) | +1 | Pipeline emits 1 extra unit locator; none missing |
| `dev/truth/truth.json` `units` | 883 | 883 | 0 | Verified across 200 files |
| `dev/truth/truth.json` `entities` | 3,234 (3,230 PII + 4 canaries) | 3,234 | 0 | Verified (`0/3230` leaked, `0/4` canaries) |
| `dev/truth/truth.json` `preserve` probes | **4,855** | **4,854** (`output/sanitized/`) | **-1** | **Confirmed missing probe** (see Section 3) |
| `dev/attacker/registry.csv` | 240 (`dataset_manifest.json`) | 240 data rows (241 lines) | 0 | Exact match |
| `dev/attacker/known_facts.jsonl` | — | 18 rows | — | Intact |
| `dev/truth/truth.json` LF SHA-256 | `bdf3e802a53ba1cbcec35efb12a2b7df23a42660c8962c2f76b94da0e15c35be` | `bdf3e802a53ba1cbcec35efb12a2b7df23a42660c8962c2f76b94da0e15c35be` | 0 | Byte-for-byte LF match with `dataset_manifest.json` |
| `dev/input/` file SHA-256 matches | 200 | 199 (27 exact + 172 LF) | **-1** | `registration/arogya_legacy_export.csv` (see Section 4) |

---

## 3. Confirmed Missing Item #1: The 1 Missing Medical Probe (`4,854 / 4,855`)

| Measurement | Result |
|---|---|
| **Expected original count** | `4,855` medical `preserve` probes in `dev/truth/truth.json` |
| **Current count** | `4,854` surviving in `output/sanitized/` (`check_dev.py`) |
| **Difference** | `-1` probe |
| **Missing item** | `{'text': 'Dr. Ramesh Srivastava (MD Medicine)', 'kind': 'doctor', 'weight': 0.5, 'trap': 'doctor'}` |
| **Original location** | `dev/input/discharge/Discharge_Summary_Shahid_Mohammad_UHID-010607.txt` (`loc: "doc"`) |
| **Sanitized output location** | `output/sanitized/discharge/doc_ab8096646e.txt` |
| **Likely / Confirmed reason** | Over-redaction of `MD` inside `(MD Medicine)` as `[PATIENT_NAME]` |

### Evidence & Root Cause
In `dev/input/discharge/Discharge_Summary_Shahid_Mohammad_UHID-010607.txt`:
```text
Consultant: Dr. Ramesh Srivastava (MD Medicine)
```
In `output/sanitized/discharge/doc_ab8096646e.txt`:
```text
Consultant: Dr. Ramesh Srivastava ([PATIENT_NAME] Medicine)
```
`MD` (the medical degree *Doctor of Medicine*) was matched as a personal name token (`MD` / `Mohammad`) during name span detection, replacing `MD` with `[PATIENT_NAME]` and breaking the exact substring check in `check_dev.py` for `'Dr. Ramesh Srivastava (MD Medicine)'`.

### Safe Recovery Instructions (If Fixing in a Future Change)
- Exclude uppercase medical degree tokens (`MD`, `MS`, `DM`, `DNB`, `MBBS`, `BAMS`, `BHMS`) inside parenthetical degree/credential contexts (e.g., `(MD Medicine)` or after `Dr. ...`) from `PATIENT_NAME` span redaction in `rakshak/detection/names.py`.

---

## 4. Confirmed Anomaly #2: The 1 File SHA-256 Mismatch (`199 / 200`)

| Measurement | Result |
|---|---|
| **Expected file count** | `200` files in `dev/truth/truth.json` |
| **SHA-256 matching files** | `199` (`27` exact byte-for-byte + `172` LF-normalized) |
| **Difference** | `1` file with SHA-256 mismatch (`registration/arogya_legacy_export.csv`) |
| **Original location** | `dev/input/registration/arogya_legacy_export.csv` (recorded in `truth.json`, `encoding: cp1252`, `size: 1441`) |
| **Expected SHA-256** | `90b4b08b83639d1fab4e7afbcde8248fb3975e0b28dc9f0b88599ec582d74745` |
| **Current SHA-256 (on disk, CRLF)** | `3aa4d9b43ea5b5c166f214a033cc91165be0cb0816014fc5b7b91b87a6fafd3d` (`1443` bytes) |
| **Current SHA-256 (LF-normalized)** | `fc452ced0f621d2d06d01a9ac9421ca09ed997070c39dad066f9f2e21af7c265` (`1432` bytes) |
| **Confirmed cause** | Mixed line endings (`\r\n` on 9 CSV row endings + `\n` inside 2 quoted multiline `Notes` fields) normalized by Windows Git checkout |

### Mathematical Proof
The original `cp1252` file (`1441` bytes) used `\r\n` for its 9 CSV record terminators and `\n` for the 2 embedded newlines inside quoted `Notes` fields (`1432 + 9 = 1441` bytes). Windows Git checkout (`core.autocrlf`) converted all 11 `\n` bytes to `\r\n` (`1443` bytes).

Reconstructing `\r\n` outside double quotes and `\n` inside double quotes on `dev/input/registration/arogya_legacy_export.csv` produces:
- **Length:** `1441` bytes (exact match to `truth.json["size"]`)
- **SHA-256:** `90b4b08b83639d1fab4e7afbcde8248fb3975e0b28dc9f0b88599ec582d74745` (exact match to `truth.json["sha256"]`)

**No records or data bytes are missing** from `arogya_legacy_export.csv`.

---

## 5. Commands Used (Read-Only)

- `git log --oneline -n 20`, `git branch -a`, `git log --all --stat --diff-filter=D --summary -n 30`, `git diff aa7424f HEAD -- dev/ check_dev.py check_submission.py validate_output.py scoring.toml`
- `Get-ChildItem -Recurse -Include *.zip,*.tar,*.gz,*.7z`
- Python inventory & hash verification scripts over `dev/dataset_manifest.json`, `dev/truth/truth.json`, `dev/input/`, `dev/attacker/`, and `output/sanitized/`

---

## 6. Remaining Uncertainty

- The prompt's reference figure of **"approximately 4,495 entries"** does not match any file, manifest, line count, or record count in `d:\RAKSHA` or its Git history (`dev/truth/truth.json` has `4,855` `preserve` probes, `3,234` `entities`, `883` `units`, and `200` `files`; `dev/dataset_manifest.json` has `815` `records`). If `4,495` comes from an external archive or hidden evaluation split not committed to `Med-sec`, that external source is unavailable in this workspace.
