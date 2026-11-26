# RAKSHA — Final Linux (Ubuntu WSL2) Submission Verification

**Date:** 2026-11-27  
**Environment:** Ubuntu 24.04 WSL2 (`Linux Jarvis-007 6.6.114.1-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC x86_64 GNU/Linux`, Python `3.12.3`)  
**Repository:** `/mnt/d/RAKSHA` (`main` @ `a6ca9e9`, no source code modified, no commits/pushes)

---

## Summary of Exit Codes

| Step | Command / Check | Exit Code | Result |
|---|---|---|---|
| 1 | `python3 -m venv "$VENV_DIR"` | `0` | Fresh temporary venv created |
| 2 | `pip install -r requirements.txt` | `0` | Installed `rapidfuzz-3.14.6`, `cryptography-50.0.2`, `cffi-2.1.1`, `pycparser-3.12` |
| 3 | `python check_submission.py --repo . --run` | `0` | **`READY TO SUBMIT`** (`10.9s`, `CONTRACT OK`, deterministic, secret-safe) |
| 4 | `python main.py --input dev/input --output "$OUT_DIR"` | `0` | `files 200 sanitized 192 quarantined 8 records 816 linked 771 generalized 677` |
| 5 | `python validate_output.py --input dev/input --output "$OUT_DIR"` | `0` | `CONTRACT OK` (CRLF checkout warnings only; 0 errors) |
| 6 | `python check_dev.py --output "$OUT_DIR" --show 30` | `0` | `0/3230` leaked (`0.0%`), `0/4` canaries, `4854/4855` (`100.0%`) medical, `P=1.00 / R=0.72 / F0.5=0.93`, `0` wrong merges, `0` raw copies |
| 7 | Offline socket-blocked `run_pipeline` | `0` | `OFFLINE_PIPELINE_RC=0` (zero network calls attempted) |

*(Note: `RAKSHA_SECRET` was set to `[REDACTED]` during manual runs; no secret values were written to outputs or logs.)*

---

## Complete Terminal Output (Secrets Redacted)

```text
=== 1. VENV & INSTALL ===
Collecting rapidfuzz>=3.0.0 (from -r requirements.txt (line 2))
  Downloading rapidfuzz-3.14.6-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl.metadata (12 kB)
Collecting cryptography>=41.0.0 (from -r requirements.txt (line 3))
  Downloading cryptography-50.0.2-cp311-abi3-manylinux_2_34_x86_64.whl.metadata (4.4 kB)
Collecting cffi>=2.0.0 (from cryptography>=41.0.0->-r requirements.txt (line 3))
  Downloading cffi-2.1.1-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl.metadata (2.5 kB)
Collecting pycparser (from cffi>=2.0.0->cryptography>=41.0.0->-r requirements.txt (line 3))
  Downloading pycparser-3.12-py3-none-any.whl.metadata (9.7 kB)
Installing collected packages: rapidfuzz, pycparser, cffi, cryptography
Successfully installed cffi-2.1.1 cryptography-50.0.2 pycparser-3.12 rapidfuzz-3.14.6
EXIT_VENV=0 EXIT_PIP=0

=== 2. CHECK_SUBMISSION ===
Secret Wards pre-submit check: /mnt/d/RAKSHA

1) Repository files
  ✅ raksha.toml found at the root
  ✅ team name: team-raksha
  ✅ run: python main.py --input {input} --output {output}
  ✅ setup: pip install -r requirements.txt
  ✅ README.md found (1616 words)
  ✅ Project Brief PDF found: brief/PROJECT_BRIEF.pdf
  ✅ requirements.txt has no LLM / hosted-AI packages
  ✅ config/policy.yaml found

2) Running your system on the practice data (3 runs)
  ✅ exit code 0 in 10.9s
  ✅ output contract: CONTRACT OK
  ✅ same secret twice → identical sanitized/ and records.jsonl
  ✅ different secret → different output (pseudonyms / date shifts are keyed)
  ✅ RAKSHA_SECRET is never written to output or logs
  ✅ input folder left unchanged

   Next: python3 check_dev.py --output <your output>  shows how GOOD the output is.
   Event day has NO internet: also test with your network switched off.

READY TO SUBMIT
Submit: your GitHub repo link + your 2-page Project Brief PDF, before the deadline.
EXIT_SUBMISSION=0

=== 3. LINUX PIPELINE ===
files 200 sanitized 192 quarantined 8 records 816 linked 771 generalized 677
EXIT_MAIN=0

=== 4. VALIDATE_OUTPUT ===
[... WARN report.files entry whose input_sha256 matches no input file (Windows CRLF checkout on /mnt/d/RAKSHA) ...]
CONTRACT OK
EXIT_VALIDATE=0

=== 5. CHECK_DEV ===
================================================================
 SECRET WARDS practice self-check (rough guide, not the official score)
================================================================

1) PERSONAL DATA: 0 of 3230 pieces still visible (  0.0% leaked; lower is better)
   PIN              leaked    0 / 136    0.0%
   LANDMARK         leaked    0 / 64     0.0%
   PHONE            leaked    0 / 308    0.0%
   INSURANCE_ID     leaked    0 / 22     0.0%
   RELATIVE_NAME    leaked    0 / 232    0.0%
   DOB              leaked    0 / 111    0.0%
   HOUSE            leaked    0 / 136    0.0%
   PAN              leaked    0 / 22     0.0%
   AADHAAR          leaked    0 / 71     0.0%
   EMAIL            leaked    0 / 1      0.0%
   AADHAAR_MASKED   leaked    0 / 16     0.0%
   VILLAGE          leaked    0 / 150    0.0%
   MRN              leaked    0 / 850    0.0%
   ABHA_NUMBER      leaked    0 / 46     0.0%
   PATIENT_NAME     leaked    0 / 962    0.0%
   LOCALITY         leaked    0 / 103    0.0%
   by language: latin 0.0%, deva 0.0%, hinglish 0.0%
   by hiding place: content 0.0%, filename 0.0%, base64 0.0%, metadata 0.0%, key 0.0%, header 0.0%

2) CANARIES: 0 of 4 planted canaries found in your output folder (each one costs -3 officially)

3) MEDICAL DATA KEPT: 4854 of 4855 medical values survived (100.0%; higher is better)

4) PATIENT LINKING: precision 1.00, recall 0.72, F0.5 0.93  (pseudonyms that wrongly merge different people: 0)

5) RAW COPIES: 0 broken/unsupported files were copied out unchanged instead of quarantined (each costs -5 officially)

EXIT_CHECK_DEV=0

=== 6. OFFLINE NETWORK CHECK ===
files 200 sanitized 192 quarantined 8 records 816 linked 771 generalized 677
OFFLINE_PIPELINE_RC= 0
EXIT_OFFLINE=0
```
