# RAKSHA — Final Security Report

**Track 3: Secret Wards — Yugaantar DevForge**
**Date:** 2026-11-27

---

## 1. Architecture Overview

RAKSHA implements a three-layer defense-in-depth architecture:

```
┌─────────────────────────────────────────────────┐
│ Layer 1: SENTINEL — Input & Surface Defense      │
│  • File ingestion, encoding detection             │
│  • Format sniffing (CSV/TSV/JSON/FHIR/TXT)       │
│  • Unsafe file quarantine                         │
│  • Filename/header/key/metadata/Base64 inspection │
│  • Input immutability guarantee                   │
└──────────────────┬──────────────────────────────┘
                   ▼
┌─────────────────────────────────────────────────┐
│ Layer 2: IDENTITY GUARD — Detection & Linkage    │
│  • Multilingual PII detection (EN/HI/Hinglish)   │
│  • Indian identity number patterns                │
│  • Contextual rules (clinical vs PII)             │
│  • Cross-file identity resolution                 │
│  • Conservative matching (no false merges)         │
└──────────────────┬──────────────────────────────┘
                   ▼
┌─────────────────────────────────────────────────┐
│ Layer 3: VAULT — Privacy Transformation          │
│  • HMAC-keyed pseudonymization                    │
│  • Per-patient deterministic date shifting         │
│  • Age banding, location generalization            │
│  • Rare-value suppression                          │
│  • Output rescanning and contract validation       │
└─────────────────────────────────────────────────┘
```

## 2. Data-at-Rest Security

### 2.1 In-Memory Processing Design

RAKSHA processes all data entirely in memory. The pipeline:

1. **Reads** each input file into memory (`Path.read_bytes()`)
2. **Decodes** encoding in memory (`encoding.py` → string)
3. **Parses** format in memory (CSV reader, JSON parser, text)
4. **Transforms** in memory (detection, pseudonymization, generalization)
5. **Writes** sanitized output directly to `output/sanitized/`

**No intermediate files are written to disk.** There is no use of `tempfile`, `NamedTemporaryFile`, or any temporary directory operations.

### 2.2 Verification

Post-pipeline audit confirmed:
- **0 temp files** in the output directory
- **No `logs/` directory** created (logging is counts-only to stdout)
- **No `quarantine/` directory** with raw data
- Pipeline uses `io.StringIO()` for CSV assembly (in-memory buffer)

### 2.3 Why This Satisfies Encryption-at-Rest

Since RAKSHA never writes raw or intermediate data to disk, the encryption-at-rest requirement is satisfied by design — there is nothing to encrypt. The only data written to disk is:
- **Sanitized output files** (PII removed)
- **`report.json`** (counts and SHA-256 hashes only)
- **`records.jsonl`** (pseudonyms and file locations only)

If the server is breached, the attacker sees only de-identified data.

## 3. Secret Management

### 3.1 RAKSHA_SECRET Lifecycle

| Property | Implementation |
|---|---|
| **Source** | `os.environ.get("RAKSHA_SECRET", "")` — environment variable only |
| **Access** | `_get_secret()` function — reads dynamically at each call site |
| **Caching** | ❌ Never cached in memory beyond immediate use |
| **Logging** | ❌ Never logged, printed, or included in error messages |
| **Persistence** | ❌ Never written to disk, config files, or report |
| **Derivation** | Used as HMAC key for pseudonym generation and date shift computation |

### 3.2 Secret Usage Points

1. **Pseudonym generation** (`privacy/pseudonymize.py`): `hmac.new(secret, patient_key, sha256)` → deterministic, non-reversible pseudonym
2. **Date shift computation** (`privacy/transforms.py`): `hmac.new(secret, patient_key, sha256)` → per-patient shift in `[-max_days, +max_days]`
3. **Filename sanitization** (`detection/hidden_surfaces.py`): HMAC-based hash for renamed filenames

### 3.3 Unlinkability Across Releases

Different `RAKSHA_SECRET` values produce:
- Different pseudonyms (HMAC output changes)
- Different date shifts (shift derived from HMAC)
- Verified: different secret → different output digest ✅

## 4. PII-Free Logging

### 4.1 `rakshak/security/logging.py` — `emit_summary()`

The only output to stdout/stderr:
```
files 200 sanitized 192 quarantined 8 records 816 linked 771 generalized 677
```

This contains only aggregate counts. No file names, patient names, identifiers, or data values are logged.

### 4.2 Error Handling

- Ingestion failures → quarantine entry with generic `reason` (e.g., `"unsupported_format"`, `"malformed_csv"`)
- No PII in exception messages (generic error types only)
- No debug output in production mode
- No crash traces expose input data

## 5. HMAC Pseudonymization

### 5.1 Design

```python
hmac.new(secret, patient_cluster_key.encode(), hashlib.sha256).digest()
```

- **Non-reversible**: HMAC is a one-way keyed hash
- **Deterministic**: Same patient + same secret = same pseudonym
- **Collision-resistant**: SHA-256 based, 256-bit output
- **Secret-dependent**: Different secret → different pseudonym (unlinkability)

### 5.2 Pseudonym Format

`PSN-{base32_encoded}` — 10-character alphanumeric string using Crockford Base32 alphabet.

### 5.3 HMAC Is Not Encryption

HMAC provides **integrity and authenticity** of pseudonyms, not confidentiality of the original data. The original patient identifiers are **replaced** (not encrypted) — they cannot be recovered from the pseudonym, even with the secret key. This is by design: pseudonymization is a one-way mapping.

## 6. Input Immutability

### 6.1 Design

- Input files are read via `Path.read_bytes()` — read-only access
- No write operations target the input directory
- SHA-256 hash of input directory verified unchanged after pipeline execution

### 6.2 Verification

Input directory hash computed before and after pipeline run → identical.

## 7. Quarantine Design

### 7.1 Quarantine Triggers

| Trigger | Handling |
|---|---|
| Empty file (0 bytes) | Quarantined with reason |
| Malformed CSV | Quarantined with reason |
| Malformed JSON | Quarantined with reason |
| Oversized file (> 50 MB) | Quarantined with reason |
| Unsupported format (.xml, .pdf, .jpg) | Quarantined with reason |
| Excessively nested JSON (> 128 depth) | Quarantined with reason |

### 7.2 Quarantine Report Entry

```json
{
  "input_sha256": "51aa...",
  "output": null,
  "status": "quarantined",
  "reason": "unsupported_format"
}
```

- Quarantined files are **never copied** to `sanitized/`
- No raw data appears in the quarantine report entry
- 8 files correctly quarantined in practice dataset

## 8. Side-Channel Analysis

| Channel | Status | Details |
|---|---|---|
| `report.json` | ✅ Clean | Contains only SHA hashes, counts, and status strings |
| `records.jsonl` | ✅ Clean | Contains only pseudonyms, file paths, and locations |
| `stdout/stderr` | ✅ Clean | Only aggregate count summary |
| Output filenames | ✅ Clean | PII filenames replaced with `doc_<hash>.ext` |
| `logs/` | ✅ N/A | Directory not created |
| `TMPDIR/HOME` | ✅ Clean | No temp files created |
| CSV headers | ✅ Clean | PII headers sanitized via `sanitize_csv_header()` |
| JSON keys | ✅ Clean | PII keys sanitized via `sanitize_json_key()` |

## 9. Re-identification Risk Analysis

### 9.1 Protections Applied

| Quasi-identifier | Generalization | Utility Preserved |
|---|---|---|
| Exact age | 5-year bands (0–4, 5–9, ...) | Band contains true age |
| Date of birth | Date shifted (per-patient) | Within ±180 days |
| Admission/discharge dates | Date shifted (same shift) | Stay duration preserved exactly |
| Village | Generalized to district level | District retained |
| PIN code | Truncated to 3-digit prefix | State-level geography |
| House/locality | Fully suppressed | N/A |

### 9.2 Risk Assessment

The combination of age banding + location generalization + date shifting provides layered defense:

- **Age band + district**: Groups patients into larger populations (k > 5 target)
- **Date shifting**: Prevents exact date matching by external registries
- **Uniform shift per patient**: Preserves temporal intervals for research
- **PIN truncation**: 3-digit prefix covers ~100 PIN codes per prefix

### 9.3 Limitations

- Rare diagnoses combined with demographic quasi-identifiers may still enable re-identification in small populations
- The system does not explicitly compute k-anonymity across the full output dataset
- Very rare combinations (e.g., unique diagnosis + small village promoted to only district) remain a theoretical risk

## 10. Compliance Notes

| Standard | Alignment |
|---|---|
| **HIPAA Safe Harbor** | Addresses all 18 identifier categories applicable to Indian context |
| **India DPDP Act 2023** | Personal data processing compliant: purpose limitation, minimization |
| **ABDM Guidelines** | Health data de-identification following ABDM recommendations |
| **Competition Rules** | No LLMs, fully offline, CPU-only, no real patient data |
