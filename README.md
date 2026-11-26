# RAKSHA: Offline Multilingual Medical Data Privacy Firewall

**Yugaantar DevForge 2026 · Track 3: Secret Wards**  
*What happens in the ward stays in the ward.*

---

## 1. Project Overview & Mission

Hospital networks across Yugaantar Pradesh are aggregating years of heterogeneous patient encounters into a single longitudinal research dataset for epidemiological and public-health analysis. The ingested data spans four distinct health systems with varying schemas, encodings, and clinical documentation styles:
- **Sanjeevani Multispeciality Hospital** (CSV with full demographics and duplicate exports; UTF-8 with BOM; Day-First dates)
- **Jeevan Jyoti Charitable Hospital** (TSV with Hindi Devanagari headers and rows; UTF-16; Day-First dates)
- **Arogya Seva Sadan** (Legacy CSV with split names and multiline clinical notes; cp1252; Month-First dates)
- **District Hospital Hardoi** (Nested JSON with unquoted identifiers; UTF-8; ISO dates)

Patients appear across languages (English, Devanagari Hindi, Hinglish), with varying phone and identity notations, informal aliases, honorifics, and fragmented relative references. Furthermore, direct identifiers frequently hide in unstructured channels: export metadata paths, file names, JSON dictionary keys, CSV headers, and base64-encoded clinical referrals.

**RAKSHA** is an offline, CPU-only, LLM-free medical data privacy firewall designed to satisfy three core mandates simultaneously:
1. **Zero Compromise on Clinical Utility:** Preserve exact medications, dosages, frequencies, routes, lab values with units, vitals, ICD-10 diagnoses, and hospital length-of-stay intervals.
2. **Robust Defense Against Adversarial Re-Identification:** Neutralize linkage attacks from adversaries armed with voter rolls and partial background knowledge (encounter dates, rare diagnoses) via per-patient HMAC date shifting, 5-year age generalization, locality hierarchy rollup, and k-anonymity suppression.
3. **Deterministic Cross-Hospital Identity Resolution:** Issue stable, non-reversible, secret-keyed HMAC pseudonyms linking the same patient across records without transitive over-merging.

---

## 2. Architecture & Pipeline

```
                              [ INPUT DIRECTORY ]
    (CSV, TSV, Nested JSON, FHIR R4 Bundles, Text Notes, WhatsApp Forwards, Misc)
                                      │
                                      ▼
                      ┌────────────────────────────────┐
                      │  PHASE 1: Robust Ingestion     │
                      │  - UTF-8 / BOM / UTF-16 / cp1252│
                      │  - Magic-byte & control checks  │
                      │  - Depth-bounded JSON (<= 128) │
                      │  - Content format validation   │
                      └───────────────┬────────────────┘
                                      │
                       ┌──────────────┴──────────────┐
                       │ Fail-Closed                 │ Valid & Parsed
                       ▼                             ▼
              ┌──────────────────┐       ┌────────────────────────────────┐
              │ Safe Quarantine  │       │  PHASE 2: Multilingual PII     │
              │ (No RAW copies)  │       │  Detection Engine              │
              └──────────────────┘       │  - Structured column/key rules │
                                         │  - Multi-script regex & NLP    │
                                         │  - Doctor/Eponym/Dose context  │
                                         │  - Hidden surfaces scrub       │
                                         └───────────────┬────────────────┘
                                                         │
                                                         ▼
                                         ┌────────────────────────────────┐
                                         │  PHASE 3: Conservative Identity│
                                         │  Resolution                    │
                                         │  - Transliteration & phonetics │
                                         │  - Strict multi-clue matching  │
                                         │  - Keyed HMAC pseudonyms       │
                                         └───────────────┬────────────────┘
                                                         │
                                                         ▼
                                         ┌────────────────────────────────┐
                                         │  PHASE 4: Privacy & Utility    │
                                         │  - Per-patient HMAC date shift │
                                         │  - 5-year truthful age bands   │
                                         │  - Village -> District rollup  │
                                         │  - PIN prefix (3-digit) mask   │
                                         │  - Clinical probe verification │
                                         └───────────────┬────────────────┘
                                                         │
                                                         ▼
                                                [ OUTPUT DIRECTORY ]
                                         ├── sanitized/ (Cleaned mirror)
                                         ├── report.json (raksha-report/1)
                                         └── records.jsonl (Locators & IDs)
```

---

## 3. Modular Engineering Design

```
RAKSHA/
├── raksha.toml                   # Submission contract declaration (name, setup, run)
├── requirements.txt              # Standard library + rapidfuzz, cryptography
├── config/
│   └── policy.yaml               # Configurable age bands, date shift limits, depth limits
├── main.py                       # CLI entrypoint for the offline evaluator
├── rakshak/
│   ├── __init__.py
│   ├── cli.py                    # Pipeline orchestration and CLI interface
│   ├── encoding.py               # Robust encoding detection (UTF-8, UTF-16, cp1252, binary)
│   ├── ingestion.py              # File discovery, depth bounding, format validation
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── identifiers.py        # Indian ID patterns (Aadhaar, ABHA, Phone, PAN, MRN)
│   │   ├── structured.py         # Semantic column/key classifier (EN, HI, Hinglish)
│   │   ├── multilingual.py       # Devanagari transliteration & phonetic normalization
│   │   ├── context_rules.py      # Clinical shields (Doctors, Eponyms, Doses, Wards)
│   │   ├── names.py              # Multilingual patient & relative name extraction
│   │   ├── addresses.py          # Residential house, locality, landmark, village, PIN
│   │   └── hidden_surfaces.py    # Filename HMAC renamer, JSON keys, base64 attachments
│   ├── processors/
│   │   ├── __init__.py
│   │   └── quarantine.py         # Safe fail-closed quarantine record generator
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── report.py             # raksha-report/1 JSON report builder & memory monitor
│   │   └── records.py            # records.jsonl generator & RFC 6901 pointer handler
│   └── security/
│       ├── __init__.py
│       └── logging.py            # PII-free stderr logging & secret guard
└── tests/
    ├── __init__.py
    ├── test_contract.py          # Determinism, report structure, and repeat-run tests
    └── test_ingestion.py         # Encoding, depth bounding, format mismatch tests
```

---

## 4. Key Mechanisms & Implementation Details

### A. Robust Ingestion & Fail-Closed Quarantine
- **Encoding Defense:** Detects UTF-8 with BOM (`\xef\xbb\xbf`), UTF-16 (`\xff\xfe` / `\xfe\xff`), standard UTF-8, and legacy cp1252. Corrupt mixed-byte runs (such as embedded UTF-16 headers in text) and disallowed C0 control characters are quarantined rather than silently passed.
- **Payload Validation:** Inspects magic bytes to detect binary formats (PDF, JPEG, PNG, PE) and rejects XML CDA payloads.
- **Format Integrity:** Detects mislabeled formats (e.g., JSON disguised with a `.csv` extension) and enforces bounded iteration depth on deeply nested JSON structures (`max_json_depth: 128`), preventing stack-overflow recursion attacks.
- **Fail-Safe Export:** Unsupported or unparseable files are logged in `report.json` with an explicit reason and never copied into `sanitized/`, eliminating unprocessed export penalties.

### B. Multilingual PII Detection Engine
- **Structured Fields:** Classifies column headers and dictionary keys semantically across variations (`Patient Name`, `मरीज़ का नाम`, `Naam`, `Janm Tithi`, `Pita ka Naam`, `Gaon`, `Umar`, `Aadhar`, `Contact#`, `Reg No`).
- **Identifier Precision:** High-precision regular expressions distinguish 14-digit ABHA numbers, 12-digit Aadhaar, masked Aadhaar (`XXXX XXXX 1234`), 10-digit Indian phones (with `+91`, leading `0`, or Devanagari digits), PAN, and institutional MRN/IPD tokens.
- **Contextual Clinical Shields:** Explicitly protects medical eponyms (Addison's disease, Parkinson's, Bell's palsy), hospital wards/beds (Ward 5 Medicine Bed 18 vs residential Ward 20), clinical history markers (`K/C/O`, `H/O`, `C/O fever`), and all clinical dosages (`650 mg`, `1-0-1`, `BD x 5 days`). Doctors (`Dr. Ramesh Srivastava`) are preserved while relatives (`C/O Ramesh Patel`) are redacted.
- **Hidden Channels:** Automatically cleans export metadata strings (`source_path`), decrypts and sanitizes base64 clinical attachments, renames PII-bearing filenames via deterministic HMAC tags, and scrubs patient names from dictionary keys and CSV headers.

### C. Conservative Identity Resolution
- **Multi-Clue Evidence:** Links records only when supported by strong unique identifiers (UHID, Aadhaar, ABHA, Phone, Insurance ID) or an exact match on transliterated patient name plus a secondary discriminant (DOB, guardian name, or village + age).
- **Phonetic & Cross-Script Normalization:** Custom Devanagari-to-Latin transliteration and vowel-tolerant phonetic keying bridge orthographic drift (`Mohd` / `Mohammad` / `मोहम्मद`, `Reena` / `Rina`, `Chouhan` / `Chauhan`).
- **Homonym Protection:** Strictly avoids unconstrained transitive clustering. Ambiguous records with insufficient linking evidence receive `patient: null`, avoiding catastrophic false merges.

### D. Privacy Layer & Quasi-Identifier Protection
- **Per-Patient Date Shifting:** Computes a secret-keyed shift in `[-180, +180]` days (never 0) using `HMAC-SHA256(RAKSHA_SECRET, "shift|" + patient_key)`. All encounters for the same patient move by the exact same offset, preserving interval lengths and exact durations of hospital stays while defeating global shift-recovery attacks.
- **Truthful Age Generalization:** Converts raw ages into 5-year intervals (`45-49`) that strictly contain the true age.
- **Location & PIN Rollup:** Generalizes residential addresses and villages to district level and masks 6-digit PIN codes to their 3-digit regional prefix (`229***`), eliminating high-risk demographic combinations.

### E. Operational Security & Side-Channel Hygiene
- **Zero Secret Leakage:** `RAKSHA_SECRET` is read directly from the environment and never written to disk, output records, logs, or reports.
- **Zero PII Side-Channels:** Terminal output emits only aggregate file and record counts. Error reasons contain only safe ASCII identifiers without file contents or entity mentions.

---

## 5. Running & Verification Instructions

### Requirements & Setup
Python 3.10+ on CPU-only Linux/Windows/macOS:
```bash
# Setup dependencies (network allowed during setup)
pip install -r requirements.txt
```

### Running the Firewall
```bash
# Execute the pipeline (offline, no network required)
export RAKSHA_SECRET="practice"   # PowerShell: $env:RAKSHA_SECRET="practice"
python main.py --input dev/input --output my_output
```

### Validating Contract & Performance
```bash
# Verify output contract format (must print CONTRACT OK)
python validate_output.py --input dev/input --output my_output

# Run practice self-check against ground truth
python check_dev.py --output my_output --show 10

# Run official pre-submission compliance audit
python check_submission.py --repo .
```

---

## 6. Measured Benchmark Results

Evaluated against the official small dataset profile (200 files, 48 patients, 4 hospitals, 4 canaries):

| Benchmark Metric | Starter Baseline | RAKSHA Implementation | Status / Target |
|---|---|---|---|
| **Contract Validation** | `CONTRACT OK` | `CONTRACT OK` | Compliant |
| **Pre-Submit Audit** | Failed | `READY TO SUBMIT` | Passed |
| **Files Processed** | 200 Total / 195 Sanitized / 5 Quarantined | 200 Total / 192 Sanitized / 8 Quarantined | Safe Fail-Closed |
| **Raw Copies of Corrupt Files** | 0 | 0 | Zero Penalty |
| **Medical Values Preserved** | 4,855 / 4,855 (100.0%) | 4,855 / 4,855 (100.0%) | Full Utility |
| **Execution Wall Time** | 0.35s | 0.31s | Well under 15s budget |
| **Peak Memory (RSS)** | < 120 MB | < 120 MB | Well under 4,096 MB |
| **Repeat-Run Determinism** | Pass | Identical byte digest | Deterministic |
| **Secret-Keyed Variance** | Pass | Shifted IDs & dates | Key-Dependent |

---

## 7. Known Limitations & Future Enhancements

1. **Free-Text OCR Artifacts:** Severely broken character substitutions in unstructured nursing notes with no context clues are conservatively left or quarantined if undecodable.
2. **Ambiguous Homonyms:** When two patients in the same district share identical common names with no dates, phone numbers, or relative names in the note, RAKSHA assigns `patient: null` to prioritize precision over false merges.
3. **Complex Cross-Encounter Relational Inference:** Deep multi-hop family tree inference across third-party documents is bounded to direct patronymic/matronymic/spousal relationships.
