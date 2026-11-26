# Team RAKSHA: Offline Multilingual Medical Privacy Firewall

**Track 3 · Secret Wards** · Repo: [team-raksha](https://github.com/team-raksha)

## 1. In one paragraph

RAKSHA is an offline, CPU-only, LLM-free privacy firewall that de-identifies Indian hospital records across English, Hindi, and Hinglish. Unlike off-the-shelf PII tools that miss Indian name structures and multilingual text, RAKSHA combines rule-based detection, Indian name gazetteers, Devanagari–Latin transliteration, phonetic blocking, and contextual intelligence to remove personal data while preserving every medical value exactly. Its three-layer architecture—SENTINEL for ingestion, IDENTITY GUARD for detection and cross-file patient linking, and VAULT for privacy transformation—processes 200 files in under 3 seconds with 32 MB RAM, achieves zero content PII leaks, zero wrong merges, and 100% medical value preservation on the practice dataset.

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        RAKSHA Pipeline                               │
│                                                                      │
│  ┌────────────────┐   ┌─────────────────┐   ┌────────────────────┐  │
│  │   SENTINEL      │   │  IDENTITY GUARD  │   │      VAULT         │  │
│  │  (Layer 1)      │──▶│    (Layer 2)     │──▶│    (Layer 3)       │  │
│  │                 │   │                  │   │                    │  │
│  │ • Encoding      │   │ • Name detection │   │ • HMAC pseudonyms  │  │
│  │ • Format sniff  │   │ • ID detection   │   │ • Date shifting    │  │
│  │ • Quarantine    │   │ • Context rules  │   │ • Age banding      │  │
│  │ • Hidden PII    │   │ • Linkage        │   │ • Location gen.    │  │
│  └────────────────┘   └─────────────────┘   └────────────────────┘  │
│                                                                      │
│  Input ──▶  sanitized/  +  report.json  +  records.jsonl             │
└──────────────────────────────────────────────────────────────────────┘
```

**Two-pass design:** Pass 1 ingests all files and extracts evidence for identity resolution. Pass 2 applies PII detection, pseudonymization, and privacy transforms using resolved patient clusters.

## 3. How it works

- **Ingestion:** Reads CSV, TSV, JSON, FHIR R4 Bundles, and text notes. Detects UTF-8, UTF-8 BOM, UTF-16, and cp1252 encodings. Quarantines empty, oversized, malformed, and unsupported files (8/200 on practice data). Sanitizes filenames containing PII. Preserves relative folder structure.

- **Detection:** Multi-module engine combining: (1) regex-based identifier detection for Aadhaar, ABHA, PAN, MRN/UHID, phone, email, and insurance IDs; (2) Indian name gazetteers with honorific handling (ji, sahab, didi) and surname-first ordering; (3) contextual rules that distinguish "C/O Ramesh" (relative) from "C/O fever" (complaint), preserve "Dr. Ramesh", keep "Ramipril 5 mg", "1-0-1" dosages, and "Parkinson's disease"; (4) hidden-surface inspection of CSV headers, JSON keys, filenames, metadata paths, and Base64 payloads; (5) Devanagari–Latin transliteration for Hindi name detection.

- **Linkage & pseudonyms:** Evidence-based identity resolution using name normalization, phonetic keys (Soundex-like), Devanagari transliteration, and fuzzy matching via `rapidfuzz`. Blocking by phonetic key and normalized identifiers prevents O(n²) comparisons. Conservative matching: conflicting DOB or identifiers prevent merges; insufficient evidence → `patient: null`. HMAC-SHA256 keyed pseudonyms (format: `PSN-XXXXXXXX`) ensure non-reversibility and cross-release unlinkability.

- **Privacy layer:** Per-patient deterministic date shifting (±180 days via HMAC), 5-year age banding, village → district generalization, PIN → 3-digit prefix, house/locality suppression. Date shifts are uniform per patient, preserving exact stay durations. Different `RAKSHA_SECRET` → different pseudonyms and shifts.

- **Security:** Fully in-memory processing — no raw intermediate files written to disk. Secret read from `RAKSHA_SECRET` env var, never cached or logged. PII-free stdout (counts only). Quarantine design for unsafe files. No `tempfile` usage.

## 4. USP

- **True multilingual detection:** Handles Mohammad/Mohd/Md./मोहम्मद as the same person; detects S/o, D/o, W/o and Hindi kinship frames (पत्नी, बेटा); processes mixed English-Hindi-Hinglish text in the same record — capabilities that off-the-shelf PII tools lack entirely.

- **Context-aware clinical preservation:** Understands that "Ramipril" is a drug not a name, "1-0-1" is a dosage not an ID, and "Parkinson's" is a disease not a person. Achieves 100% medical value preservation with zero content PII leaks.

- **Sub-3-second, 32 MB processing:** No model loading, no GPU, no network — pure algorithmic approach. 364× faster and 130× lighter than resource limits, ensuring reliability even on constrained evaluation hardware.

## 5. Privacy–utility trade-off (measured on practice data)

| Measure | Value |
|---|---|
| Personal data leaked (content / Hindi / Hinglish) | 0.0% / 0.0% / 0.0% |
| Medical values kept | 100.0% (4671/4671 matched probes) |
| Linking precision / recall / F0.5 | 1.00 / 0.70 / 0.92 |
| Wrong patient merges | 0 |
| Re-identification risk estimate | Low: 5-year age bands + district-level geography + ±180-day date shift |
| Run time / peak memory | 2.47s / 31.6 MB |
| On unseen data (expected) | Detection gaps likely for unseen name patterns and formats; linkage precision prioritized over recall to avoid false merges |

We chose conservative settings: 5-year age bands and district-level location generalization sacrifice some research granularity but substantially reduce the quasi-identifier attack surface. Per-patient date shifting preserves temporal intervals exactly (a 9-day stay remains 9 days) while preventing calendar-based re-identification. The trade-off is deliberate: in a medical privacy context, false safety (missed PII) is far worse than over-generalization.

## 6. Known limitations

- **Unseen name patterns:** The gazetteer and rules are tuned on practice data. Unusual names, new ID formats, or labels never seen in training data will reduce recall on hidden datasets.
- **Rare diagnosis + small population:** While age banding and location generalization provide strong protection, a unique diagnosis in a small district may still enable re-identification.
- **No classical ML NER:** Detection relies on rules and gazetteers rather than CRF/spaCy models. This keeps the system fast and dependency-light but may miss edge cases a trained model would catch.
- **Recall vs precision trade-off:** F0.5 = 0.92 reflects our deliberate choice to prioritize precision (zero wrong merges) over recall (some patients left unlinked). On hidden data with more ambiguous cases, recall may drop further.
