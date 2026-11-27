# RAKSHA — Offline Multilingual Medical Data Privacy Firewall

**Track 3 · Secret Wards** · Team: `POINT_BLANK` · Repo: https://github.com/30sharathkumar-ux/Med-sec

**Positioning:** *Adversarial Re-identification Resistance with Clinical-Utility Preservation*

---

## 1. The Challenge

Secret Wards asks teams to build an **offline, CPU-only, LLM-free privacy firewall** for synthetic Indian hospital records from four hospital systems, spanning English, Hindi and Hinglish. The system must remove personal information, preserve medically useful values exactly, link the same patient across languages/files/hospitals without false merges, and prevent leaks in outputs, logs, temporary files and errors.

The hidden attacker may combine quasi-identifiers—age, village, PIN, visit date, rare diagnosis and length of stay—with outside population knowledge. Removing names alone is not sufficient.

## 2. RAKSHA's Response to the Six Challenge Traps

| Track requirement | RAKSHA design response |
|---|---|
| **Language** — English, Hindi, Hinglish; aliases and transliteration | Script-aware rules, Devanagari–Latin normalization, name patterns and phonetic blocking. |
| **Meaning** — relative vs complaint; doctor vs patient; dose vs identifier | Context-sensitive clinical shields protect clinician credentials, diagnoses, medicines and dosage expressions. |
| **Fragmented identity** — stable IDs without false merges | Evidence-based cross-file linkage, keyed HMAC pseudonyms and null assignment when evidence is insufficient. |
| **Re-identification** — quasi-identifiers and attacker knowledge | Per-patient date shifts, age bands, district-level generalization and PIN-prefix masking reduce linkage clues. |
| **Clinical integrity** — preserve medical values and stay intervals | Practice-set medical checks; patient-level date shift is designed to preserve interval lengths. |
| **Hidden leakage** — filenames, headers, keys, metadata, attachments | Supported hidden surfaces are scanned/sanitized; unsafe inputs are quarantined. |

## 3. Three-Layer Architecture

- **SENTINEL:** Ingestion, encoding/format checks, depth and payload guards, fail-closed quarantine.
- **IDENTITY GUARD:** Multilingual PII/context detection, evidence extraction and conservative patient linkage.
- **VAULT:** Domain-separated HMAC pseudonyms, date shifts, quasi-identifier generalization and reporting.

Output contract: `sanitized/ + report.json + records.jsonl`. Unsupported/unsafe inputs are quarantined; ambiguous identity is `null`.

## 4. What Makes RAKSHA Different

RAKSHA treats privacy as a combined detection, identity and attacker-resistance problem—not a name-redaction task. Its differentiators are multilingual/contextual extraction, conservative identity resolution, domain-separated keyed pseudonymization, hidden-channel hygiene and an explicit privacy–utility balance.

## 5. Practice-Set Validation Snapshot

| Metric | Reported result |
|---|---|
| PII leakage | `0 / 3,230` (`0.0%`) |
| Canary leakage | `0 / 4` |
| Medical values preserved | `4,855 / 4,855` (`100.0%`) |
| Identity linkage | Precision `1.00` · Recall `1.00` · F0.5 `1.00` · `0` wrong merges |
| File accounting / raw copies | `192` sanitized + `8` quarantined = `200` · `0` raw copies |
| Contract / pre-submit audit | `CONTRACT OK` · `READY TO SUBMIT` |
| Tests / runtime / memory | `199 passed` · `6.64 s` · `31.0 MB` peak RSS |

> **Scope:** These are repository-reported results on the 200-file practice set, not hidden-dataset or official attacker scores.

## 6. Privacy–Utility Trade-off & Security Design

- **Trade-off:** Five-year age bands, village-to-district generalization, three-digit PIN prefixes and per-patient date shifts reduce the linkage surface while preserving clinical values and exact length-of-stay durations.
- **Security:** `RAKSHA_SECRET` is supplied through the environment and never committed, logged or written to output; HMAC-SHA256 uses separate purpose prefixes (`psn|`, `shift|`, `fname|`); malformed/unsupported inputs are quarantined fail-closed; runtime is offline, CPU-only and LLM-free.

## 7. Honest Limitations & Unverified Items

- **Official attacker evaluation:** The organizer's `raksha_eval` runner is not bundled in the repository. Exact official A1–A7 attack probabilities and B³ F1 are **not evaluated locally**.
- **Adaptive k-anonymity:** Helper/risk-analysis code exists, but record-level adaptive age widening/PIN suppression is **not actively enforced** in the current sanitized export.
- **Generalization & unseen data:** Unseen regional names, unfamiliar identifiers and novel file structures may reduce recall or linkage quality on the three hidden evaluation datasets.
