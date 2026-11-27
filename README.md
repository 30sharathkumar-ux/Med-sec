# RAKSHA --- Track 3: Secret Wards

**Adversarial Re-identification Resistance with Clinical-Utility
Preservation**\
**Yugaantar DevForge 2026 · Track 3: Secret Wards**

RAKSHA is an offline, CPU-only, LLM-free privacy firewall for synthetic
Indian hospital records. It is designed to detect personal information
across English, Hindi and Hinglish; preserve medically useful values;
link the same patient across files and hospitals without unsafe merges;
and reduce re-identification risk from quasi-identifiers and auxiliary
information.

> **Evaluation boundary:** Metrics below are project-reported
> practice-set or local synthetic-simulation results. They are not
> official hidden-dataset scores. The organizer's `raksha_eval`
> evaluator has not been run locally.

## 1. Track 3 Problem

A submission must remove personal information from structured fields and
free text; preserve medically useful values; recognize the same patient
across languages, files and hospitals without unsafe merges; reduce
re-identification risk from quasi-identifiers and outside knowledge; and
prevent leakage through outputs, logs, temporary files and errors.

An attacker may know approximate age, locality, diagnosis, visit date or
length of stay. Removing names alone is not sufficient.

## 2. Challenge-to-Solution Mapping

  -----------------------------------------------------------------------
  Requirement                         RAKSHA approach
  ----------------------------------- -----------------------------------
  English, Hindi and Hinglish PII     Script-aware rules, normalization,
                                      Devanagari--Latin handling and
                                      contextual detection

  Indian names, aliases and kinship   Name normalization,
  references                          transliteration, phonetic blocking
                                      and relationship-context rules

  Meaning-sensitive redaction         Context rules distinguish relatives
                                      from complaints, clinicians from
                                      patients, and medical values from
                                      identifiers

  Cross-file and cross-hospital       Evidence-based record linkage and
  identity                            secret-keyed HMAC pseudonyms

  Quasi-identifier risk               Adaptive age-band generalization,
                                      location generalization, PIN
                                      suppression and patient-level date
                                      shifting

  Hidden leakage channels             Sanitization/scanning of supported
                                      content, filenames, headers, JSON
                                      keys and metadata

  Malformed or unsupported files      Fail-closed quarantine rather than
                                      copying uncertain input into
                                      sanitized output

  Reproducibility and security        Environment-provided secret,
                                      deterministic transformations and
                                      PII-conscious logging
  -----------------------------------------------------------------------

## 3. Three-Layer Architecture

### SENTINEL --- Ingestion and safety

-   Discovers files and checks paths, encoding, format, depth and
    payload limits.
-   Rejects or quarantines malformed and unsupported inputs.
-   Preserves the expected output directory structure for supported
    files.

### IDENTITY GUARD --- Detection and linkage

-   Detects multilingual and contextual personal information.
-   Extracts identity evidence across files and hospitals.
-   Uses conservative patient resolution; ambiguous identities remain
    `null` rather than being force-merged.

### VAULT --- Privacy transformations and output checks

-   Generates purpose-separated, secret-keyed HMAC pseudonyms.
-   Applies date shifting and quasi-identifier generalization.
-   Applies adaptive profile-level generalization/suppression where
    configured and supported by the current implementation.
-   Checks sanitized outputs and produces reports.

## 4. Required Submission Contract

``` text
output/
├── sanitized/
├── report.json
└── records.jsonl
```

-   `sanitized/`: cleaned supported files, retaining supported formats
    and directory structure.
-   `report.json`: truthful file accounting, processing status, counts
    and resource information.
-   `records.jsonl`: record locator to pseudonymous patient ID mapping;
    ambiguous identity is `null`.

Unsafe or unsupported inputs must be quarantined rather than silently
passed through as sanitized.

## 5. Run and Verify

``` bash
pip install -r requirements.txt

# Linux / WSL
export RAKSHA_SECRET="replace-with-a-strong-random-secret"

# PowerShell
$env:RAKSHA_SECRET = "replace-with-a-strong-random-secret"

python main.py --input dev/input --output output
python validate_output.py --input dev/input --output output
python check_dev.py --output output --truth dev/truth/truth.json
python check_submission.py --repo . --run
```

Do not commit the secret or use a weak production fallback. Follow the
repository configuration and official Team Kit for the exact evaluation
invocation. The organizer's environment is offline, CPU-only and
LLM-free, with a stated limit of 2 CPUs, 4 GB RAM and 15 minutes. Hidden
datasets contain unseen names, labels and formats; practice results do
not guarantee hidden-set performance.

## 6. Reported Phase 3 Validation Snapshot

These are the latest Phase 3 results reported by the project team.
Reproduce them against the exact final commit before treating them as
final submission evidence.

  ------------------------------------------------------------------------
  Metric                             Reported result Evidence boundary
  --------------------- ---------------------------- ---------------------
  A1 development PII                       0 / 3,230 Local development
  leakage                                            checker

  Canary leakage                               0 / 4 Local development
                                                     checker

  A5 targeted                                 1 / 18 Local synthetic
  re-identification                                  simulation

  A6 dictionary                           0 / 10,800 Local synthetic
  inversions                                         simulation; not a
                                                     cryptographic proof

  A7 unique profile                           0 / 52 Local synthetic
  links                                              simulation; not zero
                                                     statistical
                                                     linkability

  Medical values                       4,313 / 4,313 Phase 3 truth-based
  preserved                                          report

  Dosage patterns                          859 / 859 Local clinical
  preserved                                          utility checks

  Inpatient                                  21 / 21 Local clinical
  length-of-stay checks                              utility checks

  Identity linkage         P=1.00, R=1.00, F0.5=1.00 Earlier development
                                                     check; confirm
                                                     against final Phase 3
                                                     run

  Automated tests                         219 passed Reported Windows test
                                                     run

  Submission checker                 READY TO SUBMIT Reported WSL2,
                                                     two-CPU run
  ------------------------------------------------------------------------

Earlier practice-set reports used a different medical-probe count
(4,855). The 4,313 Phase 3 figure belongs to a different truth-based
evaluation set; do not combine these denominators.

**Official evaluation status:** Exact official A1--A7 attack
probabilities and B-cubed F1 have not been independently measured
locally because the organizer's `raksha_eval` runner is not bundled in
the repository. Local attacker simulations must not be described as
official scores.

## 7. Privacy--Utility Trade-off

RAKSHA reduces the precision of selected quasi-identifiers while seeking
to retain clinical information. Transformations include age-band
generalization, location generalization, PIN suppression and
patient-level date shifting. A consistent patient-level date shift is
intended to preserve encounter intervals and length-of-stay durations.

Adaptive profile-level generalization and suppression are reported as
implemented in the later hardening phase. This is not a blanket
guarantee that every exported dataset satisfies a formal k-anonymity
threshold. Actual equivalence classes and residual linkage risk must be
measured on each output.

## 8. Security Design and Limitations

-   `RAKSHA_SECRET` must be supplied securely through the environment
    and must not be committed, logged or written to reports.
-   HMAC-SHA256 uses separate purpose prefixes for pseudonym, date-shift
    and filename-tag derivations.
-   Runtime network calls and hosted AI services are not part of the
    design.
-   Unsafe or unsupported inputs should be quarantined, not silently
    passed through as clean.
-   Local simulations do not establish formal cryptographic security or
    complete anonymity.
-   Profile-based linkage may remain possible even when pseudonyms
    differ across releases.
-   Unseen regional names, unfamiliar identifiers and novel file
    structures may reduce detection or linkage quality.
-   Ambiguous records should remain unlinked rather than risk a false
    merge.

## 9. Alignment with the Scoring Rubric

  ------------------------------------------------------------------------
  Scoring category                            Weight RAKSHA focus
  --------------------- ---------------------------- ---------------------
  Privacy against                                 25 Reduce direct and
  attacks                                            quasi-identifier
                                                     linkage; official
                                                     attack scores pending

  Personal-data                                   20 Multilingual content
  detection                                          and hidden-surface
                                                     detection with
                                                     context safeguards

  Medical-data                                    20 Preserve medicines,
  preservation                                       doses, vitals, labs,
                                                     diagnoses and stay
                                                     intervals

  Patient identity                                15 Stable pseudonyms and
  consistency                                        conservative linkage;
                                                     avoid false merges

  Output quality and                              10 Required outputs,
  validity                                           valid formats,
                                                     truthful reports and
                                                     quarantine

  Speed and reliability                           10 Deterministic
                                                     execution, runtime,
                                                     memory and
                                                     repeatability
  ------------------------------------------------------------------------

**Project positioning:** RAKSHA targets **Adversarial Re-identification
Resistance with Clinical-Utility Preservation**---protecting patient
identity without destroying the clinical value of the records.

**Repository:** https://github.com/30sharathkumar-ux/Med-sec\
**Track:** Yugaantar DevForge 2026 --- Track 3: Secret Wards
