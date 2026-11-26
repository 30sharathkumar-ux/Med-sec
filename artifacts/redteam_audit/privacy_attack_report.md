# RAKSHA — Privacy & Re-Identification Attack Report

## Dependencies
- `anonymeter`: `NOT_INSTALLED`
- `pycanon`: `NOT_INSTALLED`
- **Local Synthetic Checks Executed:** Voter-list-style quasi-identifier equivalence class & k-anonymity check (`PRIV-01`), HMAC determinism & secret-rotation checks (`SEC-01`, `SEC-02`), and cross-hospital/homonym linkage checks (`LINK-01..03`).

## Observed Results
- **Secret Rotation & Cross-Release Unlinkability (`SEC-01`, `SEC-02`):** `PASS` — identical secret produced identical output tree SHA-256; rotating secret (`SECRET_1` → `SECRET_2`) changed all pseudonyms and shifted dates.
- **Quasi-Identifier Generalization (`CLIN-12`, `CLIN-13`, `PRIV-01`):**
  - Ages `47` and `62` generalized to `45-49` and `60-64`.
  - Admission/discharge dates shifted consistently per patient, preserving exact `7`-day length of stay.
  - On the 4-row synthetic `hosp_alpha_reg.csv` alone, `min k-anonymity = 1` across `(age, gender, village, pin)` because 4 distinct synthetic individuals had distinct `(age_band, village, pin)` tuples; note that on small datasets (`n < 5`), rare combinations cannot achieve `k >= 5` without full suppression.
- **Linkage Attack Resistance (`LINK-01..03`):**
  - P1 linked across CSV, TSV, nested JSON, and FHIR R4 JSON to a single pseudonym (`PSN-5QM5RR`).
  - Homonyms (`Sunita Verma`, ages 56 vs 31, different villages/phones) remained separated (`PSN-VD8E3Q != PSN-G3FEGV`).
  - Ambiguous single-mention `Asha` remained `patient: null`.
- **Caveat:** Synthetic local checks do not reproduce the organizers' hidden attacker.
