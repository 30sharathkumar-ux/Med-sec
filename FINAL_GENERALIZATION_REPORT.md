# RAKSHA Phase 4 — Final Generalization Report

## Scope

Documents generalization behavior across unseen formats, scripts, and edge cases, verified by `tests/test_hidden_generalization.py`, `tests/test_adversarial_a1_a7.py`, and `tests/test_k_anonymity.py`.

## Key Generalization Guarantees

1. **Dynamic Issuer Prefix Parsing**: MRNs across unseen hospital prefixes (`KGMU/`, `AIIMS/`, `APOLLO-`, `MAX-`) are parsed dynamically without hardcoded institution lists.
2. **Multilingual & Cross-Script Consistency**: Devanagari (`उम्र: 42 वर्ष/M`) and English (`Age/Sex: 42 Yrs/M`) free-text ages both band cleanly without double-banding under 5yr, 10yr, and 20yr adaptive widths.
3. **Adaptive 4-Tier Generalization**:
   - **Tier 0**: 5-year age band, 3-digit PIN prefix, district kept.
   - **Tier 1**: 10-year age band (`80+` cap for seniors), 2-digit PIN prefix, district kept.
   - **Tier 2**: 20-year age band (`80+` cap for seniors), PIN suppressed (`[PIN]`), district kept.
   - **Tier 3**: 20-year age band, PIN suppressed (`[PIN]`), district suppressed (`[DISTRICT]`) when class size `< min_group_size`.
4. **Cross-Platform Hash & Report Hygiene**: `rakshak/ingestion.py` computes both raw and LF-normalized SHA-256 hashes so Windows CRLF checkouts and Linux LF evaluators both validate cleanly without inflating `counts` in `report.json`.
