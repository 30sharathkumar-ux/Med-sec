# RAKSHA Phase 4 — Final Performance Report

## Environment & Constraints

- **Target constraints**: Fully offline, CPU-only, max 2 CPUs, max 4 GB RAM, max 15 minutes (900s), no LLMs or hosted AI APIs, deterministic under `RAKSHA_SECRET`.
- **Verification environment**: WSL2 Ubuntu under `taskset -c 0,1` (2-CPU cap) via `check_submission.py --repo . --run`.

## Measured Performance

| Metric | Measured Value | Official Threshold (Good / Limit) |
|--------|----------------|-----------------------------------|
| **WSL2 2-CPU Submission Run (`check_submission.py`)** | **10.5s** (3 runs verified) | 60s / 900s |
| **Peak Memory RSS (`report.json`)** | **~31 MB** | 512 MB / 4,096 MB |
| **Determinism** | Identical `sanitized/` and `records.jsonl` for same secret | Required |
| **Secret Keying** | Different output for different `RAKSHA_SECRET` | Required |
| **Secret Isolation** | `RAKSHA_SECRET` never written to output or logs | Required |
| **Automated Test Suite (`pytest`)** | 219+ tests passing in ~14s | All passing |
