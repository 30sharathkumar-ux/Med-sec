# RAKSHA — Final Submission Checklist

- [x] **Submission Contract (`raksha.toml`, `main.py`, `requirements.txt`, `config/policy.yaml`):** Verified by `check_submission.py --repo . --run` → `READY TO SUBMIT`.
- [x] **Project Brief PDF (`brief/PROJECT_BRIEF.pdf`):** Verified **exact 2 pages** via `pypdf.PdfReader`.
- [x] **README Documentation (`README.md`):** Updated with architecture Mermaid diagram, setup/run/test commands, verified metrics, and honest limitations.
- [x] **Architecture Diagram Source (`docs/architecture.mmd`):** Created and aligned with `README.md` and `PROJECT_BRIEF.pdf`.
- [x] **Automated Test Suite (`pytest tests/`):** `199 passed in 10.47s` (including 8 doctor qualification & context trap tests).
- [x] **Medical Preservation (`check_dev.py`):** `4,855 / 4,855` (`100.0%`), including `Dr. Ramesh Srivastava (MD Medicine)`, `Dr. Anil Kumar MD Cardiology`, `Dr. Anil Kumar, MD, Cardiology`, `Ramipril 5mg`, `Dolo 650 BD x 5 days`, `1-0-1`, `Parkinson's disease`.
- [x] **PII & Canary Leakage (`check_dev.py`):** `0 / 3,230` (`0.0%`) across all scripts and channels; `0 / 4` canaries.
- [x] **Identity Linkage (`check_dev.py`):** Precision `1.00`, Recall `1.00`, F0.5 `1.00`, `0` wrong merges.
- [x] **Output Contract (`validate_output.py`):** `CONTRACT OK` (`192` sanitized + `8` quarantined = `200/200`, `0` raw copies).
- [x] **Resource & Offline Compliance:** `6.64s` runtime, `31.0 MB` peak RSS, `taskset -c 0,1` 2-CPU Linux verified, zero LLMs, zero network calls.
- [x] **Source & Truth Integrity:** `dev/`, `check_dev.py`, `validate_output.py`, `check_submission.py`, `scoring.toml` untouched.
- [ ] **Git Commit & Push:** Awaiting user review/approval of local changes (`git status --short`).
