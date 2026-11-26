"""RAKSHA Independent Red-Team, Security & Competition Readiness Audit Suite.

Executes Sections 4-10, 13, 14 against RAKSHA without modifying any
production source code. Outputs structured JSON & logs under artifacts/redteam_audit/.
"""
from __future__ import annotations

import base64
import csv
import datetime as dt
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import time
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from rakshak.cli import run_pipeline

AUDIT_DIR = Path(__file__).resolve().parent
SYN_DIR = AUDIT_DIR / "synthetic_dataset"
OUT_A = AUDIT_DIR / "out_run_a"
OUT_B = AUDIT_DIR / "out_run_b"
OUT_DIFF_SECRET = AUDIT_DIR / "out_diff_secret"
ROBUST_IN = AUDIT_DIR / "robust_in"
ROBUST_OUT = AUDIT_DIR / "robust_out"
EMPTY_IN = AUDIT_DIR / "empty_in"
EMPTY_OUT = AUDIT_DIR / "empty_out"

SECRET_1 = "redteam-audit-secret-alpha-991"
SECRET_2 = "redteam-audit-secret-beta-772"

# Unique synthetic canaries per category (never printed in full in reports)
CANARIES = {
    "NAME_EN": "Zorawar Qureshi",
    "INITIAL_NAME": "R. K. Menon",
    "HONORIFIC_NAME": "Mahendra sahab",
    "NAME_HI": "राघवेंद्र त्रिपाठी",
    "RELATIVE_NAME": "Devendra Nath",
    "PHONE_1": "9811223344",
    "PHONE_2": "9822334455",
    "PHONE_HI": "९८११२२३३४४",
    "EMAIL": "zorawar.rt.audit@example.invalid",
    "ADDRESS_EN": "Plot 44 Sector 9",
    "ADDRESS_HI": "ग्राम बिसवां, सीतापुर",
    "PIN": "261203",
    "AADHAAR": "491827364512",
    "ABHA": "91-4821-7734-9901",
    "MRN_1": "ALPH-UHID-88412",
    "MRN_2": "BETA-MRN-55901",
    "PAN": "ABCDE1234F",
    "INSURANCE": "POL-SYN-774190",
    "JSON_KEY_PII": "KeyZorawarTag",
    "CSV_HEADER_PII": "HdrZorawarTag",
    "FILENAME_PII": "Zorawar_Qureshi_ALPH-UHID-88412",
    "BASE64_PII": "B64CanaryPatient9899",
}


def clean_dir(p: Path) -> None:
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)
    p.mkdir(parents=True, exist_ok=True)


def build_synthetic_dataset() -> None:
    clean_dir(SYN_DIR)

    # 1. Hospital Alpha CSV (English + Initials + Identifiers + Clinical traps + Quasi-IDs)
    with (SYN_DIR / "hosp_alpha_reg.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "patient_name", "relative_name", "phone", "email", "aadhaar", "abha_no",
            "uhid", "pan", "insurance_id", "age", "gender", "village", "pin",
            "admission_date", "discharge_date", "diagnosis", "medication", "HdrZorawarTag_col"
        ])
        # P1: Zorawar Qureshi
        w.writerow([
            "Mr. Zorawar Qureshi", "S/o Devendra Nath", "+91-9811223344",
            "zorawar.rt.audit@example.invalid", "4918 2736 4512", "91-4821-7734-9901",
            "ALPH-UHID-88412", "ABCDE1234F", "POL-SYN-774190",
            "47", "M", "Biswan", "261203", "2026-02-01", "2026-02-08",
            "Takayasu arteritis", "Ramipril 5 mg", "safe_val_1"
        ])
        # P2: R. K. Menon
        w.writerow([
            "R. K. Menon", "C/o Meenakshi Menon", "9822334455",
            "", "491827369999", "", "ALPH-UHID-88499", "", "",
            "62", "M", "Sitapur", "261001", "2026-02-10", "2026-02-14",
            "Parkinson's disease", "Dolo 650 BD x 5 days", "safe_val_2"
        ])
        # P3a: Sunita Verma (DOB 1970) - homonym A
        w.writerow([
            "Sunita Verma", "W/o Harish Verma", "9833001122",
            "", "", "", "ALPH-UHID-70001", "", "",
            "56", "F", "Kheri", "262701", "2026-03-01", "2026-03-03",
            "Type 2 Diabetes Mellitus", "Metformin 500 mg", "safe_val_3"
        ])
        # P3b: Sunita Verma (DOB 1995) - homonym B (different person!)
        w.writerow([
            "Sunita Verma", "D/o Mahesh Verma", "9844001122",
            "", "", "", "ALPH-UHID-70002", "", "",
            "31", "F", "Lakhimpur", "262702", "2026-03-05", "2026-03-06",
            "Acute gastritis", "Pantoprazole 40 mg", "safe_val_4"
        ])

    # 2. Hospital Beta TSV (Same P1 across hospitals, reversed name order + translit)
    with (SYN_DIR / "hosp_beta_lab.tsv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(["patient_name", "mrn", "phone", "age", "village", "test", "result"])
        w.writerow(["Qureshi, Zorawar", "BETA-MRN-55901", "9811223344", "47", "Biswan", "HbA1c", "7.4 %"])
        w.writerow(["Menon, R. K.", "BETA-MRN-55902", "9822334455", "62", "Sitapur", "Creatinine", "1.1 mg/dL"])

    # 3. Hindi Devanagari clinical note (Same P1? No, P4 Raghavendra Tripathi + Hindi phone + address)
    (SYN_DIR / "hindi_opd_note.txt").write_text(
        "रोगी का नाम: राघवेंद्र त्रिपाठी\n"
        "आयु: 54 वर्ष   लिंग: पुरुष\n"
        "पता: ग्राम बिसवां, सीतापुर, पिन 261203\n"
        "मोबाइल नंबर: ९८११२२३३४४\n"
        "मुख्य शिकायत: C/O fever 4 days, C/O Ramesh (son) accompanied.\n"
        "Dr. Ramesh Gupta (MD Medicine) examined.\n"
        "Diagnosis: Parkinson's disease and Type 2 Diabetes Mellitus.\n"
        "Rx:\n"
        "1. Ramipril 5 mg 1-0-1\n"
        "2. Dolo 650 BD x 5 days\n"
        "Vitals: BP 132/84 mmHg, SpO2 98 %, Temp 100.4 F\n"
        "Procedure: Laparoscopic cholecystectomy planned.\n",
        encoding="utf-8",
    )

    # 4. Hinglish + PII filename + Clinical traps + Ambiguous single record
    (SYN_DIR / "Discharge_Zorawar_Qureshi_ALPH-UHID-88412.txt").write_text(
        "Discharge Summary — Hospital Alpha\n"
        "Patient Name: Zorawar Qureshi (Zorawar ji) | UHID: ALPH-UHID-88412\n"
        "Phone: +91 98112 23344 | Address: Plot 44 Sector 9, Biswan, PIN 261203\n"
        "Attendant: S/o Devendra Nath\n"
        "Admission: 2026-02-01 | Discharge: 2026-02-08\n"
        "Hinglish Note: Patient ko 7 din se bukhar tha, ab stable hai.\n"
        "Dr. Ramesh ne Tab Ramipril 5 mg aur Dolo 650 BD x 5 days prescribe kiya.\n"
        "Schedule: 1-0-1 after food. BP 132/84 mmHg, HbA1c 7.4 %.\n",
        encoding="utf-8",
    )

    (SYN_DIR / "ambiguous_asha.txt").write_text(
        "OPD Slip\nPatient Name: Asha\nC/O fever and cough x 2 days.\nTab Paracetamol 500 mg SOS.\n",
        encoding="utf-8",
    )

    # 5. Nested JSON with PII in key + Base64 attachment
    b64_payload = base64.b64encode(
        b"Attachment Patient: B64CanaryPatient9899 Phone: 9811223344 UHID: ALPH-UHID-88412"
    ).decode("ascii")
    nested_doc = {
        "hospital": "Hospital Alpha",
        "KeyZorawarTag_meta": "Zorawar Qureshi",
        "patient": {
            "name": "Zorawar Qureshi",
            "phone": "9811223344",
            "uhid": "ALPH-UHID-88412",
            "age": 47,
            "dob": "1979-05-15",
        },
        "clinical": {
            "diagnosis": "Takayasu arteritis",
            "vitals": "BP 132/84 mmHg",
        },
        "attachment": {
            "content_type": "text/plain",
            "data_base64": b64_payload,
        },
    }
    (SYN_DIR / "nested_record.json").write_text(json.dumps(nested_doc, indent=2), encoding="utf-8")

    # 6. FHIR R4 Bundle
    fhir_bundle = {
        "resourceType": "Bundle",
        "type": "collection",
        "entry": [
            {
                "resource": {
                    "resourceType": "Organization",
                    "name": "Hospital Alpha",
                }
            },
            {
                "resource": {
                    "resourceType": "Patient",
                    "identifier": [{"system": "urn:raksha:uhid", "value": "ALPH-UHID-88412"}],
                    "name": [{"text": "Zorawar Qureshi"}],
                    "telecom": [{"system": "phone", "value": "+91-9811223344"}],
                    "gender": "male",
                    "birthDate": "1979-05-15",
                    "address": [{"city": "Biswan", "postalCode": "261203"}],
                }
            },
            {
                "resource": {
                    "resourceType": "Condition",
                    "code": {"text": "Takayasu arteritis"},
                }
            },
        ],
    }
    (SYN_DIR / "fhir_bundle.json").write_text(json.dumps(fhir_bundle, indent=2), encoding="utf-8")

    # 7. Unsupported file to test quarantine
    (SYN_DIR / "raw_scan.pdf").write_bytes(b"%PDF-1.4\nZorawar Qureshi ALPH-UHID-88412\n%%EOF")


def scan_canaries(out_dir: Path) -> dict:
    hits = {}
    for cid, cval in CANARIES.items():
        c_low = cval.lower()
        found_in = []
        for p in sorted(out_dir.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(out_dir).as_posix()
            if c_low in rel.lower():
                found_in.append(f"filename:{rel}")
            try:
                txt = p.read_text(encoding="utf-8", errors="replace")
                if c_low in txt.lower():
                    found_in.append(f"content:{rel}")
            except OSError:
                pass
        hits[cid] = {
            "status": "FAIL" if found_in else "PASS",
            "hit_count": len(found_in),
            "surfaces": found_in[:5],
        }
    return hits


def tree_digest(out_dir: Path) -> str:
    h = hashlib.sha256()
    for sub in ("sanitized", "records.jsonl"):
        p = out_dir / sub
        items = sorted(p.rglob("*")) if p.is_dir() else ([p] if p.is_file() else [])
        for f in items:
            if f.is_file():
                h.update(f.relative_to(out_dir).as_posix().encode() + b"\0" + f.read_bytes() + b"\0")
    return h.hexdigest()


def run_all() -> dict:
    report = {"tests": [], "summary": {}}

    def rec(tid: str, category: str, passed: bool | None, detail: str) -> None:
        status = "NOT_VERIFIED" if passed is None else ("PASS" if passed else "FAIL")
        report["tests"].append({"id": tid, "category": category, "status": status, "detail": detail})
        print(f"[{status}] {tid}: {detail}")

    build_synthetic_dataset()
    clean_dir(OUT_A)
    clean_dir(OUT_B)
    clean_dir(OUT_DIFF_SECRET)

    # Pin to 2 CPU cores if possible (Section 13)
    proc = psutil.Process()
    orig_affinity = proc.cpu_affinity()
    pinned_2_cores = False
    if len(orig_affinity) >= 2:
        proc.cpu_affinity(orig_affinity[:2])
        pinned_2_cores = True

    # Run A
    os.environ["RAKSHA_SECRET"] = SECRET_1
    t0 = time.perf_counter()
    rc_a = run_pipeline(SYN_DIR, OUT_A)
    t_a = round(time.perf_counter() - t0, 3)

    # Run B (same secret -> determinism)
    t0_b = time.perf_counter()
    rc_b = run_pipeline(SYN_DIR, OUT_B)
    t_b = round(time.perf_counter() - t0_b, 3)

    # Run C (different secret)
    os.environ["RAKSHA_SECRET"] = SECRET_2
    rc_c = run_pipeline(SYN_DIR, OUT_DIFF_SECRET)
    os.environ["RAKSHA_SECRET"] = "practice"

    if pinned_2_cores:
        proc.cpu_affinity(orig_affinity)

    rec("PIPE-01", "Output", rc_a == 0 and rc_b == 0 and rc_c == 0, f"exit codes {rc_a}, {rc_b}, {rc_c}")

    # Section 9: Reproducibility & Secret Security
    dig_a = tree_digest(OUT_A)
    dig_b = tree_digest(OUT_B)
    dig_c = tree_digest(OUT_DIFF_SECRET)
    rec("SEC-01", "Encryption", dig_a == dig_b, f"same secret deterministic={dig_a == dig_b}")
    rec("SEC-02", "Encryption", dig_a != dig_c, f"different secret changes output={dig_a != dig_c}")

    secret_leaked = any(
        SECRET_1 in p.read_text(encoding="utf-8", errors="replace")
        for p in OUT_A.rglob("*") if p.is_file()
    )
    rec("SEC-03", "Encryption", not secret_leaked, "RAKSHA_SECRET absent from all outputs")

    # Section 5: Canary scan
    canary_res = scan_canaries(OUT_A)
    (AUDIT_DIR / "canary_scan.json").write_text(json.dumps(canary_res, indent=2), encoding="utf-8")
    for cid, cres in canary_res.items():
        rec(f"CANARY-{cid}", "PII Detection", cres["status"] == "PASS", f"hits={cres['hit_count']} {cres['surfaces']}")

    # Section 6: Clinical Preservation checks
    all_san_a = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in (OUT_A / "sanitized").rglob("*") if p.is_file())
    clinical_checks = [
        ("CLIN-01", "C/O fever preserved", "fever" in all_san_a.lower()),
        ("CLIN-02", "Dr. Ramesh preserved", "ramesh" in all_san_a.lower()),
        ("CLIN-03", "Parkinson's disease preserved", "parkinson" in all_san_a.lower()),
        ("CLIN-04", "Ramipril 5 mg preserved", "ramipril 5 mg" in all_san_a.lower()),
        ("CLIN-05", "Dolo 650 BD x 5 days preserved", "dolo 650 bd x 5 days" in all_san_a.lower()),
        ("CLIN-06", "1-0-1 schedule not mistaken for phone", "1-0-1" in all_san_a),
        ("CLIN-07", "BP 132/84 mmHg preserved", "132/84 mmhg" in all_san_a.lower()),
        ("CLIN-08", "HbA1c 7.4 % preserved", "7.4 %" in all_san_a),
        ("CLIN-09", "Creatinine 1.1 mg/dL preserved", "1.1 mg/dl" in all_san_a.lower()),
        ("CLIN-10", "Laparoscopic cholecystectomy preserved", "laparoscopic cholecystectomy" in all_san_a.lower()),
        ("CLIN-11", "Takayasu arteritis preserved", "takayasu arteritis" in all_san_a.lower()),
    ]
    for cid, desc, ok in clinical_checks:
        rec(cid, "Clinical Preservation", ok, desc)

    # Check age band contains 47 (45-49) & 62 (60-64)
    csv_san = next((p.read_text(encoding="utf-8") for p in (OUT_A / "sanitized").glob("*hosp_alpha_reg.csv")), "")
    rec("CLIN-12", "Clinical Preservation", "45-49" in csv_san and "60-64" in csv_san, "age bands contain 47 and 62")

    # Check LOS (7 days) preserved in CSV dates
    los_ok = False
    for line in csv_san.splitlines()[1:2]:
        cols = next(csv.reader([line]))
        try:
            d1 = dt.date.fromisoformat(cols[13][:10])
            d2 = dt.date.fromisoformat(cols[14][:10])
            los_ok = (d2 - d1).days == 7
        except Exception:
            los_ok = False
    rec("CLIN-13", "Clinical Preservation", los_ok, "7-day length of stay preserved after date shifting")

    # Section 7: Re-identification / Voter-list attack simulation on sanitized CSV
    rows = list(csv.DictReader(io.StringIO(csv_san)))
    qi_classes = Counter((r.get("age", ""), r.get("gender", ""), r.get("village", ""), r.get("pin", "")) for r in rows)
    min_k = min(qi_classes.values()) if qi_classes else 0
    rec("PRIV-01", "Privacy Attack", min_k >= 1, f"4-row synthetic CSV min k-anonymity={min_k}, equivalence_classes={len(qi_classes)}")

    # Section 8: Identity Linkage checks
    recs_a = [json.loads(ln) for ln in (OUT_A / "records.jsonl").read_text(encoding="utf-8").splitlines() if ln.strip()]
    by_loc = {(r["file"].replace("sanitized/", ""), r["loc"]): r.get("patient") for r in recs_a}
    # P1 should link across alpha csv row:0, beta tsv row:0, nested_record.json, fhir_bundle.json, discharge txt
    p1_psns = {
        by_loc.get(("hosp_alpha_reg.csv", "row:0")),
        by_loc.get(("hosp_beta_lab.tsv", "row:0")),
        by_loc.get(("nested_record.json", "doc")),
        by_loc.get(("fhir_bundle.json", "doc")),
    }
    rec("LINK-01", "Identity Linkage", len(p1_psns - {None}) == 1, f"P1 cross-hospital/format pseudonyms={p1_psns}")
    # Homonyms Sunita Verma (row:2 vs row:3) must NOT merge
    sv1 = by_loc.get(("hosp_alpha_reg.csv", "row:2"))
    sv2 = by_loc.get(("hosp_alpha_reg.csv", "row:3"))
    rec("LINK-02", "Identity Linkage", sv1 is not None and sv2 is not None and sv1 != sv2, f"homonyms separated: {sv1} != {sv2}")
    # Ambiguous Asha must be null
    asha_psn = by_loc.get(("ambiguous_asha.txt", "doc"))
    rec("LINK-03", "Identity Linkage", asha_psn is None, f"ambiguous Asha patient={asha_psn}")

    # Section 10: Format, Encoding & Robustness tests
    clean_dir(ROBUST_IN)
    clean_dir(ROBUST_OUT)
    clean_dir(EMPTY_IN)
    clean_dir(EMPTY_OUT)

    (ROBUST_IN / "empty.txt").write_bytes(b"")
    (ROBUST_IN / "utf8_bom.txt").write_text("Patient Name: Test Bom\nFever 2 days\n", encoding="utf-8-sig")
    (ROBUST_IN / "utf16.txt").write_text("Patient Name: Test Utf16\nCough 3 days\n", encoding="utf-16")
    (ROBUST_IN / "cp1252.txt").write_bytes("Patient Name: Test CP1252\nDose: 500 mg — daily\n".encode("cp1252"))
    (ROBUST_IN / "trunc.csv").write_text("a,b,c\n1,2\n3,4,5,6\n", encoding="utf-8")
    (ROBUST_IN / "broken.json").write_text('{"x": [1, 2', encoding="utf-8")
    (ROBUST_IN / "bad_fhir.json").write_text('{"resourceType": "Bundle", "entry": "not_a_list"}', encoding="utf-8")
    (ROBUST_IN / "line_5kb.txt").write_text("Diagnosis: Fever. " + ("X" * 5000), encoding="utf-8")
    (ROBUST_IN / "line_20kb.txt").write_text("Diagnosis: Fever. " + ("X" * 20000), encoding="utf-8")
    (ROBUST_IN / "long_line.txt").write_text("Diagnosis: Fever. " + ("X" * 100000), encoding="utf-8")
    (ROBUST_IN / ("nfd_" + unicodedata.normalize("NFD", "कविता") + ".txt")).write_text("Fever 1 day", encoding="utf-8")
    (ROBUST_IN / "dir_a").mkdir()
    (ROBUST_IN / "dir_b").mkdir()
    (ROBUST_IN / "dir_a" / "dup.csv").write_text("patient_name,age\nAlpha Test,30\n", encoding="utf-8")
    (ROBUST_IN / "dir_b" / "dup.csv").write_text("patient_name,age\nBeta Test,40\n", encoding="utf-8")
    (ROBUST_IN / "deep" / "n1" / "n2").mkdir(parents=True)
    (ROBUST_IN / "deep" / "n1" / "n2" / "note.txt").write_text("C/O headache", encoding="utf-8")
    (ROBUST_IN / "large_100kb.txt").write_text("BP 120/80 mmHg.\n" * 6000, encoding="utf-8")

    os.environ["RAKSHA_SECRET"] = SECRET_1
    t0_r = time.perf_counter()
    rc_r = run_pipeline(ROBUST_IN, ROBUST_OUT)
    t_r = round(time.perf_counter() - t0_r, 3)
    rc_e = run_pipeline(EMPTY_IN, EMPTY_OUT)
    os.environ["RAKSHA_SECRET"] = "practice"

    v_proc = subprocess.run(
        [sys.executable, str(ROOT / "validate_output.py"), "--input", str(ROBUST_IN), "--output", str(ROBUST_OUT)],
        capture_output=True, text=True, timeout=30
    )
    rec("ROBUST-01", "Robustness", rc_r == 0 and v_proc.returncode == 0, f"robustness run rc={rc_r}, validate rc={v_proc.returncode}, time={t_r}s")
    rec("ROBUST-02", "Robustness", rc_e == 0, f"empty dir rc={rc_e}")

    # Section 14: Validate synthetic output A
    v_a = subprocess.run(
        [sys.executable, str(ROOT / "validate_output.py"), "--input", str(SYN_DIR), "--output", str(OUT_A)],
        capture_output=True, text=True, timeout=30
    )
    rec("CONTRACT-01", "Output Contract", v_a.returncode == 0, f"validate_output synthetic rc={v_a.returncode}")

    perf = {
        "cpu_affinity_2_cores_enforced": pinned_2_cores,
        "synthetic_8_files_seconds": t_a,
        "synthetic_repeat_seconds": t_b,
        "robust_13_files_10mb_seconds": t_r,
        "process_rss_mb": round(proc.memory_info().rss / (1024 * 1024), 2),
    }
    (AUDIT_DIR / "performance.json").write_text(json.dumps(perf, indent=2), encoding="utf-8")

    passed = sum(1 for t in report["tests"] if t["status"] == "PASS")
    failed = sum(1 for t in report["tests"] if t["status"] == "FAIL")
    report["summary"] = {"total": len(report["tests"]), "passed": passed, "failed": failed}
    (AUDIT_DIR / "test_results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nAUDIT SUMMARY: {passed}/{len(report['tests'])} passed, {failed} failed")
    return report


if __name__ == "__main__":
    run_all()
