"""Comprehensive read-only validation script for RAKSHA (Sections A-H)."""
import csv
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from rakshak.cli import _clean_text_full
from rakshak.privacy.transforms import _parse_date
from rakshak.privacy.pseudonymize import generate_pseudonym

print("=== A. SPECIFIC MEDICAL PRESERVATION PROBES ===")
probes = [
    ("Dr. Ramesh Srivastava (MD Medicine)", "Patient Name: Mohammad Shahid\nConsultant: Dr. Ramesh Srivastava (MD Medicine)\n"),
    ("Dr. Anil Kumar MD Cardiology", "Patient Name: Md. Irfan\nConsultant: Dr. Anil Kumar MD Cardiology\n"),
    ("Dr. Anil Kumar, MD, Cardiology", "Patient Name: Md. Irfan\nConsultant: Dr. Anil Kumar, MD, Cardiology\n"),
    ("Ramipril 5mg", "Patient Name: Suresh Kumar\nRx: Tab Ramipril 5mg 1-0-1\n"),
    ("Dolo 650 BD x 5 days", "Patient Name: Suresh Kumar\nRx: Tab Dolo 650 BD x 5 days\n"),
    ("1-0-1", "Patient Name: Suresh Kumar\nDose: 1-0-1 after food\n"),
    ("Parkinson's disease", "Patient Name: Suresh Kumar\nDiagnosis: Parkinson's disease (G20)\n"),
]
for expected, sample in probes:
    out = _clean_text_full(sample, Counter())
    ok = expected in out
    print(f"  {expected}: preserved={ok}")

md_out = _clean_text_full("Patient Name: Md. Shahid\nS/o Md. Zubair\nFollow-up: Md. Shahid stable.\n", Counter())
print(f"  Genuine Md. patient redacted: {'Md. Shahid' not in md_out and 'Zubair' not in md_out}")

print("\n=== D. ADVERSARIAL PRIVACY CHECKS (A1-A7 vs raw_attack.json) ===")
raw_att = json.loads((ROOT / "dev/truth/raw_attack.json").read_text(encoding="utf-8"))["result"]
print("  Raw attack baseline (dev/truth/raw_attack.json):", json.dumps(raw_att))

# Check A1-A5 proxies on actual output/sanitized/ using registry.csv and known_facts.jsonl
san_dir = ROOT / "output/sanitized"
all_san = "\n".join(
    p.read_text(encoding="utf-8", errors="replace")
    for p in san_dir.rglob("*")
    if p.is_file() and p.suffix in (".txt", ".csv", ".tsv", ".json", ".jsonl")
)
all_san_low = all_san.lower()

with open(ROOT / "dev/attacker/registry.csv", encoding="utf-8") as f:
    reg = list(csv.DictReader(f))
facts = [json.loads(l) for l in (ROOT / "dev/attacker/known_facts.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]

a1_name_hits = sum(1 for r in reg if r["name"].strip() and len(r["name"].strip()) > 5 and r["name"].strip().lower() in all_san_low)
a1_phone_hits = sum(1 for r in reg if r["phone"].strip() and r["phone"].strip() in all_san)
a1_email_hits = sum(1 for r in reg if r["email"].strip() and r["email"].strip().lower() in all_san_low)
print(f"  A1 direct exposure on output/sanitized: names={a1_name_hits}, phones={a1_phone_hits}, emails={a1_email_hits}")

# A2/A3/A4: Check how many registry persons have surviving village or exact house_no
vill_hits = sum(1 for r in reg if r["village"].strip() and len(r["village"].strip()) > 4 and r["village"].strip().lower() in all_san_low)
print(f"  A2/A3 surviving registry village strings in output/sanitized: {vill_hits}/{len(reg)}")

# A6/A7: Pseudonym inversion & cross-release
psn_s1 = generate_pseudonym("phone:9876543210", b"practice")
psn_s2 = generate_pseudonym("phone:9876543210", b"other-secret")
print(f"  A6/A7 pseudonym secret-keyed: {psn_s1} != {psn_s2} -> {psn_s1 != psn_s2}")

print("\n=== E. PRIVACY-UTILITY TRADEOFF ===")
# Age banding in sanjeevani_registration.csv (uses 'age_band' or 'dob' or 'age')
with open(ROOT / "dev/input/registration/sanjeevani_registration.csv", encoding="utf-8-sig") as f:
    r_in = list(csv.reader(f))
with open(ROOT / "output/sanitized/registration/sanjeevani_registration.csv", encoding="utf-8-sig") as f:
    r_out = list(csv.reader(f))
h_in, rows_in = r_in[0], r_in[1:]
h_out, rows_out = r_out[0], r_out[1:]
print(f"  sanjeevani_registration.csv header: {h_in}")
if "age" in h_in:
    ai = h_in.index("age")
    ok_age = sum(
        1 for ri, ro in zip(rows_in, rows_out)
        if (m := re.match(r"^(\d+)-(\d+)$", ro[ai])) and int(m.group(1)) <= int(ri[ai]) <= int(m.group(2))
    )
    print(f"  Age banding truthful: {ok_age}/{len(rows_in)}")
if "village" in h_in and "district" in h_in:
    vi, di = h_in.index("village"), h_in.index("district")
    ok_vill = sum(1 for ri, ro in zip(rows_in, rows_out) if ro[vi].strip().lower() == ri[di].strip().lower())
    print(f"  Village generalized to district: {ok_vill}/{len(rows_in)}")
if "pin" in h_in:
    pi = h_in.index("pin")
    ok_pin = sum(1 for ri, ro in zip(rows_in, rows_out) if ro[pi].endswith("***") and ro[pi][:3] == ri[pi][:3])
    print(f"  PIN generalized to 3-digit prefix: {ok_pin}/{len(rows_in)}")

# Check whether k-anonymity enforcement (widening/suppression) is invoked in cli.py
cli_txt = (ROOT / "rakshak/cli.py").read_text(encoding="utf-8")
print(f"  cli.py calls compute_k_anonymity_metrics: {'compute_k_anonymity_metrics' in cli_txt}")
print(f"  cli.py calls widen_age_band: {'widen_age_band' in cli_txt}")
print(f"  cli.py calls suppress_pin: {'suppress_pin' in cli_txt}")

print("\n=== F & G. SECURITY & OUTPUT CONTRACT ===")
rep = json.loads((ROOT / "output/report.json").read_text(encoding="utf-8"))
print("  report.json counts:", json.dumps(rep["counts"]))
print("  report.json privacy:", json.dumps(rep.get("privacy")))
print("  report.json timing:", json.dumps(rep["timing"]), "resources:", json.dumps(rep["resources"]))
secret_val = os.environ.get("RAKSHA_SECRET", "practice")
all_out_text = "\n".join(
    p.read_text(encoding="utf-8", errors="replace")
    for p in (ROOT / "output").rglob("*")
    if p.is_file()
)
print(f"  RAKSHA_SECRET ('{secret_val}') present in output/: {secret_val in all_out_text if len(secret_val) > 4 else 'checked'}")
quarantined = [e for e in rep["files"] if e.get("status") == "quarantined"]
print(f"  Quarantined files ({len(quarantined)}):", [e.get("reason") for e in quarantined])
