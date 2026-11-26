"""Trace why specific records don't merge in the actual pipeline."""
import csv, json, os, sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
os.environ["RAKSHA_SECRET"] = "practice"

from rakshak.linkage.resolver import (
    IdentityResolver, extract_evidence_csv, extract_evidence_json,
    _effective_hospital, _infer_hospital_from_mrn
)
from rakshak.linkage.normalize import normalize_mrn

ROOT = Path(__file__).resolve().parent.parent.parent

# Load all lab records for UHID JJH-0076928
target_mrn = normalize_mrn("JJH-0076928")
print(f"Target MRN (normalized): '{target_mrn}'")

evidence_records = []

# Registration: jeevanjyoti_patients.tsv
with open(ROOT / "dev/input/registration/jeevanjyoti_patients.tsv", encoding="utf-16") as f:
    reader = csv.reader(f, delimiter="\t")
    header = next(reader)
    for idx, row in enumerate(reader):
        ev = extract_evidence_csv(header, row, f"sanitized/registration/jeevanjyoti_patients.tsv", idx, "jeevanjyoti")
        if target_mrn in ev.mrns:
            print(f"\nREG row:{idx}: name='{ev.patient_name}' norm='{ev.patient_name_normalized}' mrns={ev.mrns}")
            print(f"  hospital='{ev.hospital}' effective='{_effective_hospital(ev)}'")
            evidence_records.append(("reg", ev))

# City results
with open(ROOT / "dev/input/lab/city_results.csv", encoding="utf-8") as f:
    reader = csv.reader(f)
    header = next(reader)
    for idx, row in enumerate(reader):
        ev = extract_evidence_csv(header, row, f"sanitized/lab/city_results.csv", idx, "")
        if target_mrn in ev.mrns:
            print(f"\nCITY row:{idx}: name='{ev.patient_name}' norm='{ev.patient_name_normalized}' mrns={ev.mrns}")
            print(f"  hospital='{ev.hospital}' effective='{_effective_hospital(ev)}'")
            evidence_records.append(("city", ev))

# Sanjeevani results
with open(ROOT / "dev/input/lab/sanjeevani_results.csv", encoding="utf-8") as f:
    reader = csv.reader(f)
    header = next(reader)
    for idx, row in enumerate(reader):
        ev = extract_evidence_csv(header, row, f"sanitized/lab/sanjeevani_results.csv", idx, "")
        if target_mrn in ev.mrns:
            print(f"\nSNJ row:{idx}: name='{ev.patient_name}' norm='{ev.patient_name_normalized}' mrns={ev.mrns}")
            print(f"  hospital='{ev.hospital}' effective='{_effective_hospital(ev)}'")
            evidence_records.append(("snj", ev))

# Bulk lab export
data = json.load(open(ROOT / "dev/input/lab/bulk_lab_export.json"))
for idx, item in enumerate(data.get("results", [])):
    ev = extract_evidence_json(item, "sanitized/lab/bulk_lab_export.json", f"/results/{idx}", "")
    if target_mrn in ev.mrns:
        print(f"\nBULK /results/{idx}: name='{ev.patient_name}' norm='{ev.patient_name_normalized}' mrns={ev.mrns}")
        print(f"  hospital='{ev.hospital}' effective='{_effective_hospital(ev)}'")
        evidence_records.append(("bulk", ev))

# Now test actual resolve
resolver = IdentityResolver()
for _, ev in evidence_records:
    resolver.add_record(ev)
clusters = resolver.resolve()
print(f"\n--- Resolve with {len(evidence_records)} records ---")
cluster_groups = defaultdict(list)
for src, ev in evidence_records:
    cid = clusters[ev.record_id]
    cluster_groups[cid].append((src, ev.record_id, ev.patient_name))
for cid, members in cluster_groups.items():
    print(f"Cluster {cid}: {len(members)} records")
    for src, rid, name in members:
        print(f"  [{src}] {rid} = {name}")
