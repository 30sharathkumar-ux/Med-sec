"""Deep linkage gap analysis: find exactly which patients we fail to link."""
import json, itertools, re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
truth = json.load(open(ROOT / "dev" / "truth" / "truth.json"))
report = json.load(open(ROOT / "output" / "report.json"))
renamed = {e.get("input_sha256"): e.get("output") for e in report.get("files", [])}

# Load records.jsonl
recs = defaultdict(dict)
for line in (ROOT / "output" / "records.jsonl").read_text(encoding="utf-8").splitlines():
    if line.strip():
        r = json.loads(line)
        f = str(r["file"]).replace("sanitized/", "", 1)
        recs[f][r["loc"]] = r.get("patient")

def record_for(loc, file_recs):
    if loc in file_recs:
        return file_recs[loc]
    if loc.startswith("/"):
        parts = loc.split("/")
        for i in range(len(parts)-1, 1, -1):
            anc = "/".join(parts[:i])
            if anc in file_recs:
                return file_recs[anc]
    return file_recs.get("doc")

# Build unit_patient mapping
unit_patient = {}
for rel, f in truth["files"].items():
    out_rel = rel
    declared = renamed.get(f["sha256"])
    if declared:
        out_rel = str(declared).replace("sanitized/", "", 1)
    for loc, u in f["units"].items():
        if u.get("link") == "required" and u.get("patient"):
            our_psn = record_for(loc, recs.get(out_rel, {}))
            unit_patient[(rel, loc)] = (u["patient"], our_psn)

# Group by true patient
by_true = defaultdict(list)
for key, (true_pt, our_psn) in unit_patient.items():
    by_true[true_pt].append((key, our_psn))

# Find patients where we used multiple pseudonyms (= fragmented linking)
fragmented = {}
for true_pt, entries in by_true.items():
    psns = set()
    for _, psn in entries:
        if psn:
            psns.add(psn)
    if len(psns) > 1:
        fragmented[true_pt] = entries

# Find patients with no pseudonym
unlinked = {}
for true_pt, entries in by_true.items():
    missing = [(k, p) for k, p in entries if not p]
    if missing:
        unlinked[true_pt] = missing

print(f"Total true patients with required links: {len(by_true)}")
print(f"Patients with fragmented pseudonyms: {len(fragmented)}")
print(f"Patients with unlinked records: {len(unlinked)}")

# Calculate pair-level impact
total_true_pairs = sum(len(v) * (len(v)-1) // 2 for v in by_true.values())
tp = fn = 0
yours = defaultdict(list)
for i, ((rel, loc), (true_pt, our_psn)) in enumerate(unit_patient.items()):
    if our_psn:
        yours[our_psn].append(i)
units = list(unit_patient.values())
for members in yours.values():
    for i, j in itertools.combinations(members, 2):
        if units[i][0] == units[j][0]:
            tp += 1
fn = total_true_pairs - tp
print(f"\nTrue pairs: {total_true_pairs}, TP: {tp}, FN: {fn}")
print(f"Recall: {tp / (tp + fn):.4f}")

# Show details of fragmented patients
print("\n--- FRAGMENTED PATIENTS (biggest recall loss) ---")
for true_pt, entries in sorted(fragmented.items(), key=lambda x: -len(x[1])):
    psn_groups = defaultdict(list)
    for (rel, loc), psn in entries:
        psn_groups[psn or "NONE"].append(f"{rel}::{loc}")
    pair_loss = 0
    group_sizes = [len(v) for v in psn_groups.values()]
    max_possible = len(entries) * (len(entries) - 1) // 2
    actual = sum(s * (s - 1) // 2 for s in group_sizes)
    pair_loss = max_possible - actual
    print(f"\n  {true_pt}: {len(entries)} records, {len(psn_groups)} fragments, {pair_loss} lost pairs")
    for psn, locs in psn_groups.items():
        print(f"    {psn}: {len(locs)} records")
        for l in locs[:3]:
            print(f"      {l}")
