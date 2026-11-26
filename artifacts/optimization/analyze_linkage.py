"""Analyze linkage gaps between RAKSHA output and truth.json."""
import json
import os
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TRUTH = ROOT / "dev" / "truth" / "truth.json"
OUTPUT = ROOT / "output"
RECORDS = OUTPUT / "records.jsonl"

truth = json.load(open(TRUTH))
patients = truth["patients"]

# Build truth mapping: file::loc -> patient_id
truth_map = {}  # (file, loc) -> patient_key (e.g. PT00001)
for pt_key, pt in patients.items():
    for hosp, file_locs in pt.get("record_locs", pt.get("locs", {})).items():
        for fl in file_locs:
            if isinstance(fl, str):
                truth_map[fl] = pt_key
            elif isinstance(fl, dict):
                f = fl.get("file", "")
                l = fl.get("loc", "")
                truth_map[f"{f}::{l}"] = pt_key

print(f"Truth: {len(truth_map)} record locations across {len(patients)} patients")

# If truth_map is empty, the structure is different. Let's inspect further.
if not truth_map:
    # Try alternative structures
    for pt_key, pt in list(patients.items())[:3]:
        print(f"\n{pt_key} keys: {list(pt.keys())}")
        for k, v in pt.items():
            if isinstance(v, (dict, list)):
                print(f"  {k}: {type(v).__name__} len={len(v)}")
                if isinstance(v, dict):
                    for kk in list(v.keys())[:3]:
                        print(f"    {kk}: {v[kk]}")
                elif isinstance(v, list) and v:
                    print(f"    [0]: {v[0]}")
            else:
                print(f"  {k}: {v}")

# Load our output records.jsonl
our_records = []
if RECORDS.exists():
    with open(RECORDS) as f:
        for line in f:
            line = line.strip()
            if line:
                our_records.append(json.loads(line))

print(f"\nOur output: {len(our_records)} records")

# Count clusters
clusters = defaultdict(list)
for rec in our_records:
    psn = rec.get("patient")
    if psn:
        clusters[psn].append(rec)

print(f"Our clusters: {len(clusters)}")
multi_rec = {k: v for k, v in clusters.items() if len(v) >= 2}
print(f"Clusters with 2+ records: {len(multi_rec)}")
for k, v in list(multi_rec.items())[:5]:
    files = [r.get("file", "") for r in v]
    print(f"  {k}: {len(v)} records in {files[:3]}")

# Show distribution of cluster sizes
from collections import Counter
size_dist = Counter(len(v) for v in clusters.values())
print(f"\nCluster size distribution:")
for s in sorted(size_dist.keys()):
    print(f"  size {s}: {size_dist[s]} clusters")
