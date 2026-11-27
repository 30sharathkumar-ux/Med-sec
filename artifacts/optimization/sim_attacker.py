"""Local A1-A7 Adversarial Attack Simulation (per docs/ATTACKS.md).

NOTE: This is a local simulation using dev/attacker/registry.csv and
dev/attacker/known_facts.jsonl, NOT the official raksha_eval package.
"""
import csv
import hashlib
import hmac
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from rakshak.privacy.transforms import _parse_date
from rakshak.privacy.pseudonymize import generate_pseudonym


def load_registry():
    with open(ROOT / "dev/attacker/registry.csv", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_known_facts():
    return [
        json.loads(l)
        for l in (ROOT / "dev/attacker/known_facts.jsonl").read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]


def extract_profile_evidence(san_dir: Path, records_jsonl: Path):
    """Aggregate quasi-identifiers, dates, and rare conditions per pseudonymized profile."""
    # Map file::loc -> patient_psn from records.jsonl
    loc_to_psn = defaultdict(dict)
    for line in records_jsonl.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            f = str(r["file"]).replace("sanitized/", "", 1)
            loc_to_psn[f][r["loc"]] = r.get("patient")

    profiles = defaultdict(lambda: {
        "ages": [], "age_bands": [], "genders": set(), "districts": set(),
        "villages": set(), "pins": set(), "dates": [], "conditions": set(),
        "hospitals": set(), "records": 0, "files": set(),
    })

    for p in sorted(san_dir.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(san_dir).as_posix()
        file_recs = loc_to_psn.get(rel, {})
        default_psn = file_recs.get("doc")
        txt = p.read_text(encoding="utf-8", errors="replace")

        if p.suffix in (".csv", ".tsv"):
            delim = "\t" if p.suffix == ".tsv" else ","
            try:
                rows = list(csv.reader(txt.splitlines(), delimiter=delim))
            except Exception:
                continue
            if not rows:
                continue
            hdr = [h.lower().strip() for h in rows[0]]
            for ridx, row in enumerate(rows[1:]):
                psn = file_recs.get(f"row:{ridx}") or default_psn
                if not psn:
                    continue
                prof = profiles[psn]
                prof["records"] += 1
                prof["files"].add(rel)
                for col, val in zip(hdr, row):
                    val = val.strip()
                    if not val or val.startswith("["):
                        continue
                    if col in ("age", "umar", "age_sex"):
                        m = re.match(r"^(\d+)-(\d+)", val)
                        if m:
                            prof["age_bands"].append((int(m.group(1)), int(m.group(2))))
                        elif re.match(r"^(\d+)(?:/[MF])?$", val):
                            a = int(re.match(r"^(\d+)", val).group(1))
                            prof["ages"].append(a)
                    elif col in ("gender", "sex", "ling"):
                        if val[:1].upper() in ("M", "F"):
                            prof["genders"].add(val[:1].upper())
                    elif col in ("district", "jila", "zila"):
                        prof["districts"].add(val.lower())
                    elif col in ("pin", "pin code"):
                        prof["pins"].add(val)
                    elif any(k in col for k in ("date", "admission", "discharge")):
                        d = _parse_date(val)
                        if d:
                            prof["dates"].append(d.isoformat())
        elif p.suffix == ".txt":
            psn = default_psn
            if not psn:
                continue
            prof = profiles[psn]
            prof["records"] += 1
            prof["files"].add(rel)
            # Extract Age/Sex in free text (e.g. "Age/Sex: 39 Yrs/M" or "45-49 Yrs/M" or "80+ Yrs/M")
            for m in re.finditer(r"Age(?:/Sex)?\s*[:\-]\s*(\d+)(?:-(\d+)|(\+))?\s*(?:Yrs?)?(?:/([MF]))?", txt, re.I):
                if m.group(2):
                    prof["age_bands"].append((int(m.group(1)), int(m.group(2))))
                elif m.group(3):
                    prof["age_bands"].append((int(m.group(1)), 120))
                else:
                    prof["ages"].append(int(m.group(1)))
                if m.group(4):
                    prof["genders"].add(m.group(4).upper())
            # Diagnosis
            for m in re.finditer(r"Diagnosis\s*[:\-]\s*([^\n]+)", txt, re.I):
                prof["conditions"].add(m.group(1).strip().lower())
    return profiles


def run_simulation(out_dir: Path):
    reg = load_registry()
    facts = load_known_facts()
    san_dir = out_dir / "sanitized"
    records_jsonl = out_dir / "records.jsonl"
    profiles = extract_profile_evidence(san_dir, records_jsonl)

    # A1: Direct exposure in sanitized/
    all_san = "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in san_dir.rglob("*") if p.is_file()
    ).lower()
    a1_hits = sum(
        1 for r in reg
        if (r["name"].strip() and len(r["name"].strip()) > 5 and r["name"].strip().lower() in all_san)
        or (r["phone"].strip() and r["phone"].strip() in all_san)
    )

    # A2/A3/A4: Sweeney-style registry candidate filtering per profile
    linkage_probs = []
    confident_reid = 0
    for psn, prof in profiles.items():
        cands = reg
        # Filter by district
        if prof["districts"]:
            sub = [r for r in cands if r["district"].strip().lower() in prof["districts"]]
            if sub:
                cands = sub
        # Filter by gender
        if len(prof["genders"]) == 1:
            g = next(iter(prof["genders"]))
            sub = [r for r in cands if r["gender"].strip().upper() == g]
            if sub:
                cands = sub
        # Filter by exact age or age_band
        if prof["ages"]:
            a = prof["ages"][0]
            sub = [r for r in cands if r["age"].isdigit() and abs(int(r["age"]) - a) <= 2]
            if sub:
                cands = sub
        elif prof["age_bands"]:
            lo, hi = prof["age_bands"][0]
            sub = [r for r in cands if r["age"].isdigit() and (lo - 1) <= int(r["age"]) <= (hi + 1)]
            if sub:
                cands = sub
        # Filter by PIN prefix
        if prof["pins"]:
            prefixes = {pv[:3] for pv in prof["pins"] if len(pv) >= 3 and pv[:3].isdigit()}
            if prefixes:
                sub = [r for r in cands if r["pin"].strip()[:3] in prefixes]
                if sub:
                    cands = sub

        prob = 1.0 / len(cands) if cands else 0.0
        linkage_probs.append(prob)
        if prob >= 0.5:
            confident_reid += 1

    mean_prob = sum(linkage_probs) / len(linkage_probs) if linkage_probs else 0.0
    reid_share = confident_reid / len(profiles) if profiles else 0.0

    # A5: Known-date exact match check across profiles
    all_dates = {d for prof in profiles.values() for d in prof["dates"]}
    exact_date_hits = sum(
        1 for f in facts for d in f.get("visit_dates", []) if d in all_dates
    )

    # Exact-age leaks in free text
    exact_text_ages = sum(len(prof["ages"]) for prof in profiles.values())

    # A6/A7: Pseudonym domain separation & cross-release
    p1 = generate_pseudonym("phone:9876543210", b"practice")
    p2 = generate_pseudonym("phone:9876543210", b"other-secret")

    print(f"Profiles analyzed: {len(profiles)}")
    print(f"A1 direct hits (registry names/phones): {a1_hits}/{len(reg)}")
    print(f"A2/A3 mean candidate-set 1/|C| risk: {mean_prob:.4f}")
    print(f"A4 confident profile re-id (>=0.5): {confident_reid}/{len(profiles)} ({reid_share:.4f})")
    print(f"A5 exact unshifted visit-date hits: {exact_date_hits}")
    print(f"Exact unbanded ages in output: {exact_text_ages}")
    print(f"A6/A7 cross-secret unlinkable: {p1 != p2}")


if __name__ == "__main__":
    run_simulation(ROOT / "output")
