"""Reproducible Phase 2 Baseline & Post-Hardening Evaluator for A5, A6, A7 & Clinical Utility."""
import csv
import hashlib
import hmac
import json
import os
import re
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from rakshak.cli import run_pipeline
from rakshak.privacy.pseudonymize import generate_pseudonym
from rakshak.privacy.transforms import _parse_date, compute_date_shift
from artifacts.optimization.sim_attacker import extract_profile_evidence, load_known_facts, load_registry


def eval_a5(out_dir: Path):
    profiles = extract_profile_evidence(out_dir / "sanitized", out_dir / "records.jsonl")
    facts = load_known_facts()
    reg = {r["rid"]: r for r in load_registry()}

    # 1. Global shift recovery: compare dates of profiles matching exact rare condition or unique demo
    # For each known_fact with a visit_date, check offset against profile dates
    offset_votes = Counter()
    for fact in facts:
        person = reg.get(fact["rid"], {})
        p_dist = person.get("district", "").strip().lower()
        p_gen = person.get("gender", "").strip().upper()
        for fdate_s in fact.get("visit_dates", []):
            fd = _parse_date(fdate_s)
            if not fd:
                continue
            for psn, prof in profiles.items():
                if p_dist and prof["districts"] and p_dist not in prof["districts"]:
                    continue
                if p_gen and prof["genders"] and p_gen not in prof["genders"]:
                    continue
                for od_s in prof["dates"]:
                    od = _parse_date(od_s)
                    if od:
                        offset_votes[(od - fd).days] += 1

    top_offset, top_votes = offset_votes.most_common(1)[0] if offset_votes else (0, 0)
    total_facts_with_dates = sum(1 for f in facts if f.get("visit_dates"))

    # 2. Rare-condition + demographic profile uniqueness
    cond_counts = Counter()
    for prof in profiles.values():
        for c in prof["conditions"]:
            cond_counts[c] += 1
    rare_conds = {c for c, cnt in cond_counts.items() if cnt <= 2}

    rare_profiles = 0
    unique_rare_profiles = 0
    seen_rare_keys = Counter()
    for psn, prof in profiles.items():
        has_rare = bool(prof["conditions"] & rare_conds)
        if has_rare:
            rare_profiles += 1
            ab = prof["age_bands"][0] if prof["age_bands"] else (prof["ages"][0] if prof["ages"] else None)
            dist = tuple(sorted(prof["districts"]))
            gen = tuple(sorted(prof["genders"]))
            seen_rare_keys[(ab, dist, gen, tuple(sorted(prof["conditions"] & rare_conds)))] += 1
    unique_rare_profiles = sum(1 for v in seen_rare_keys.values() if v == 1)

    # 3. Admission/discharge chronology & LOS preservation in billing/arogya_claims.csv
    los_ok = los_total = 0
    for rel in ("billing/arogya_claims.csv", "billing/jeevanjyoti_claims.csv", "billing/sanjeevani_claims.csv"):
        p_in = ROOT / "dev/input" / rel
        p_out = out_dir / "sanitized" / rel
        if not (p_in.exists() and p_out.exists()):
            continue
        with open(p_in, encoding="utf-8-sig") as f1, open(p_out, encoding="utf-8-sig") as f2:
            r1 = list(csv.DictReader(f1))
            r2 = list(csv.DictReader(f2))
        for a, b in zip(r1, r2):
            d1_in, d2_in = _parse_date(a.get("admission_date", "")), _parse_date(a.get("discharge_date", ""))
            d1_out, d2_out = _parse_date(b.get("admission_date", "")), _parse_date(b.get("discharge_date", ""))
            if d1_in and d2_in and d1_out and d2_out:
                los_total += 1
                if (d2_out - d1_out).days == (d2_in - d1_in).days and d2_out >= d1_out:
                    los_ok += 1

    return {
        "global_shift_top_votes": top_votes,
        "total_facts": total_facts_with_dates,
        "rare_profiles": rare_profiles,
        "unique_rare_profiles": unique_rare_profiles,
        "los_preserved": f"{los_ok}/{los_total}",
    }


def eval_a6():
    # Dictionary attack over 240 registry entries without secret
    reg = load_registry()
    target_psn = generate_pseudonym("phone:" + reg[0]["phone"], b"practice") if reg[0]["phone"] else generate_pseudonym("name:test|", b"practice")
    inversions = 0
    for r in reg:
        for cand_key in (f"phone:{r['phone']}", f"name:{r['name'].lower()}|"):
            if generate_pseudonym(cand_key, b"attacker-guess") == target_psn:
                inversions += 1
            if generate_pseudonym(cand_key, b"") == target_psn:
                inversions += 1
    # Cross-domain check
    d_psn = hmac.new(b"practice", b"psn|phone:9876543210", hashlib.sha256).hexdigest()
    d_shift = hmac.new(b"practice", b"shift|phone:9876543210", hashlib.sha256).hexdigest()
    d_fname = hmac.new(b"practice", b"fname|phone:9876543210", hashlib.sha256).hexdigest()
    return {
        "dictionary_inversions": inversions,
        "domains_distinct": len({d_psn, d_shift, d_fname}) == 3,
    }


def eval_a7():
    with tempfile.TemporaryDirectory() as tmp:
        out_a = Path(tmp) / "rel_a"
        out_b = Path(tmp) / "rel_b"
        out_c = Path(tmp) / "rel_c"
        old = os.environ.get("RAKSHA_SECRET")
        try:
            os.environ["RAKSHA_SECRET"] = "secret-alpha-release"
            run_pipeline(ROOT / "dev/input", out_a)
            os.environ["RAKSHA_SECRET"] = "secret-beta-release"
            run_pipeline(ROOT / "dev/input", out_b)
            os.environ["RAKSHA_SECRET"] = "secret-alpha-release"
            run_pipeline(ROOT / "dev/input", out_c)
        finally:
            if old is None:
                os.environ.pop("RAKSHA_SECRET", None)
            else:
                os.environ["RAKSHA_SECRET"] = old

        def _psn_set(d: Path):
            return {
                json.loads(l)["patient"]
                for l in (d / "records.jsonl").read_text(encoding="utf-8").splitlines()
                if l.strip() and json.loads(l).get("patient")
            }

        psn_a, psn_b, psn_c = _psn_set(out_a), _psn_set(out_b), _psn_set(out_c)
        ab_exact_overlap = len(psn_a & psn_b)
        ac_exact_overlap = len(psn_a & psn_c)

        # Filename overlap for renamed doc_* files
        f_a = {p.name for p in (out_a / "sanitized").rglob("doc_*") if p.is_file()}
        f_b = {p.name for p in (out_b / "sanitized").rglob("doc_*") if p.is_file()}
        fname_overlap = len(f_a & f_b)

        # Statistical profile correlation across A vs B using (age_band, gender, district, conditions)
        prof_a = extract_profile_evidence(out_a / "sanitized", out_a / "records.jsonl")
        prof_b = extract_profile_evidence(out_b / "sanitized", out_b / "records.jsonl")

        def _sig(prof):
            return (
                tuple(sorted(prof["age_bands"])),
                tuple(sorted(prof["genders"])),
                tuple(sorted(prof["districts"])),
                tuple(sorted(prof["conditions"])),
            )

        sigs_a = Counter(_sig(v) for v in prof_a.values())
        sigs_b = Counter(_sig(v) for v in prof_b.values())
        unique_stat_linkable = sum(1 for sig, cnt in sigs_a.items() if cnt == 1 and sigs_b.get(sig, 0) == 1)

        return {
            "psn_a": len(psn_a),
            "psn_b": len(psn_b),
            "ab_exact_psn_overlap": ab_exact_overlap,
            "ac_same_key_overlap": f"{ac_exact_overlap}/{len(psn_a)}",
            "ab_renamed_filename_overlap": fname_overlap,
            "ab_stat_unique_profile_matches": f"{unique_stat_linkable}/{len(prof_a)}",
        }


def eval_utility(out_dir: Path):
    # Age generalization score distribution per docs/SCORING.md
    profiles = extract_profile_evidence(out_dir / "sanitized", out_dir / "records.jsonl")
    scores = []
    widths = Counter()
    for prof in profiles.values():
        for lo, hi in prof["age_bands"]:
            w = hi - lo + 1
            widths[w] += 1
            if w <= 5:
                scores.append(0.9)
            elif w <= 10:
                scores.append(0.8)
            elif w <= 20:
                scores.append(0.6)
            else:
                scores.append(0.3)
    mean_age_score = sum(scores) / len(scores) if scores else 0.0
    return {
        "age_band_widths": dict(widths),
        "mean_age_generalization_score": round(mean_age_score, 4),
    }


if __name__ == "__main__":
    out = ROOT / "output"
    print("A5:", json.dumps(eval_a5(out)))
    print("A6:", json.dumps(eval_a6()))
    print("A7:", json.dumps(eval_a7()))
    print("UTILITY:", json.dumps(eval_utility(out)))
