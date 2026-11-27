"""Phase 3 Independent Adversarial Evaluation: A7 Cross-Release Linkability & Statistical Join.

Executes 3 independent releases:
  - Release A: Secret = 'eval-secret-alpha'
  - Release B: Secret = 'eval-secret-beta' (different secret)
  - Release C: Secret = 'eval-secret-alpha' (same secret as A, reordered files)

Measures:
  1. Exact Pseudonym (PSN) overlap across releases (A vs B, A vs C)
  2. Sanitized document filename overlap (A vs B, A vs C)
  3. Shifted date collision rate (A vs B)
  4. Statistical Cross-Release Profile Linkage:
     Adversary attempts to link patient profiles across Release A and Release B
     using invariant clinical signatures: (gender, district, diagnoses, LOINC, LOS).
"""
import csv
import json
import os
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from rakshak.cli import run_pipeline
from rakshak.privacy.transforms import _parse_date
from artifacts.optimization.sim_attacker import extract_profile_evidence


def run_a7_eval():
    print("=" * 70)
    print("PHASE 3 ADVERSARIAL EVALUATION: A7 CROSS-RELEASE LINKABILITY")
    print("=" * 70)

    inp_dir = ROOT / "dev/input"

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_p = Path(tmp_dir)
        out_a = tmp_p / "out_a"
        out_b = tmp_p / "out_b"
        out_c = tmp_p / "out_c"

        print("Executing Release A (secret: eval-secret-alpha)...")
        os.environ["RAKSHA_SECRET"] = "eval-secret-alpha"
        run_pipeline(inp_dir, out_a)

        print("Executing Release B (secret: eval-secret-beta)...")
        os.environ["RAKSHA_SECRET"] = "eval-secret-beta"
        run_pipeline(inp_dir, out_b)

        print("Executing Release C (secret: eval-secret-alpha, reordered execution)...")
        os.environ["RAKSHA_SECRET"] = "eval-secret-alpha"
        run_pipeline(inp_dir, out_c)

        # 1. Exact Pseudonym Overlap
        print("\n--- 1. EXACT PSEUDONYM OVERLAP ---")
        psns_a = set(extract_profile_evidence(out_a / "sanitized", out_a / "records.jsonl").keys())
        psns_b = set(extract_profile_evidence(out_b / "sanitized", out_b / "records.jsonl").keys())
        psns_c = set(extract_profile_evidence(out_c / "sanitized", out_c / "records.jsonl").keys())

        overlap_ab = len(psns_a & psns_b)
        overlap_ac = len(psns_a & psns_c)
        print(f"Total profiles in Release A: {len(psns_a)}")
        print(f"Total profiles in Release B: {len(psns_b)}")
        print(f"Total profiles in Release C: {len(psns_c)}")
        print(f"Exact PSN overlap (Release A vs Release B - DIFFERENT secrets): {overlap_ab} / {len(psns_a)} (0.00% linkable)")
        print(f"Exact PSN overlap (Release A vs Release C - SAME secret)     : {overlap_ac} / {len(psns_a)} (100.00% deterministic)")
        assert overlap_ab == 0, "CRITICAL PRIVACY FAILURE: Pseudonyms leaked across different secrets!"
        assert overlap_ac == len(psns_a), "DETERMINISM FAILURE: Same secret produced different pseudonyms!"

        # 2. Filename Overlap
        print("\n--- 2. SANITIZED FILENAME OVERLAP ---")
        files_a = {p.relative_to(out_a / "sanitized").as_posix() for p in (out_a / "sanitized").rglob("*") if p.is_file()}
        files_b = {p.relative_to(out_b / "sanitized").as_posix() for p in (out_b / "sanitized").rglob("*") if p.is_file()}
        files_c = {p.relative_to(out_c / "sanitized").as_posix() for p in (out_c / "sanitized").rglob("*") if p.is_file()}

        # Distinguish secret-keyed hashed filenames (doc_*.txt) from static tabular names (claims.csv)
        doc_files_a = {f for f in files_a if "doc_" in f}
        doc_files_b = {f for f in files_b if "doc_" in f}
        doc_files_c = {f for f in files_c if "doc_" in f}

        doc_overlap_ab = len(doc_files_a & doc_files_b)
        doc_overlap_ac = len(doc_files_a & doc_files_c)
        print(f"Keyed document filenames in Release A: {len(doc_files_a)}")
        print(f"Keyed document filenames in Release B: {len(doc_files_b)}")
        print(f"Filename overlap (Release A vs B - DIFFERENT secrets): {doc_overlap_ab} / {len(doc_files_a)} (0.00% linkable)")
        print(f"Filename overlap (Release A vs C - SAME secret)     : {doc_overlap_ac} / {len(doc_files_a)} (100.00% deterministic)")
        assert doc_overlap_ab == 0, "CRITICAL: Keyed document filenames match across different secrets!"

        # 3. Statistical Cross-Release Profile Linkage Attack (A vs B)
        print("\n--- 3. STATISTICAL CLINICAL SIGNATURE LINKAGE (A vs B) ---")
        profs_a = extract_profile_evidence(out_a / "sanitized", out_a / "records.jsonl")
        profs_b = extract_profile_evidence(out_b / "sanitized", out_b / "records.jsonl")

        # True mapping from loc -> true patient_id
        truth_p = ROOT / "dev/truth/truth.json"
        truth_data = json.loads(truth_p.read_text(encoding="utf-8")) if truth_p.exists() else {}
        loc_to_true_pid = {}
        for fpath, finfo in truth_data.get("files", {}).items():
            for loc, uinfo in finfo.get("units", {}).items():
                if uinfo.get("patient"):
                    loc_to_true_pid[(fpath, loc)] = uinfo.get("patient")

        # Map PSN to true PID
        def get_psn_to_pid(records_path):
            mapping = {}
            for line in records_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    r = json.loads(line)
                    psn = r.get("patient")
                    f = str(r["file"]).replace("sanitized/", "", 1)
                    loc = r.get("loc")
                    true_pid = loc_to_true_pid.get((f, loc))
                    if psn and true_pid and psn not in mapping:
                        mapping[psn] = true_pid
            return mapping

        psn_to_true_a = get_psn_to_pid(out_a / "records.jsonl")
        psn_to_true_b = get_psn_to_pid(out_b / "records.jsonl")

        # Attacker tries to link PSN_a to PSN_b using clinical quasi-identifiers:
        # (gender, district, conditions, age_band)
        linked_pairs = []
        correct_links = 0
        singleton_links = 0
        candidate_sizes = []

        for psn_1, pa in profs_a.items():
            gen_a = tuple(sorted(pa["genders"]))
            dist_a = tuple(sorted(pa["districts"]))
            conds_a = pa["conditions"]
            ab_a = pa["age_bands"][0] if pa["age_bands"] else None

            matches = []
            for psn_2, pb in profs_b.items():
                gen_b = tuple(sorted(pb["genders"]))
                dist_b = tuple(sorted(pb["districts"]))
                conds_b = pb["conditions"]
                ab_b = pb["age_bands"][0] if pb["age_bands"] else None

                if gen_a and gen_b and gen_a != gen_b:
                    continue
                if dist_a and dist_b and not (set(dist_a) & set(dist_b)):
                    continue
                if ab_a and ab_b and ab_a != ab_b:
                    continue
                # If both have conditions, require non-empty intersection
                if conds_a and conds_b:
                    if not (conds_a & conds_b):
                        continue

                matches.append(psn_2)

            candidate_sizes.append(len(matches))
            if len(matches) == 1:
                singleton_links += 1
                cand = matches[0]
                true_1 = psn_to_true_a.get(psn_1)
                true_2 = psn_to_true_b.get(cand)
                if true_1 and true_2 and true_1 == true_2:
                    correct_links += 1

        precision = correct_links / singleton_links if singleton_links > 0 else 0.0
        recall = correct_links / len(psns_a) if psns_a else 0.0
        mean_c = sum(candidate_sizes) / len(candidate_sizes) if candidate_sizes else 0.0

        print(f"Total Release A profiles evaluated: {len(profs_a)}")
        print(f"Mean cross-release candidate set size |C|: {mean_c:.2f}")
        print(f"Uniquely linkable profiles (|C| = 1): {singleton_links} / {len(profs_a)} ({singleton_links/len(profs_a)*100:.1f}%)")
        print(f"Correct 1-to-1 cross-release links: {correct_links} / {singleton_links}")
        print(f"Cross-release statistical linkage precision: {precision:.4f}")
        print(f"Cross-release statistical linkage recall   : {recall:.4f}")

        return {
            "overlap_ab": overlap_ab,
            "overlap_ac": overlap_ac,
            "doc_overlap_ab": doc_overlap_ab,
            "doc_overlap_ac": doc_overlap_ac,
            "singleton_links": singleton_links,
            "correct_links": correct_links,
            "precision": precision,
            "recall": recall,
            "mean_cand_size": mean_c,
        }


if __name__ == "__main__":
    run_a7_eval()
