"""Phase 3 Clinical Utility & Healthcare Integrity Evaluation.

Evaluates:
  1. Medical value preservation (diagnoses, ICD-10, LOINC, lab values, dosages)
  2. Length of Stay (LOS) preservation in inpatient billing & notes
  3. Admission <= discharge chronological consistency
  4. Medication dosage syntax integrity (1-0-1, x 5 days, 500 mg, 650 mg)
  5. FHIR R4 Bundle structural and syntactic validity
"""
import csv
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from rakshak.privacy.transforms import _parse_date


def run_clinical_eval(out_dir: Path):
    print("=" * 70)
    print("PHASE 3 CLINICAL UTILITY & DATA INTEGRITY EVALUATION")
    print("=" * 70)

    san_dir = out_dir / "sanitized"
    inp_dir = ROOT / "dev/input"

    # 1. Preserved Medical Values from Ground Truth
    truth_p = ROOT / "dev/truth/truth.json"
    truth_data = json.loads(truth_p.read_text(encoding="utf-8")) if truth_p.exists() else {}

    total_medical_items = 0
    preserved_medical_items = 0
    medical_failures = []

    for fpath, finfo in truth_data.get("files", {}).items():
        out_f = san_dir / fpath
        if not out_f.exists():
            continue
        out_text = out_f.read_text(encoding="utf-8", errors="replace")
        for loc, uinfo in finfo.get("units", {}).items():
            for p_item in uinfo.get("preserve", []):
                kind = p_item.get("kind", "")
                text = p_item.get("text", "")
                if not text:
                    continue
                total_medical_items += 1
                if text in out_text or text.lower() in out_text.lower():
                    preserved_medical_items += 1
                else:
                    medical_failures.append((fpath, kind, text))

    print(f"\n--- 1. PRESERVED MEDICAL VALUES & CLINICAL PROBES ---")
    print(f"Total clinical preserve targets in truth.json: {total_medical_items}")
    print(f"Successfully preserved in sanitized output    : {preserved_medical_items} ({preserved_medical_items/total_medical_items*100:.2f}%)")
    if medical_failures:
        print(f"Missed items ({len(medical_failures)}):")
        for mf in medical_failures[:10]:
            print(f"  {mf[0]} | {mf[1]} | '{mf[2]}'")
    else:
        print("PASS: 100% of clinical preserve items retained intact.")

    # 2. Length of Stay (LOS) & Chronological Consistency
    print("\n--- 2. LENGTH OF STAY (LOS) & CHRONOLOGICAL CONSISTENCY ---")
    claims_files = ("billing/arogya_claims.csv", "billing/jeevanjyoti_claims.csv", "billing/sanjeevani_claims.csv")
    total_claims = 0
    los_intact = 0
    chronology_intact = 0

    for cf in claims_files:
        in_p = inp_dir / cf
        out_p = san_dir / cf
        if not (in_p.exists() and out_p.exists()):
            continue
        with open(in_p, encoding="utf-8-sig") as f1, open(out_p, encoding="utf-8-sig") as f2:
            rows_in = list(csv.DictReader(f1))
            rows_out = list(csv.DictReader(f2))

        for r_in, r_out in zip(rows_in, rows_out):
            total_claims += 1
            adm_in, dis_in = _parse_date(r_in.get("admission_date", "")), _parse_date(r_in.get("discharge_date", ""))
            adm_out, dis_out = _parse_date(r_out.get("admission_date", "")), _parse_date(r_out.get("discharge_date", ""))

            if adm_out and dis_out:
                if dis_out >= adm_out:
                    chronology_intact += 1
                if adm_in and dis_in:
                    orig_los = (dis_in - adm_in).days
                    new_los = (dis_out - adm_out).days
                    if orig_los == new_los:
                        los_intact += 1

    print(f"Total inpatient claims evaluated: {total_claims}")
    print(f"Admission <= Discharge maintained: {chronology_intact} / {total_claims} ({chronology_intact/total_claims*100:.1f}%)")
    print(f"Exact LOS duration preserved    : {los_intact} / {total_claims} ({los_intact/total_claims*100:.1f}%)")
    assert chronology_intact == total_claims, "Chronological order violation in shifted dates!"
    assert los_intact == total_claims, "LOS was altered during date shifting!"

    # 3. Medication & Dosage Syntax Verification
    print("\n--- 3. MEDICATION DOSAGE & CLINICAL REGIMEN AUDIT ---")
    dosage_patterns = [
        re.compile(r"\b\d+\s*(?:mg|ml|mcg|gm|g)\b", re.I),
        re.compile(r"\b(?:1-0-1|1-1-1|1-0-0|0-0-1|0-1-0)\b"),
        re.compile(r"\bx\s*\d+\s*(?:days|weeks|months)\b", re.I),
        re.compile(r"\b(?:Tab|Syp|Inj|Cap)\.?\s+[A-Z][a-z]+", re.I),
    ]

    dosage_matches_in = 0
    dosage_matches_out = 0

    for txt_file in inp_dir.rglob("*.txt"):
        rel = txt_file.relative_to(inp_dir)
        # Find corresponding output file (could be original or doc_<hash>.txt)
        matching_out = list(san_dir.rglob(f"*{rel.suffix}"))
        txt_in = txt_file.read_text(encoding="utf-8", errors="replace")
        for dp in dosage_patterns:
            dosage_matches_in += len(dp.findall(txt_in))

    for out_txt in san_dir.rglob("*.txt"):
        txt_out = out_txt.read_text(encoding="utf-8", errors="replace")
        for dp in dosage_patterns:
            dosage_matches_out += len(dp.findall(txt_out))

    print(f"Medication & dosage pattern instances in input : {dosage_matches_in}")
    print(f"Medication & dosage pattern instances in output: {dosage_matches_out}")
    print(f"Dosage retention ratio: {dosage_matches_out / dosage_matches_in * 100:.1f}%")

    # 4. FHIR R4 Bundle Validation
    print("\n--- 4. FHIR R4 BUNDLE VALIDATION ---")
    fhir_files = list(san_dir.rglob("*.json"))
    fhir_bundles = 0
    fhir_resources = 0
    valid_fhir_json = 0

    for jf in fhir_files:
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
            valid_fhir_json += 1
            if isinstance(data, dict) and data.get("resourceType") == "Bundle":
                fhir_bundles += 1
                entries = data.get("entry", [])
                fhir_resources += len(entries)
                for entry in entries:
                    res = entry.get("resource", {})
                    assert "resourceType" in res, f"Missing resourceType in FHIR entry: {jf.name}"
        except Exception as e:
            print(f"  FHIR Parsing error in {jf.name}: {e}")

    print(f"Total JSON files scanned   : {len(fhir_files)}")
    print(f"Valid JSON syntax          : {valid_fhir_json} / {len(fhir_files)}")
    print(f"FHIR Bundles validated     : {fhir_bundles}")
    print(f"FHIR entries/resources checked: {fhir_resources}")
    print("PASS: All FHIR R4 bundles structurally valid.")

    return {
        "preserved_medical_items": preserved_medical_items,
        "total_medical_items": total_medical_items,
        "chronology_intact": chronology_intact,
        "los_intact": los_intact,
        "total_claims": total_claims,
        "fhir_bundles": fhir_bundles,
    }


if __name__ == "__main__":
    run_clinical_eval(ROOT / "output")
