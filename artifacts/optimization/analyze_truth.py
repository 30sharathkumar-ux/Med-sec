import json
truth = json.load(open('dev/truth/truth.json'))
patients = truth['patients']
link = truth['linkability']
print(f"Patients: {len(patients)}")
print(f"Required units: {link['required_units']}")
print(f"Ambiguous units: {link['ambiguous_units']}")
print(f"Components: {link['components']}")

multi_hosp = {k:v for k,v in patients.items() if len(v.get('hospitals',[])) > 1}
print(f"Multi-hospital patients: {len(multi_hosp)}")
for k,v in list(multi_hosp.items())[:5]:
    hosps = v["hospitals"]
    traps = v.get("traps", [])
    print(f"  {k}: hospitals={hosps}, traps={traps}")

trapped = {k:v for k,v in patients.items() if v.get('traps')}
print(f"Patients with traps: {len(trapped)}")
for k,v in list(trapped.items())[:10]:
    traps = v["traps"]
    hosps = v["hospitals"]
    print(f"  {k}: traps={traps}, hospitals={hosps}")

# Count records per patient
total_recs = 0
for k,v in patients.items():
    uhids = v.get("uhids", {})
    rec_count = sum(len(ulist) for ulist in uhids.values())
    total_recs += max(1, rec_count)
print(f"Total patient records (approx): {total_recs}")
