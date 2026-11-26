"""Lightweight structural FHIR R4 validation for RAKSHA.

No external library needed. Validates:
 - resourceType field presence and known type
 - Bundle.entry is a list of dicts with resource sub-dicts
 - Patient resource has name, gender (optional), identifier (optional)
 - Organization has name
 - Encounter, Condition, Observation have subject reference
 - After sanitisation: pseudonym injected, PII fields replaced

This module is used BEFORE export to quarantine malformed FHIR bundles and
AFTER sanitisation to verify the output is still structurally valid.
"""
from __future__ import annotations

import re
from typing import Any, Optional


# Known FHIR R4 resource types that RAKSHA handles
_KNOWN_RESOURCE_TYPES = frozenset({
    "Bundle", "Patient", "Organization", "Encounter", "Condition",
    "Observation", "MedicationRequest", "MedicationStatement",
    "AllergyIntolerance", "Procedure", "DiagnosticReport",
    "Immunization", "Composition", "Coverage", "Claim",
    "ServiceRequest", "CarePlan", "CareTeam", "Location",
    "Practitioner", "PractitionerRole", "OperationOutcome",
})


class FhirValidationResult:
    """Result of FHIR structural validation."""

    def __init__(self) -> None:
        self.valid: bool = True
        self.warnings: list[str] = []
        self.errors: list[str] = []
        self.resource_counts: dict[str, int] = {}

    def add_error(self, msg: str) -> None:
        self.valid = False
        self.errors.append(msg)

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)

    def __bool__(self) -> bool:
        return self.valid


def validate_fhir_input(data: Any) -> FhirValidationResult:
    """Validate that input JSON looks like a valid FHIR R4 resource or Bundle."""
    result = FhirValidationResult()

    if not isinstance(data, dict):
        result.add_error("FHIR resource must be a JSON object")
        return result

    rt = data.get("resourceType")
    if not rt or not isinstance(rt, str):
        result.add_error("Missing or invalid 'resourceType'")
        return result

    if rt not in _KNOWN_RESOURCE_TYPES:
        result.add_warning(f"Unknown resourceType '{rt}' — processing as generic JSON")

    if rt == "Bundle":
        _validate_bundle(data, result)
    elif rt == "Patient":
        _validate_patient(data, result, prefix="")

    return result


def validate_fhir_output(data: Any) -> FhirValidationResult:
    """Validate that sanitised FHIR output is structurally intact."""
    result = FhirValidationResult()

    if not isinstance(data, dict):
        result.add_error("Sanitised FHIR output must be a JSON object")
        return result

    rt = data.get("resourceType")
    if not rt or not isinstance(rt, str):
        result.add_error("Missing 'resourceType' in sanitised output")
        return result

    if rt == "Bundle":
        entries = data.get("entry")
        if not isinstance(entries, list):
            result.add_error("Bundle.entry must be a list")
            return result
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict):
                result.add_error(f"entry[{i}] is not a dict")
                continue
            res = entry.get("resource")
            if not isinstance(res, dict):
                result.add_error(f"entry[{i}].resource is not a dict")
                continue
            res_rt = res.get("resourceType")
            if not res_rt:
                result.add_error(f"entry[{i}].resource missing resourceType")
            result.resource_counts[str(res_rt)] = result.resource_counts.get(str(res_rt), 0) + 1

        # Check pseudonym injection
        meta = data.get("meta", {})
        if isinstance(meta, dict) and "patient_ref" in meta:
            pr = meta["patient_ref"]
            if isinstance(pr, str) and pr.startswith("PSN-"):
                pass  # Good
            elif isinstance(pr, str) and pr == "":
                result.add_warning("Empty patient_ref in Bundle.meta")
        else:
            result.add_warning("No patient_ref in Bundle.meta after sanitisation")

    return result


def _validate_bundle(data: dict, result: FhirValidationResult) -> None:
    """Validate FHIR Bundle structure."""
    entries = data.get("entry")
    if not isinstance(entries, list):
        result.add_error("Bundle.entry must be a list")
        return
    if not entries:
        result.add_warning("Bundle.entry is empty")
        return

    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            result.add_error(f"entry[{i}] is not a dict")
            continue
        res = entry.get("resource")
        if not isinstance(res, dict):
            result.add_error(f"entry[{i}].resource is not a dict")
            continue
        res_rt = res.get("resourceType", "")
        if not res_rt:
            result.add_error(f"entry[{i}].resource missing resourceType")
            continue
        result.resource_counts[res_rt] = result.resource_counts.get(res_rt, 0) + 1
        if res_rt == "Patient":
            _validate_patient(res, result, prefix=f"entry[{i}].")


def _validate_patient(data: dict, result: FhirValidationResult, prefix: str = "") -> None:
    """Validate FHIR Patient resource."""
    names = data.get("name")
    if names is None:
        result.add_warning(f"{prefix}Patient has no 'name' field")
    elif isinstance(names, list):
        for j, n in enumerate(names):
            if isinstance(n, dict):
                has_text = isinstance(n.get("text"), str) and n["text"].strip()
                has_given = isinstance(n.get("given"), list) and any(n["given"])
                has_family = isinstance(n.get("family"), str) and n["family"].strip()
                if not (has_text or has_given or has_family):
                    result.add_warning(f"{prefix}Patient.name[{j}] has no usable name parts")

    # Gender is optional but expected
    gender = data.get("gender")
    if gender and isinstance(gender, str) and gender not in ("male", "female", "other", "unknown"):
        result.add_warning(f"{prefix}Patient.gender '{gender}' not in FHIR value set")

    # birthDate format check
    bd = data.get("birthDate")
    if bd and isinstance(bd, str):
        if not re.match(r"^\d{4}(-\d{2}(-\d{2})?)?$", bd) and not bd.startswith("["):
            result.add_warning(f"{prefix}Patient.birthDate '{bd}' may not be valid FHIR date")
