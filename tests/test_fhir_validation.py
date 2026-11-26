"""Tests for FHIR R4 structural validation."""
import unittest

from rakshak.privacy.fhir_validator import (
    FhirValidationResult,
    validate_fhir_input,
    validate_fhir_output,
)


class TestFhirInputValidation(unittest.TestCase):
    """Validate FHIR input structural checks."""

    def test_valid_bundle(self):
        """A well-formed FHIR Bundle should pass validation."""
        bundle = {
            "resourceType": "Bundle",
            "type": "collection",
            "entry": [
                {
                    "resource": {
                        "resourceType": "Patient",
                        "name": [{"text": "Suresh Kumar"}],
                        "gender": "male",
                        "birthDate": "1985-03-15",
                    }
                },
                {
                    "resource": {
                        "resourceType": "Organization",
                        "name": "Sanjeevani Hospital",
                    }
                },
            ],
        }
        result = validate_fhir_input(bundle)
        self.assertTrue(result)
        self.assertEqual(len(result.errors), 0)
        self.assertEqual(result.resource_counts.get("Patient", 0), 1)
        self.assertEqual(result.resource_counts.get("Organization", 0), 1)

    def test_missing_resource_type(self):
        """Missing resourceType should fail."""
        result = validate_fhir_input({"type": "collection", "entry": []})
        self.assertFalse(result)
        self.assertTrue(any("resourceType" in e for e in result.errors))

    def test_non_dict_input(self):
        """Non-dict input should fail."""
        result = validate_fhir_input([1, 2, 3])
        self.assertFalse(result)

    def test_bundle_entry_not_list(self):
        """Bundle.entry that is not a list should fail."""
        result = validate_fhir_input({"resourceType": "Bundle", "entry": "not_list"})
        self.assertFalse(result)

    def test_patient_without_name(self):
        """Patient without name generates a warning but doesn't fail."""
        bundle = {
            "resourceType": "Bundle",
            "entry": [
                {"resource": {"resourceType": "Patient", "gender": "female"}}
            ],
        }
        result = validate_fhir_input(bundle)
        self.assertTrue(result)  # Warnings don't make it invalid
        self.assertTrue(any("name" in w for w in result.warnings))

    def test_invalid_gender(self):
        """Non-standard gender generates a warning."""
        bundle = {
            "resourceType": "Bundle",
            "entry": [
                {
                    "resource": {
                        "resourceType": "Patient",
                        "name": [{"text": "Test"}],
                        "gender": "invalid_value",
                    }
                }
            ],
        }
        result = validate_fhir_input(bundle)
        self.assertTrue(result)
        self.assertTrue(any("gender" in w for w in result.warnings))

    def test_unknown_resource_type_warning(self):
        """Unknown resourceType generates a warning."""
        result = validate_fhir_input({"resourceType": "CustomResource"})
        self.assertTrue(result)  # Unknown is a warning, not an error
        self.assertTrue(any("Unknown" in w for w in result.warnings))


class TestFhirOutputValidation(unittest.TestCase):
    """Validate sanitised FHIR output checks."""

    def test_valid_sanitised_bundle(self):
        """Sanitised bundle with pseudonym should pass."""
        bundle = {
            "resourceType": "Bundle",
            "meta": {"patient_ref": "PSN-ABC123"},
            "entry": [
                {
                    "resource": {
                        "resourceType": "Patient",
                        "name": [{"text": "[PATIENT_NAME]"}],
                        "gender": "male",
                    }
                }
            ],
        }
        result = validate_fhir_output(bundle)
        self.assertTrue(result)
        self.assertEqual(len(result.errors), 0)

    def test_missing_patient_ref_warning(self):
        """Missing patient_ref generates a warning."""
        bundle = {
            "resourceType": "Bundle",
            "entry": [
                {"resource": {"resourceType": "Patient"}}
            ],
        }
        result = validate_fhir_output(bundle)
        self.assertTrue(result)  # Warnings don't fail
        self.assertTrue(any("patient_ref" in w for w in result.warnings))

    def test_non_dict_output(self):
        """Non-dict output should fail."""
        result = validate_fhir_output("not a dict")
        self.assertFalse(result)


class TestFhirRoundTrip(unittest.TestCase):
    """Verify that input validation + sanitisation + output validation works end-to-end."""

    def test_valid_input_produces_valid_output(self):
        """A valid input that is 'sanitised' (simulated) should pass output validation."""
        input_bundle = {
            "resourceType": "Bundle",
            "type": "collection",
            "entry": [
                {
                    "resource": {
                        "resourceType": "Patient",
                        "name": [{"text": "Priya Sharma"}],
                        "gender": "female",
                        "birthDate": "1990-06-25",
                    }
                },
                {
                    "resource": {
                        "resourceType": "Encounter",
                        "status": "finished",
                        "class": {"code": "IMP"},
                    }
                },
            ],
        }
        # Validate input
        in_result = validate_fhir_input(input_bundle)
        self.assertTrue(in_result)

        # Simulate sanitisation
        sanitised = {
            "resourceType": "Bundle",
            "type": "collection",
            "meta": {"patient_ref": "PSN-XYZ789"},
            "entry": [
                {
                    "resource": {
                        "resourceType": "Patient",
                        "name": [{"text": "[PATIENT_NAME]"}],
                        "gender": "female",
                        "birthDate": "30-34",
                    }
                },
                {
                    "resource": {
                        "resourceType": "Encounter",
                        "status": "finished",
                        "class": {"code": "IMP"},
                    }
                },
            ],
        }
        # Validate output
        out_result = validate_fhir_output(sanitised)
        self.assertTrue(out_result)
        self.assertEqual(out_result.resource_counts.get("Patient", 0), 1)
        self.assertEqual(out_result.resource_counts.get("Encounter", 0), 1)


if __name__ == "__main__":
    unittest.main()
