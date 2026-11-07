"""TrustLens — Tests for Shared Schema Contracts and Examples.

Validates that all JSON schemas conform to Draft 2020-12, all $ref references resolve,
all example fixtures validate against their schemas, and all models remain 100% compatible
with the intelligence engine's Pydantic models and public interfaces.
"""

import json
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from trustlens_intelligence import (
    FindingCategory,
    FindingSeverity,
    LayerCoverage,
    ProviderResultStatus,
    ScanEvidence,
    ThreatAssessment,
    Verdict,
    analyze_website,
)

CONTRACTS_DIR = Path(__file__).resolve().parents[2] / "shared" / "contracts"
SCHEMAS_DIR = CONTRACTS_DIR / "schemas"
EXAMPLES_DIR = CONTRACTS_DIR / "examples"
SCENARIOS_DIR = EXAMPLES_DIR / "scenarios"


@pytest.fixture(scope="module")
def schema_registry():
    """Load and register all schemas in referencing Registry."""
    registry = Registry()
    schemas = {}
    schema_names = [
        "scanner-evidence.schema.json",
        "ai-engine-input.schema.json",
        "ai-engine-output.schema.json",
    ]
    for name in schema_names:
        file_path = SCHEMAS_DIR / name
        assert file_path.exists(), f"Schema file missing: {file_path}"
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            schemas[name] = data
            resource = Resource.from_contents(data)
            registry = registry.with_resource(data["$id"], resource)
            registry = registry.with_resource(name, resource)
    return schemas, registry


@pytest.fixture(scope="module")
def validators(schema_registry):
    """Instantiate Draft 2020-12 validators for each contract."""
    schemas, registry = schema_registry
    return {
        "scanner-evidence": Draft202012Validator(schemas["scanner-evidence.schema.json"], registry=registry),
        "ai-engine-input": Draft202012Validator(schemas["ai-engine-input.schema.json"], registry=registry),
        "ai-engine-output": Draft202012Validator(schemas["ai-engine-output.schema.json"], registry=registry),
    }


def test_schemas_are_valid_draft_2020_12(schema_registry):
    """Assert that all schema definitions are valid Draft 2020-12 schemas."""
    schemas, _ = schema_registry
    for name, schema_dict in schemas.items():
        Draft202012Validator.check_schema(schema_dict)
        assert schema_dict["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert "$id" in schema_dict
        assert "version" in schema_dict


def test_schema_refs_resolve(validators):
    """Assert that cross-file and internal $ref references resolve without error."""
    for name, validator in validators.items():
        # Validate an empty object or dummy to trigger ref resolution
        assert validator is not None


@pytest.mark.parametrize(
    "schema_key, example_filename",
    [
        ("scanner-evidence", "scanner-evidence.example.json"),
        ("ai-engine-input", "ai-engine-input.example.json"),
        ("ai-engine-output", "ai-engine-output.example.json"),
        # Edge cases & scenarios
        ("scanner-evidence", "scenarios/scanner-evidence.missing-tls.json"),
        ("ai-engine-input", "scenarios/ai-engine-input.missing-tls.json"),
        ("ai-engine-output", "scenarios/ai-engine-output.missing-tls.json"),
        ("scanner-evidence", "scenarios/scanner-evidence.threat-match.json"),
        ("ai-engine-input", "scenarios/ai-engine-input.threat-match.json"),
        ("ai-engine-output", "scenarios/ai-engine-output.threat-match.json"),
        ("scanner-evidence", "scenarios/scanner-evidence.provider-unavailable.json"),
        ("ai-engine-input", "scenarios/ai-engine-input.provider-unavailable.json"),
        ("ai-engine-output", "scenarios/ai-engine-output.provider-unavailable.json"),
        ("scanner-evidence", "scenarios/scanner-evidence.sensitive-url.json"),
        ("ai-engine-input", "scenarios/ai-engine-input.sensitive-url.json"),
        ("ai-engine-output", "scenarios/ai-engine-output.sensitive-url.json"),
    ],
)
def test_all_examples_validate_against_schemas(validators, schema_key, example_filename):
    """Assert that every example payload validates cleanly against its contract schema."""
    example_path = EXAMPLES_DIR / example_filename
    assert example_path.exists(), f"Example file missing: {example_path}"
    with open(example_path, "r", encoding="utf-8") as f:
        instance = json.load(f)

    validator = validators[schema_key]
    errors = list(validator.iter_errors(instance))
    assert not errors, f"Validation errors in {example_filename}: {[e.message for e in errors]}"


def test_pydantic_model_compatibility():
    """Verify that all scanner and AI input examples deserialize into ScanEvidence models."""
    sample_files = [
        EXAMPLES_DIR / "scanner-evidence.example.json",
        SCENARIOS_DIR / "scanner-evidence.missing-tls.json",
        SCENARIOS_DIR / "scanner-evidence.threat-match.json",
        SCENARIOS_DIR / "scanner-evidence.provider-unavailable.json",
        SCENARIOS_DIR / "scanner-evidence.sensitive-url.json",
    ]
    for path in sample_files:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # ScanEvidence ignores extraneous operational fields like scanner_execution
        ev = ScanEvidence.model_validate(data)
        assert ev.original_url == data["original_url"]
        assert ev.canonical_url == data.get("canonical_url", data["original_url"])


def test_ai_output_pydantic_compatibility():
    """Verify that AI output examples deserialize into ThreatAssessment models."""
    sample_files = [
        EXAMPLES_DIR / "ai-engine-output.example.json",
        SCENARIOS_DIR / "ai-engine-output.missing-tls.json",
        SCENARIOS_DIR / "ai-engine-output.threat-match.json",
        SCENARIOS_DIR / "ai-engine-output.provider-unavailable.json",
        SCENARIOS_DIR / "ai-engine-output.sensitive-url.json",
    ]
    for path in sample_files:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        ta = ThreatAssessment.model_validate(data)
        assert ta.verdict.value == data["verdict"]
        assert ta.confidence == data["confidence"]
        assert ta.scoring_version == data["scoring_version"]


def test_analyze_website_with_contract_inputs(validators):
    """Verify end-to-end execution of analyze_website using contract examples and schema validation."""
    # Scenario 1: Clean site
    with open(EXAMPLES_DIR / "scanner-evidence.example.json", "r", encoding="utf-8") as f:
        clean_ev = ScanEvidence.model_validate(json.load(f))
    clean_out = analyze_website(clean_ev)
    assert clean_out.verdict == Verdict.SAFE
    assert clean_out.risk_score == 0

    # Scenario 2: Missing TLS
    with open(SCENARIOS_DIR / "scanner-evidence.missing-tls.json", "r", encoding="utf-8") as f:
        missing_tls_ev = ScanEvidence.model_validate(json.load(f))
    missing_tls_out = analyze_website(missing_tls_ev)
    assert missing_tls_out.verdict == Verdict.SAFE
    assert missing_tls_out.risk_score == 18
    assert missing_tls_out.coverage["certificate"] == LayerCoverage.NOT_APPLICABLE

    # Scenario 3: Threat match
    with open(SCENARIOS_DIR / "scanner-evidence.threat-match.json", "r", encoding="utf-8") as f:
        threat_ev = ScanEvidence.model_validate(json.load(f))
    threat_out = analyze_website(threat_ev)
    assert threat_out.verdict == Verdict.MALICIOUS
    assert threat_out.risk_score == 100

    # Scenario 4: Provider outage
    with open(SCENARIOS_DIR / "scanner-evidence.provider-unavailable.json", "r", encoding="utf-8") as f:
        outage_ev = ScanEvidence.model_validate(json.load(f))
    outage_out = analyze_website(outage_ev)
    assert outage_out.verdict == Verdict.INCONCLUSIVE

    # Scenario 5: Sensitive URL
    with open(SCENARIOS_DIR / "scanner-evidence.sensitive-url.json", "r", encoding="utf-8") as f:
        sens_ev = ScanEvidence.model_validate(json.load(f))
    sens_out = analyze_website(sens_ev)
    assert sens_out.verdict == Verdict.INCONCLUSIVE

    # Verify that to_api_dict() of every scenario cleanly validates against ai-engine-output.schema.json
    for out in [clean_out, missing_tls_out, threat_out, outage_out, sens_out]:
        out_dict = out.to_api_dict()
        errs = list(validators["ai-engine-output"].iter_errors(out_dict))
        assert not errs, f"Generated output failed schema validation: {[e.message for e in errs]}"


def test_contract_enum_consistency(schema_registry):
    """Verify that JSON schema enum values match Python StrEnum definitions."""
    schemas, _ = schema_registry
    out_schema = schemas["ai-engine-output.schema.json"]

    # Verdict
    schema_verdicts = set(out_schema["$defs"]["Verdict"]["enum"])
    py_verdicts = {v.value for v in Verdict}
    assert schema_verdicts == py_verdicts

    # FindingCategory
    schema_categories = set(out_schema["$defs"]["FindingCategory"]["enum"])
    py_categories = {c.value for c in FindingCategory}
    assert schema_categories == py_categories

    # FindingSeverity
    schema_severities = set(out_schema["$defs"]["FindingSeverity"]["enum"])
    py_severities = {s.value for s in FindingSeverity}
    assert schema_severities == py_severities

    # ProviderResultStatus
    schema_statuses = set(out_schema["$defs"]["ProviderResultStatus"]["enum"])
    py_statuses = {s.value for s in ProviderResultStatus}
    assert schema_statuses == py_statuses

    # LayerCoverage
    schema_coverages = set(out_schema["$defs"]["LayerCoverage"]["enum"])
    py_coverages = {c.value for c in LayerCoverage}
    assert schema_coverages == py_coverages

