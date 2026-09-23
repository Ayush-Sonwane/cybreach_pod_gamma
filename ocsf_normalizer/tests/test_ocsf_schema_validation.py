"""
OCSF schema compliance tests (Pod Gamma — Module 2, task 2b).

Validates normalized output from all 5 SIEM platforms (plus webhook) against
the declarative OCSFSchemaRegistry:

1. Mandatory base fields present with correct types.
2. Enum/range constraints (severity_id 1-6, status_id in {1,2,99}).
3. Complex object schema compliance (endpoint ip str, port numeric, ...).
4. metadata block structure (version, product.name, product.vendor_name).
5. Class-specific rules sourced from the registry (not hardcoded).
6. Registry-driven negative cases: out-of-range / bad-enum values are flagged.

These tests are data-driven: they walk the schema registry, so adding a new
OCSF class or field does not require new test code.
"""
import json
import os

import pytest

from src.adapters.asim_adapter import ASIMAdapter
from src.adapters.ecs_adapter import ECSAdapter
from src.adapters.logscale_adapter import LogScaleAdapter
from src.adapters.qradar_adapter import QRadarAdapter
from src.adapters.splunk_adapter import SplunkAdapter
from src.adapters.webhook_adapter import WebhookAdapter
from src.schema.ocsf_schema import DEFAULT as REGISTRY
from src.validator import OCSFValidator

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

PLATFORMS = {
    "splunk": SplunkAdapter(),
    "sentinel": ASIMAdapter(),
    "ecs": ECSAdapter(),
    "qradar": QRadarAdapter(),
    "logscale": LogScaleAdapter(),
    "webhook": WebhookAdapter(),
}

# Fixture file names (webhook has its own fixture set)
FIXTURE_FILES = {
    "splunk": "splunk_events.json",
    "sentinel": "sentinel_events.json",
    "ecs": "ecs_events.json",
    "qradar": "qradar_events.json",
    "logscale": "logscale_events.json",
    "webhook": "webhook_events.json",
}


def _load(platform: str):
    path = os.path.join(FIXTURES_DIR, FIXTURE_FILES[platform])
    with open(path, encoding="utf-8") as f:
        return json.load(f)


ALL_EVENTS = [
    (platform, idx, raw)
    for platform in PLATFORMS
    for idx, raw in enumerate(_load(platform))
]

VALIDATOR = OCSFValidator()


def _norm(platform, raw):
    return PLATFORMS[platform].normalize(raw)


# ---------------------------------------------------------------------------
# 1. Mandatory base fields & types
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("platform,idx,raw", ALL_EVENTS)
def test_required_base_fields_present(platform, idx, raw):
    ocsf = _norm(platform, raw)
    for field in REGISTRY.base_fields:
        spec = REGISTRY.base_fields[field]
        if spec.get("required"):
            assert field in ocsf, f"{platform}[{idx}] missing required '{field}'"


@pytest.mark.parametrize("platform,idx,raw", ALL_EVENTS)
def test_scalar_field_types_match_registry(platform, idx, raw):
    ocsf = _norm(platform, raw)
    for field, spec in REGISTRY.base_fields.items():
        value = ocsf.get(field)
        if value is None:
            continue
        err = REGISTRY.validate_field_value(field, value, spec)
        assert err is None, f"{platform}[{idx}] {err}"


# ---------------------------------------------------------------------------
# 2. Enum / range constraints
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("platform,idx,raw", ALL_EVENTS)
def test_severity_id_within_ocsf_range(platform, idx, raw):
    ocsf = _norm(platform, raw)
    sev = ocsf.get("severity_id")
    spec = REGISTRY.base_fields["severity_id"]
    err = REGISTRY.validate_field_value("severity_id", sev, spec)
    assert err is None, f"{platform}[{idx}] {err}"


@pytest.mark.parametrize("platform,idx,raw", ALL_EVENTS)
def test_status_id_is_valid_ocsf_enum(platform, idx, raw):
    ocsf = _norm(platform, raw)
    status = ocsf.get("status_id")
    spec = REGISTRY.base_fields["status_id"]
    err = REGISTRY.validate_field_value("status_id", status, spec)
    assert err is None, f"{platform}[{idx}] {err}"


@pytest.mark.parametrize("platform,idx,raw", ALL_EVENTS)
def test_activity_id_is_integer(platform, idx, raw):
    ocsf = _norm(platform, raw)
    assert isinstance(ocsf.get("activity_id"), int), f"{platform}[{idx}]"


# ---------------------------------------------------------------------------
# 3. Complex object schema compliance
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("platform,idx,raw", ALL_EVENTS)
def test_complex_objects_match_registry(platform, idx, raw):
    ocsf = _norm(platform, raw)
    for obj_name in REGISTRY.complex_objects:
        obj_value = ocsf.get(obj_name)
        if obj_value is None:
            continue
        errors = REGISTRY.validate_complex_object(obj_name, obj_value)
        assert not errors, f"{platform}[{idx}] {errors}"


# ---------------------------------------------------------------------------
# 4. metadata block structure
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("platform,idx,raw", ALL_EVENTS)
def test_metadata_block_is_valid(platform, idx, raw):
    ocsf = _norm(platform, raw)
    is_valid, errors = VALIDATOR.validate_metadata(ocsf)
    assert is_valid, f"{platform}[{idx}] metadata errors: {errors}"


@pytest.mark.parametrize("platform,idx,raw", ALL_EVENTS)
def test_metadata_version_is_string(platform, idx, raw):
    ocsf = _norm(platform, raw)
    version = ocsf["metadata"]["version"]
    assert isinstance(version, str) and version, f"{platform}[{idx}]"


@pytest.mark.parametrize("platform,idx,raw", ALL_EVENTS)
def test_metadata_product_has_name_and_vendor(platform, idx, raw):
    ocsf = _norm(platform, raw)
    product = ocsf["metadata"]["product"]
    assert isinstance(product, dict)
    assert product.get("name"), f"{platform}[{idx}] missing product.name"
    assert product.get("vendor_name"), f"{platform}[{idx}] missing product.vendor_name"


# ---------------------------------------------------------------------------
# 5. Class-specific rules (registry-driven, not hardcoded)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("platform,idx,raw", ALL_EVENTS)
def test_class_rules_satisfied(platform, idx, raw):
    ocsf = _norm(platform, raw)
    errors = REGISTRY.validate_class_rules(ocsf)
    assert not errors, f"{platform}[{idx}] {errors}"


@pytest.mark.parametrize("class_uid,spec", list(REGISTRY.event_classes.items()))
def test_all_registered_classes_have_valid_rules(class_uid, spec):
    # Every registered class must express at least one requirement and the
    # referenced fields must be recognized OCSF fields.
    has_rule = bool(spec.get("requires_all") or spec.get("requires_any"))
    assert has_rule, f"Class {class_uid} has no class-specific rules"
    fields = list(spec.get("requires_all", [])) + list(spec.get("requires_any", []))
    for f in fields:
        assert f in REGISTRY.base_fields or f in REGISTRY.complex_objects, (
            f"Class {class_uid} references unknown field '{f}'"
        )


# ---------------------------------------------------------------------------
# 6. Registry-driven negative cases (out-of-range / bad enums are flagged)
# ---------------------------------------------------------------------------
def test_severity_out_of_range_reported():
    event = {"class_uid": 3002, "category_uid": 3, "time": 1, "severity_id": 99,
             "actor": {"user": {"name": "x"}}}
    is_valid, errors = VALIDATOR.validate_event(event)
    assert not is_valid
    assert any("severity_id" in e for e in errors)


def test_status_not_in_enum_reported():
    event = {"class_uid": 3002, "category_uid": 3, "time": 1, "status_id": 55,
             "actor": {"user": {"name": "x"}}}
    is_valid, errors = VALIDATOR.validate_event(event)
    assert not is_valid
    assert any("status_id" in e for e in errors)


def test_metadata_missing_reported_by_metadata_validator():
    event = {"class_uid": 3002, "category_uid": 3, "time": 1}
    is_valid, errors = VALIDATOR.validate_metadata(event)
    assert not is_valid
    assert any("metadata" in e for e in errors)


def test_metadata_bad_provenance_entry_reported():
    event = {
        "class_uid": 3002, "category_uid": 3, "time": 1,
        "metadata": {
            "version": "1.1.0",
            "product": {"name": "X", "vendor_name": "Y"},
            "provenance": [{"ocsf_field": "time"}],  # missing raw_field
        },
    }
    is_valid, errors = VALIDATOR.validate_metadata(event)
    assert not is_valid
    assert any("raw_field" in e for e in errors)


def test_metadata_bad_product_reported():
    event = {
        "class_uid": 3002, "category_uid": 3, "time": 1,
        "metadata": {
            "version": "1.1.0",
            "product": {"name": "X"},  # missing vendor_name
            "provenance": [],
        },
    }
    is_valid, errors = VALIDATOR.validate_metadata(event)
    assert not is_valid
    assert any("vendor_name" in e for e in errors)


def test_new_class_can_be_registered_without_code_change():
    # Demonstrate non-hardcoding: register a brand new class with the registry
    # and verify the validator enforces its rules immediately.
    from src.schema.ocsf_schema import OCSFSchemaRegistry

    custom_registry = OCSFSchemaRegistry()
    custom_registry.event_classes[7001] = {
        "name": "Custom Group Management",
        "category_uid": 7,
        "requires_all": ["actor"],
    }

    event = {"class_uid": 7001, "category_uid": 7, "time": 1}
    is_valid, errors = OCSFValidator.validate_event(
        event, registry=custom_registry
    )
    assert not is_valid
    joined = " ".join(errors)
    assert "actor" in joined

    event_ok = {"class_uid": 7001, "category_uid": 7, "time": 1,
                "actor": {"user": {"name": "admin"}}}
    is_valid, errors = OCSFValidator.validate_event(
        event_ok, registry=custom_registry
    )
    assert is_valid, errors


def test_new_class_registration_does_not_leak_into_default_registry():
    # Regression: mutating a fresh registry must not pollute the module
    # singleton (registration is instance-scoped, not global).
    from src.schema.ocsf_schema import OCSFSchemaRegistry, DEFAULT

    custom_registry = OCSFSchemaRegistry()
    assert 7100 not in DEFAULT.event_classes
    custom_registry.event_classes[7100] = {
        "name": "Isolated Class",
        "category_uid": 7,
        "requires_all": ["actor"],
    }
    assert 7100 in custom_registry.event_classes
    assert 7100 not in DEFAULT.event_classes, (
        "custom class leaked into the DEFAULT registry"
    )


def test_default_registry_rejects_unknown_custom_class():
    # The DEFAULT registry must NOT know about a class that only exists on a
    # custom registry (verifies the validator is not silently using a leaked
    # global registry).
    from src.schema.ocsf_schema import OCSFSchemaRegistry

    custom_registry = OCSFSchemaRegistry()
    custom_registry.event_classes[7200] = {
        "name": "Private Class",
        "category_uid": 7,
        "requires_all": ["actor"],
    }

    event = {"class_uid": 7200, "category_uid": 7, "time": 1}
    is_valid, errors = OCSFValidator.validate_event(event)
    assert is_valid, "default registry must treat unknown class as unconstrained"
