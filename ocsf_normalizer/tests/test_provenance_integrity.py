"""
Provenance integrity tests (Pod Gamma — Module 2, task 2b).

Verifies that the ``metadata.provenance`` produced by every SIEM adapter (and
the webhook adapter) is well-formed, unique, accurate against the normalized
event, and schema-valid via the ProvenanceValidator.

These tests are platform-agnostic — they validate provenance structurally
against the schema registry and the normalized event, not against any specific
vendor's field names.
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
from src.provenance_validator import ProvenanceValidator
from src.schema.ocsf_schema import DEFAULT as REGISTRY

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

PLATFORMS = {
    "splunk": SplunkAdapter(),
    "sentinel": ASIMAdapter(),
    "ecs": ECSAdapter(),
    "qradar": QRadarAdapter(),
    "logscale": LogScaleAdapter(),
    "webhook": WebhookAdapter(),
}

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

VALIDATOR = ProvenanceValidator()


def _norm(platform, raw):
    return PLATFORMS[platform].normalize(raw)


# ---------------------------------------------------------------------------
# Structural validity
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("platform,idx,raw", ALL_EVENTS)
def test_provenance_is_well_formed(platform, idx, raw):
    ocsf = _norm(platform, raw)
    is_valid, errors = VALIDATOR.validate(ocsf)
    assert is_valid, f"{platform}[{idx}] provenance errors: {errors}"


@pytest.mark.parametrize("platform,idx,raw", ALL_EVENTS)
def test_provenance_has_no_duplicate_ocsf_fields(platform, idx, raw):
    ocsf = _norm(platform, raw)
    provenance = ocsf["metadata"]["provenance"]
    ocsf_fields = [e["ocsf_field"] for e in provenance]
    assert len(ocsf_fields) == len(set(ocsf_fields)), (
        f"{platform}[{idx}] duplicate ocsf_field entries"
    )


@pytest.mark.parametrize("platform,idx,raw", ALL_EVENTS)
def test_provenance_ocsf_fields_are_schema_valid(platform, idx, raw):
    ocsf = _norm(platform, raw)
    for entry in ocsf["metadata"]["provenance"]:
        assert VALIDATOR._is_valid_ocsf_path(entry["ocsf_field"]), (
            f"{platform}[{idx}] unknown ocsf_field '{entry['ocsf_field']}'"
        )


# ---------------------------------------------------------------------------
# Completeness
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("platform,idx,raw", ALL_EVENTS)
def test_populated_scalar_fields_have_provenance(platform, idx, raw):
    ocsf = _norm(platform, raw)
    recorded = {e["ocsf_field"] for e in ocsf["metadata"]["provenance"]}
    for field, value in ocsf.items():
        if field == "metadata":
            continue
        if field in {"class_uid", "category_uid", "activity_id"}:
            continue
        if value is None:
            continue
        if field in REGISTRY.base_fields and field not in recorded:
            # severity/status/time may be defaulted but should still be traced
            # by the adapters; if present without provenance, flag it.
            assert False, f"{platform}[{idx}] field '{field}' lacks provenance"


@pytest.mark.parametrize("platform,idx,raw", ALL_EVENTS)
def test_populated_complex_objects_have_provenance(platform, idx, raw):
    ocsf = _norm(platform, raw)
    recorded = {e["ocsf_field"] for e in ocsf["metadata"]["provenance"]}
    for field, value in ocsf.items():
        if field not in REGISTRY.complex_objects or not isinstance(value, dict):
            continue
        assert field in recorded or any(
            r.startswith(field + ".") for r in recorded
        ), f"{platform}[{idx}] object '{field}' lacks provenance"


# ---------------------------------------------------------------------------
# Strict raw-field traceability (verify provenance is accurate)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("platform,idx,raw", ALL_EVENTS)
def test_strict_provenance_raw_fields_exist(platform, idx, raw):
    """
    In strict mode every referenced raw_field must exist in the source payload.
    Provenance is accurate (fully traceable) for all supported platforms.
    """
    strict = ProvenanceValidator(strict_raw_fields=True)
    ocsf = _norm(platform, raw)
    is_valid, errors = strict.validate(ocsf, raw_event=raw)
    assert is_valid, f"{platform}[{idx}] untraceable provenance: {errors}"


# ---------------------------------------------------------------------------
# Intentional corruption → validator catches it (negative cases)
# ---------------------------------------------------------------------------
def test_duplicate_provenance_detected():
    event = {
        "class_uid": 3002, "category_uid": 3, "time": 1,
        "metadata": {
            "version": "1.1.0",
            "product": {"name": "X", "vendor_name": "Y"},
            "provenance": [
                {"ocsf_field": "time", "raw_field": "_time"},
                {"ocsf_field": "time", "raw_field": "@timestamp"},
            ],
        },
    }
    is_valid, errors = VALIDATOR.validate(event)
    assert not is_valid
    assert any("Duplicate provenance" in e for e in errors)


def test_missing_provenance_field_detected():
    event = {
        "class_uid": 3002, "category_uid": 3, "time": 1,
        "metadata": {
            "version": "1.1.0",
            "product": {"name": "X", "vendor_name": "Y"},
            "provenance": [],
        },
    }
    is_valid, errors = VALIDATOR.validate(event)
    assert not is_valid
    assert any("Missing provenance" in e for e in errors)


def test_provenance_template_requires_raw_payload():
    strict = ProvenanceValidator(strict_raw_fields=True)
    event = {
        "class_uid": 3002, "category_uid": 3, "time": 1,
        "metadata": {
            "version": "1.1.0",
            "product": {"name": "X", "vendor_name": "Y"},
            "provenance": [{"ocsf_field": "time", "raw_field": "_time"}],
        },
    }
    is_valid, errors = strict.validate(event, raw_event=None)
    assert not is_valid
    assert any("raw_event" in e for e in errors)


def test_strict_mode_flags_absent_raw_field_on_clean_event():
    # Regression: strict raw-field check must run even when the provenance is
    # otherwise well-formed/complete (previously skipped by an inverted guard).
    strict = ProvenanceValidator(strict_raw_fields=True)
    event = {
        "class_uid": 3002, "category_uid": 3, "time": 1,
        "actor": {"user": {"name": "jdoe"}},
        "metadata": {
            "version": "1.1.0",
            "product": {"name": "X", "vendor_name": "Y"},
            "provenance": [
                {"ocsf_field": "time", "raw_field": "does_not_exist"},
                {"ocsf_field": "actor.user.name", "raw_field": "user"},
            ],
        },
    }
    raw_event = {"user": "jdoe"}
    is_valid, errors = strict.validate(event, raw_event=raw_event)
    assert not is_valid
    assert any("does_not_exist" in e for e in errors)
