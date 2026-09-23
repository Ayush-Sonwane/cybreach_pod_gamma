"""Tests for the re-validation OCSF validator."""
import pytest

from src.service.validator import validate_event
from tests.samples import FIXED_EVENT, INVALID_EVENT


def test_valid_event_passes():
    result = validate_event(FIXED_EVENT)
    assert result.is_valid
    assert result.errors == []


def test_missing_mandatory_fields_fail():
    result = validate_event({})
    assert not result.is_valid
    assert "Missing mandatory OCSF field: 'class_uid'" in result.errors
    assert "Missing mandatory OCSF field: 'category_uid'" in result.errors
    assert "Missing mandatory OCSF field: 'time'" in result.errors


def test_class_3002_without_user_or_actor_fails():
    event = dict(FIXED_EVENT)
    event.pop("actor")
    result = validate_event(event)
    assert not result.is_valid
    assert any("user' or 'actor'" in e for e in result.errors)


def test_invalid_time_type_fails():
    result = validate_event(INVALID_EVENT)
    assert any(e.startswith("Invalid 'time' type") for e in result.errors)


def test_complex_object_expected_dict():
    event = dict(FIXED_EVENT)
    event["src_endpoint"] = "not-a-dict"
    result = validate_event(event)
    assert any("Expected object/dict" in e for e in result.errors)


def test_non_integer_severity_fails():
    result = validate_event(INVALID_EVENT)
    assert any(e.startswith("Invalid 'severity_id'") for e in result.errors)