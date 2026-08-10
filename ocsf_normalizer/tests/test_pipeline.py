"""
Pipeline tests: schema auto-detection -> adapter normalization -> OCSF validation
via BaseNormalizer.process_log (Pod Gamma, Module 2).
"""
import json
import os

import pytest

from src.detector import SchemaDetector
from src.models.ocsf_models import OCSFAuthenticationEvent
from src.normalizer.base import BaseNormalizer
from src.validator import OCSFValidator

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
REQUIRED_PLATFORMS = ["splunk", "sentinel", "ecs", "qradar", "logscale"]


def load_fixtures():
    fixtures = {}
    for vendor in REQUIRED_PLATFORMS:
        path = os.path.join(FIXTURES_DIR, f"{vendor}_events.json")
        with open(path, encoding="utf-8") as f:
            fixtures[vendor] = json.load(f)
    return fixtures


FIXTURES = load_fixtures()


@pytest.fixture(scope="module")
def normalizer():
    return BaseNormalizer()


@pytest.fixture(scope="module")
def validator():
    return OCSFValidator()


@pytest.mark.parametrize("vendor", REQUIRED_PLATFORMS)
def test_pipeline_normalizes_all_fixture_events(vendor, normalizer, validator):
    for raw in FIXTURES[vendor]:
        detected = SchemaDetector.detect_vendor(raw)
        assert detected == vendor, f"{vendor} event detected as {detected}"
        event = normalizer.process_log(raw)
        assert isinstance(event, OCSFAuthenticationEvent)
        is_valid, errors = validator.validate_event(event.model_dump())
        assert is_valid, f"{vendor} event failed validation: {errors}"


def test_pipeline_rejects_unknown_vendor(normalizer):
    with pytest.raises(ValueError):
        normalizer.process_log({"some_random_key": "value"})


def test_pipeline_rejects_empty_payload(normalizer):
    with pytest.raises(ValueError):
        normalizer.process_log({})
