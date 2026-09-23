"""
Inter-pod normalization contract tests (Pod Gamma — task 2b).

Validates that normalized output from all SIEM platforms satisfies the
versioned inter-pod contract, which downstream pods (Re-Validation Service)
consume.  The contract validator is the single portable entry point other
pods rely on.
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
from src.contracts.normalization_contract import NormalizationContractValidator

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
    with open(
        os.path.join(FIXTURES_DIR, FIXTURE_FILES[platform]), encoding="utf-8"
    ) as f:
        return json.load(f)


ALL_EVENTS = [
    (platform, idx, raw)
    for platform in PLATFORMS
    for idx, raw in enumerate(_load(platform))
]


@pytest.fixture(scope="module")
def contract_validator():
    return NormalizationContractValidator()


@pytest.mark.parametrize("platform,idx,raw", ALL_EVENTS)
def test_contract_valid_for_all_platforms(platform, idx, raw, contract_validator):
    ocsf = PLATFORMS[platform].normalize(raw)
    result = contract_validator.validate_event(ocsf, raw_event=raw)
    assert result["is_valid"], f"{platform}[{idx}] contract errors: {result['errors']}"


@pytest.mark.parametrize("platform,idx,raw", ALL_EVENTS)
def test_strict_contract_valid_for_all_platforms(platform, idx, raw):
    strict = NormalizationContractValidator(strict_raw_fields=True)
    ocsf = PLATFORMS[platform].normalize(raw)
    result = strict.validate_event(ocsf, raw_event=raw)
    assert result["is_valid"], f"{platform}[{idx}] strict contract errors: {result['errors']}"


def test_contract_flag_invalid_event(contract_validator):
    bad = {"foo": "bar"}
    result = contract_validator.validate_event(bad)
    assert not result["is_valid"]
    assert len(result["errors"]) > 0


def test_contract_has_typed_fields_accessible():
    from src.contracts.normalization_contract import (
        Metadata,
        ProvenanceEntry,
    )

    provenance: ProvenanceEntry = {"ocsf_field": "time", "raw_field": "_time"}
    metadata: Metadata = {
        "version": "1.1.0",
        "product": {"name": "X", "vendor_name": "Y"},
        "provenance": [provenance],
    }
    assert metadata["provenance"][0]["ocsf_field"] == "time"
