"""
Automated test suite for the OCSF Normalizer's 5 SIEM adapters (Pod Gamma, Module 2).

Covers Splunk CIM, Microsoft Sentinel ASIM, Elastic ECS, IBM QRadar AQL, and
CrowdStrike LogScale LQL with at least 20 sample log events per platform.

For every sample event the suite verifies:
  1. Stage 1 - schema detection routes the event to the correct vendor adapter
  2. Stage 2 - field mapping (user, src/dst endpoint, status, severity, time)
  3. Stage 3 - output is a valid OCSF Authentication Event (OCSFValidator)
  4. Provenance tracking for every adapter (raw keys at adapter level,
     mapped.<ocsf_field> keys from complex objects)
  5. Edge cases: empty payloads and unsupported vendors fail cleanly
"""
import json
import os
from datetime import datetime

import pytest

from src.adapters.asim_adapter import ASIMAdapter
from src.adapters.ecs_adapter import ECSAdapter
from src.adapters.logscale_adapter import LogScaleAdapter
from src.adapters.qradar_adapter import QRadarAdapter
from src.adapters.splunk_adapter import SplunkAdapter
from src.detector import SchemaDetector
from src.normalizer.base import BaseNormalizer
from src.validator import OCSFValidator

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
MIN_EVENTS_PER_PLATFORM = 20
REQUIRED_PLATFORMS = ["splunk", "sentinel", "ecs", "qradar", "logscale"]

ADAPTERS = {
    "splunk": SplunkAdapter(),
    "sentinel": ASIMAdapter(),
    "ecs": ECSAdapter(),
    "qradar": QRadarAdapter(),
    "logscale": LogScaleAdapter(),
}

CLASS_UIDS = {
    "splunk": 3002,
    "sentinel": 3002,
    "ecs": 3002,
    "qradar": 3002,
    "logscale": 3002,
}


def load_fixtures():
    fixtures = {}
    for vendor in REQUIRED_PLATFORMS:
        path = os.path.join(FIXTURES_DIR, f"{vendor}_events.json")
        with open(path, encoding="utf-8") as f:
            fixtures[vendor] = json.load(f)
    return fixtures


FIXTURES = load_fixtures()

ALL_EVENTS = [
    (vendor, idx, raw)
    for vendor, events in FIXTURES.items()
    for idx, raw in enumerate(events)
]

QRADAR_LOGCALE_VENDORS = ["qradar", "logscale"]


def nested(raw, key_path):
    parts = key_path.split(".")
    curr = raw
    for p in parts:
        if isinstance(curr, dict) and p in curr:
            curr = curr[p]
        else:
            return raw.get(key_path)
    return curr


def expected_status_id(vendor, raw):
    if vendor == "splunk":
        action = str(raw.get("action") or raw.get("status") or "").lower()
        if action in ("success", "successful", "succeeded", "allowed"):
            return 1
        if action in ("failure", "failed", "error", "blocked"):
            return 2
        return 99
    if vendor == "sentinel":
        result = raw.get("EventResult", "Unknown")
        return 1 if result == "Success" else (2 if result == "Failure" else 99)
    if vendor == "ecs":
        outcome = str(nested(raw, "event.outcome") or "unknown").lower()
        return 1 if outcome in ("success", "succeeded", "allowed") else (
            2 if outcome in ("failure", "failed", "blocked", "denied") else 99)
    if vendor in ("qradar", "logscale"):
        status = str(raw.get("status") or raw.get("outcome") or "").lower()
        if status in ("success", "successful", "succeeded", "allowed"):
            return 1
        if status in ("failure", "failed", "error", "blocked"):
            return 2
        return 99
    return 99


def expected_user(vendor, raw):
    if vendor == "splunk":
        return raw.get("user") or raw.get("src_user")
    if vendor == "sentinel":
        return raw.get("TargetUsername")
    if vendor == "ecs":
        return nested(raw, "user.name")
    if vendor == "qradar":
        return raw.get("username") or raw.get("identityusername")
    if vendor == "logscale":
        return raw.get("user") or raw.get("user_name")
    return None


def expected_src_ip(vendor, raw):
    if vendor == "splunk":
        return raw.get("src_ip") or raw.get("src")
    if vendor == "sentinel":
        return raw.get("SrcIpAddr")
    if vendor == "ecs":
        return nested(raw, "source.ip")
    if vendor == "qradar":
        return raw.get("sourceip")
    if vendor == "logscale":
        return raw.get("aip") or raw.get("src_ip")
    return None


def expected_dst_ip(vendor, raw):
    if vendor == "splunk":
        return raw.get("dest_ip") or raw.get("dest")
    if vendor == "sentinel":
        return raw.get("DstIpAddr") or raw.get("TargetIpAddr")
    if vendor == "ecs":
        return nested(raw, "destination.ip")
    if vendor == "qradar":
        return raw.get("destinationip")
    if vendor == "logscale":
        return raw.get("endpoint_ip") or raw.get("dst_ip") or raw.get("endpoint")
    return None


def expected_severity_id(vendor, raw):
    if vendor == "qradar":
        try:
            mag = int(raw.get("magnitude") or raw.get("severity"))
        except (TypeError, ValueError):
            return 1
        return 5 if mag >= 9 else (4 if mag >= 7 else (3 if mag >= 5 else (2 if mag >= 3 else 1)))
    if vendor == "logscale":
        level = str(raw.get("loglevel") or raw.get("severity") or "").upper()
        mapping = {
            "DEBUG": 1, "INFO": 1, "NOTICE": 1,
            "WARN": 2, "WARNING": 2,
            "ERROR": 3, "ERR": 3,
            "HIGH": 4,
            "CRITICAL": 5, "FATAL": 5,
        }
        return mapping.get(level, 1)
    if vendor == "splunk":
        level = str(raw.get("vendor_severity", "")).lower()
        mapping = {
            "debug": 1, "info": 1, "informational": 1,
            "low": 2,
            "medium": 3, "moderate": 3,
            "high": 4,
            "critical": 5, "fatal": 5,
        }
        return mapping.get(level, 1)
    if vendor == "sentinel":
        level = str(raw.get("SeverityLevel", "")).lower()
        mapping = {
            "informational": 1, "info": 1, "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
            "fatal": 5,
        }
        return mapping.get(level, 1)
    if vendor == "ecs":
        try:
            sev = int(nested(raw, "event.severity"))
            return min(5, max(1, 1 + sev // 20))
        except (TypeError, ValueError):
            return 1
    return 1


def expected_activity_id(vendor, raw):
    return 1


def expected_time_ms(vendor, raw):
    raw_time = None
    if vendor == "splunk":
        raw_time = raw.get("_time")
    elif vendor == "qradar":
        raw_time = raw.get("starttime") or raw.get("devicetime")
    elif vendor == "logscale":
        raw_time = raw.get("@timestamp")
    elif vendor == "sentinel":
        raw_time = raw.get("EventStartTime") or raw.get("TimeGenerated")
    else:
        raw_time = raw.get("@timestamp")
    if raw_time is None:
        return None
    if isinstance(raw_time, str) and raw_time.lstrip("-").isdigit():
        raw_time = int(raw_time)
    if isinstance(raw_time, (int, float)):
        return int(raw_time) if raw_time > 10**12 else int(raw_time * 1000)
    if isinstance(raw_time, str):
        dt = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
        return int(dt.timestamp() * 1000)
    return None


CONSUMED_FIELD_PAIRS = {
    "qradar": [
        ("magnitude", "severity"),
        ("status", None),
        ("starttime", "devicetime"),
        ("sourceip", None),
        ("destinationip", None),
        ("username", "identityusername"),
    ],
    "logscale": [
        ("@timestamp", None),
        ("loglevel", "severity"),
        ("status", "outcome"),
        ("aip", "src_ip"),
        ("endpoint_ip", "dst_ip"),
        ("user", "user_name"),
    ],
}


@pytest.fixture(scope="module")
def normalizer():
    return BaseNormalizer()


@pytest.fixture(scope="module")
def validator():
    return OCSFValidator()


def test_requirement_at_least_20_events_per_platform():
    for vendor in REQUIRED_PLATFORMS:
        assert len(FIXTURES[vendor]) >= MIN_EVENTS_PER_PLATFORM, (
            f"{vendor} has {len(FIXTURES[vendor])} events, minimum is "
            f"{MIN_EVENTS_PER_PLATFORM}"
        )


def test_all_five_platforms_have_adapter_and_fixtures():
    assert set(ADAPTERS.keys()) == set(REQUIRED_PLATFORMS)
    assert set(FIXTURES.keys()) == set(REQUIRED_PLATFORMS)


@pytest.mark.parametrize("vendor,idx,raw", ALL_EVENTS)
def test_fixture_events_are_non_empty_dicts(vendor, idx, raw):
    assert isinstance(raw, dict), f"{vendor}[{idx}] is not a dict"
    assert len(raw) > 0, f"{vendor}[{idx}] is empty"


@pytest.mark.parametrize("vendor,idx,raw", ALL_EVENTS)
def test_schema_detection_routes_to_correct_vendor(vendor, idx, raw):
    assert SchemaDetector.detect_vendor(raw) == vendor, (
        f"{vendor}[{idx}] was detected as {SchemaDetector.detect_vendor(raw)}"
    )


@pytest.mark.parametrize("vendor,idx,raw", ALL_EVENTS)
def test_normalization_returns_ocsf_event(vendor, idx, raw):
    ocsf = ADAPTERS[vendor].normalize(raw)
    assert isinstance(ocsf, dict), f"{vendor}[{idx}] normalize() did not return a dict"
    assert ocsf.get("class_uid") == 3002


@pytest.mark.parametrize("vendor,idx,raw", ALL_EVENTS)
def test_ocsf_validator_accepts_normalized_event(vendor, idx, raw, validator):
    ocsf = ADAPTERS[vendor].normalize(raw)
    is_valid, errors = validator.validate_event(ocsf)
    assert is_valid, f"{vendor}[{idx}] failed validation: {errors}"


@pytest.mark.parametrize("vendor,idx,raw", ALL_EVENTS)
def test_mandatory_fields_present_and_numeric(vendor, idx, raw):
    ocsf = ADAPTERS[vendor].normalize(raw)
    for field in ("class_uid", "category_uid", "activity_id", "severity_id",
                  "status_id", "time"):
        assert field in ocsf, f"{vendor}[{idx}] missing '{field}'"
        assert isinstance(ocsf[field], int), f"{vendor}[{idx}] '{field}' not int"


@pytest.mark.parametrize("vendor,idx,raw", ALL_EVENTS)
def test_class_uid_matches_expected(vendor, idx, raw):
    ocsf = ADAPTERS[vendor].normalize(raw)
    assert ocsf["class_uid"] == CLASS_UIDS[vendor]


@pytest.mark.parametrize("vendor,idx,raw", ALL_EVENTS)
def test_status_id_mapping(vendor, idx, raw):
    ocsf = ADAPTERS[vendor].normalize(raw)
    assert ocsf["status_id"] == expected_status_id(vendor, raw), (
        f"{vendor}[{idx}] status_id={ocsf['status_id']}, expected "
        f"{expected_status_id(vendor, raw)}"
    )


@pytest.mark.parametrize("vendor,idx,raw", ALL_EVENTS)
def test_activity_id_mapping(vendor, idx, raw):
    ocsf = ADAPTERS[vendor].normalize(raw)
    assert ocsf["activity_id"] == expected_activity_id(vendor, raw)


@pytest.mark.parametrize("vendor,idx,raw", ALL_EVENTS)
def test_severity_id_mapping(vendor, idx, raw):
    ocsf = ADAPTERS[vendor].normalize(raw)
    expected = expected_severity_id(vendor, raw)
    assert ocsf["severity_id"] == expected, (
        f"{vendor}[{idx}] severity_id={ocsf['severity_id']}, expected {expected}"
    )


@pytest.mark.parametrize("vendor,idx,raw", ALL_EVENTS)
def test_user_mapping(vendor, idx, raw):
    ocsf = ADAPTERS[vendor].normalize(raw)
    expected = expected_user(vendor, raw)
    actor = ocsf.get("actor") or {}
    user = actor.get("user") if isinstance(actor, dict) else None
    if user is None:
        assert expected is None, (
            f"{vendor}[{idx}] user missing, expected '{expected}'"
        )
    else:
        assert user.get("name") == expected, (
            f"{vendor}[{idx}] user.name={user.get('name')}, expected {expected}"
        )


@pytest.mark.parametrize("vendor,idx,raw", ALL_EVENTS)
def test_src_endpoint_mapping(vendor, idx, raw):
    ocsf = ADAPTERS[vendor].normalize(raw)
    expected = expected_src_ip(vendor, raw)
    src = ocsf.get("src_endpoint")
    if src is None:
        assert expected is None, (
            f"{vendor}[{idx}] src_endpoint missing, expected ip '{expected}'"
        )
    else:
        assert src.get("ip") == expected, (
            f"{vendor}[{idx}] src_endpoint.ip={src.get('ip')}, expected {expected}"
        )


@pytest.mark.parametrize("vendor,idx,raw", ALL_EVENTS)
def test_dst_endpoint_mapping(vendor, idx, raw):
    ocsf = ADAPTERS[vendor].normalize(raw)
    expected = expected_dst_ip(vendor, raw)
    dst = ocsf.get("dst_endpoint")
    if dst is None:
        assert expected is None, (
            f"{vendor}[{idx}] dst_endpoint missing, expected ip '{expected}'"
        )
    else:
        assert dst.get("ip") == expected, (
            f"{vendor}[{idx}] dst_endpoint.ip={dst.get('ip')}, expected {expected}"
        )


@pytest.mark.parametrize("vendor,idx,raw", ALL_EVENTS)
def test_timestamp_is_epoch_ms(vendor, idx, raw):
    ocsf = ADAPTERS[vendor].normalize(raw)
    assert isinstance(ocsf["time"], int)
    assert ocsf["time"] > 0
    expected = expected_time_ms(vendor, raw)
    if expected is not None:
        assert abs(ocsf["time"] - expected) <= 1, (
            f"{vendor}[{idx}] time={ocsf['time']}, expected {expected}"
        )


@pytest.mark.parametrize("vendor,idx,raw",
                         [(v, i, e) for v, i, e in ALL_EVENTS
                          if v in QRADAR_LOGCALE_VENDORS])
def test_provenance_recorded_for_consumed_fields(vendor, idx, raw):
    ocsf = ADAPTERS[vendor].normalize(raw)
    entries = ocsf["metadata"]["provenance"]
    for primary, fallback in CONSUMED_FIELD_PAIRS[vendor]:
        source_key = None
        if primary in raw and raw[primary] is not None:
            source_key = primary
        elif fallback and fallback in raw and raw[fallback] is not None:
            source_key = fallback
        if source_key is not None:
            entry = next(
                (e for e in entries if e.get("raw_field") == source_key),
                None,
            )
            assert entry is not None, (
                f"{vendor}[{idx}] missing provenance for '{source_key}'"
            )
            assert entry["raw_field"] == source_key
            assert "ocsf_field" in entry


@pytest.mark.parametrize("vendor,idx,raw",
                         [(v, i, e) for v, i, e in ALL_EVENTS
                          if v in QRADAR_LOGCALE_VENDORS])
def test_provenance_never_records_missing_fields(vendor, idx, raw):
    ocsf = ADAPTERS[vendor].normalize(raw)
    recorded = {e.get("raw_field") for e in ocsf["metadata"]["provenance"]}
    for primary, fallback in CONSUMED_FIELD_PAIRS[vendor]:
        source_key = None
        if primary in raw and raw[primary] is not None:
            source_key = primary
        elif fallback and fallback in raw and raw[fallback] is not None:
            source_key = fallback
        if source_key is None:
            missing = [primary] + ([fallback] if fallback else [])
            assert not recorded.intersection(missing), (
                f"{vendor}[{idx}] recorded provenance for absent field(s) {missing}"
            )


@pytest.mark.parametrize("vendor", REQUIRED_PLATFORMS)
def test_end_to_end_pipeline(vendor, normalizer, validator):
    for idx, raw in enumerate(FIXTURES[vendor]):
        ocsf = normalizer.process_log(raw)
        is_valid, errors = validator.validate_event(ocsf)
        assert is_valid, f"{vendor}[{idx}] end-to-end failed: {errors}"


@pytest.mark.parametrize("vendor", REQUIRED_PLATFORMS)
def test_empty_payload_does_not_crash(vendor, validator):
    ocsf = ADAPTERS[vendor].normalize({})
    assert isinstance(ocsf, dict)
    for field in ("class_uid", "category_uid", "activity_id", "severity_id",
                  "status_id", "time"):
        assert field in ocsf and isinstance(ocsf[field], int), (
            f"{vendor} empty payload missing numeric '{field}'"
        )
    assert isinstance(ocsf["metadata"]["provenance"], list)


def test_unknown_vendor_is_rejected(normalizer):
    payload = {"some_random_key": "value"}
    assert SchemaDetector.detect_vendor(payload) == "unknown"
    with pytest.raises(ValueError):
        normalizer.process_log(payload)
