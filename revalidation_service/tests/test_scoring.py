"""Tests for confidence scoring and rule extraction."""
from src.service.scoring import build_snapshot, compute_confidence, rules_used
from src.service.validator import validate_event
from tests.samples import EVENT_ID, FIXED_EVENT, FLAWED_EVENT, INVALID_EVENT, VENDOR


def test_perfect_event_scores_100():
    confidence = compute_confidence(FIXED_EVENT, validate_event(FIXED_EVENT), VENDOR)
    assert confidence.score == 100.0
    assert confidence.reasons == []


def test_flawed_event_loses_confidence():
    confidence = compute_confidence(FLAWED_EVENT, validate_event(FLAWED_EVENT), VENDOR)
    assert confidence.score == 79.0
    assert len(confidence.reasons) == 5


def test_invalid_event_scores_low():
    validation = validate_event(INVALID_EVENT)
    confidence = compute_confidence(INVALID_EVENT, validation, VENDOR)
    assert 0.0 <= confidence.score < 50.0


def test_empty_event_baseline_score():
    confidence = compute_confidence({}, validate_event({}), VENDOR)
    assert confidence.score == 39.0


def test_rules_used_from_provenance():
    rules = rules_used(FIXED_EVENT, VENDOR)
    rule_ids = [r.rule_id for r in rules]
    assert "map.splunk.status_id" in rule_ids
    assert "map.splunk.src_endpoint.ip" in rule_ids
    for rule in rules:
        assert rule.version == "1.1.0"


def test_rules_used_falls_back_to_base_rule():
    rules = rules_used(FLAWED_EVENT, VENDOR)
    assert [r.rule_id for r in rules] == ["map.splunk.base"]
    assert rules[0].version == "1.0.0"


def test_build_snapshot_populates_all_fields():
    snapshot = build_snapshot(EVENT_ID, VENDOR, FIXED_EVENT)
    assert snapshot.event_id == EVENT_ID
    assert snapshot.vendor == VENDOR
    assert snapshot.verdict.is_valid
    assert snapshot.confidence.score == 100.0
    assert snapshot.metadata_version == "1.1.0"
    assert len(snapshot.rules_used) == 6