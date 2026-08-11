"""Tests for the delta engine: delta tracking, verdicts, metrics."""
from src.core.contracts import EventSnapshot
from src.service.delta_engine import (
    build_report,
    compare_rule_sets,
    compare_rule_versions,
    diff_events,
    evaluate,
)
from tests.samples import EVENT_ID, FIXED_EVENT, FLAWED_EVENT, VENDOR, fixed_snapshot, flawed_snapshot


def test_diff_events_tracks_changes(tmp_path):
    before = EventSnapshot(event_id=EVENT_ID, vendor=VENDOR, normalized=FLAWED_EVENT)
    after = EventSnapshot(event_id=EVENT_ID, vendor=VENDOR, normalized=FIXED_EVENT)
    deltas = diff_events(before, after)

    fields = {d.ocsf_field: d for d in deltas}
    assert fields["status_id"].change_type == "CHANGED"
    assert fields["status_id"].old_value == 99
    assert fields["status_id"].new_value == 1
    assert fields["severity_id"].old_value == 1
    assert fields["severity_id"].new_value == 4
    assert fields["src_endpoint"].change_type == "ADDED"
    assert fields["dst_endpoint"].change_type == "ADDED"
    assert fields["metadata.version"].change_type == "CHANGED"


def test_diff_events_excludes_provenance_noise():
    before = EventSnapshot(event_id=EVENT_ID, vendor=VENDOR, normalized=FLAWED_EVENT)
    after = EventSnapshot(event_id=EVENT_ID, vendor=VENDOR, normalized=FIXED_EVENT)
    deltas = diff_events(before, after)
    assert not any(d.ocsf_field.startswith("metadata.provenance") for d in deltas)


def test_identical_events_have_no_signal_deltas():
    a = EventSnapshot(event_id=EVENT_ID, vendor=VENDOR, normalized=dict(FIXED_EVENT))
    deltas = diff_events(a, a)
    changed = [d for d in deltas if d.change_type in ("ADDED", "REMOVED", "CHANGED")]
    assert changed == []


def test_evaluate_flawed_to_fixed_is_improved():
    run = evaluate(flawed_snapshot(), fixed_snapshot(), run_id="run-1")
    assert run.verdict == "IMPROVED"
    assert run.confidence_before == 79.0
    assert run.confidence_after == 100.0
    assert run.confidence_delta == 21.0
    assert run.valid_before is True
    assert run.valid_after is True
    assert "map.splunk.status_id" in run.improved_by
    assert "map.splunk.severity_id" in run.improved_by
    assert "map.splunk.src_endpoint.ip" in run.improved_by
    assert "map.splunk.dst_endpoint.ip" in run.improved_by


def test_evaluate_identical_is_unchanged():
    run = evaluate(fixed_snapshot(), fixed_snapshot(), run_id="run-2")
    assert run.verdict == "UNCHANGED"
    assert run.confidence_delta == 0.0
    assert run.improved_by == []


def test_evaluate_reverse_is_degraded():
    run = evaluate(fixed_snapshot(), flawed_snapshot(), run_id="run-3")
    assert run.verdict == "DEGRADED"
    assert run.confidence_delta == -21.0
    assert run.degraded_by != []


def test_compare_rule_sets_detects_version_change():
    comparisons = compare_rule_sets(flawed_snapshot(), fixed_snapshot())
    by_rule = {c.rule_id: c for c in comparisons}
    assert by_rule["map.splunk.base"].removed_fields == ["map.splunk.base"]
    assert by_rule["map.splunk.status_id"].added_fields == ["map.splunk.status_id"]
    assert by_rule["map.splunk.base"].before_version == "1.0.0"


def test_build_report_aggregates_metrics():
    runs = [
        evaluate(flawed_snapshot(), fixed_snapshot(), run_id="run-a"),
        evaluate(fixed_snapshot(), fixed_snapshot(), run_id="run-b"),
        evaluate(fixed_snapshot(), flawed_snapshot(), run_id="run-c"),
    ]
    report = build_report(runs)
    assert report.total_runs == 3
    assert report.improved_runs == 1
    assert report.degraded_runs == 1
    assert report.unchanged_runs == 1
    assert report.avg_confidence_delta == 0.0
    assert report.top_rules_for_improvement
    assert report.top_rules_for_improvement[0]["improvements"] >= 1


def test_build_report_empty():
    report = build_report([])
    assert report.total_runs == 0
    assert report.top_rules_for_improvement == []


def test_compare_rule_versions_across_history():
    runs = [
        evaluate(flawed_snapshot(), fixed_snapshot(), run_id="run-a"),
        evaluate(fixed_snapshot(), fixed_snapshot(), run_id="run-b"),
    ]
    comparisons = compare_rule_versions(runs, "1.0.0", "1.1.0")
    by_rule = {c.rule_id: c for c in comparisons}
    assert by_rule["map.splunk.base"].after_version is None
    assert by_rule["map.splunk.base"].removed_fields == ["map.splunk.base"]
    assert by_rule["map.splunk.status_id"].before_version is None
    assert by_rule["map.splunk.status_id"].added_fields == ["map.splunk.status_id"]