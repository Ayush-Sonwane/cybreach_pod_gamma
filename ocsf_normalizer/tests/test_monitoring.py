"""
Tests for normalization performance monitoring (Task 1 part 2).

Covers the MetricsCollector unit behavior and the API-layer integration:
  - p95 with 1, 2 and many samples
  - rolling 60-second throughput window
  - thread-safe concurrent updates
  - reset() clears all state
  - empty metrics produce valid zero-valued JSON
  - single and batch requests are counted exactly once (including the
    handler-level batch failure path)
  - existing /normalize and /normalize/batch behavior is unchanged
"""

import json
import os
import threading

import pytest

from src.monitoring.metrics import MetricsCollector
import src.main as main_mod
from src.main import app

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
REQUIRED_PLATFORMS = ["splunk", "sentinel", "ecs", "qradar", "logscale"]

INVALID_EVENT = {"totally_random_key": "value"}
VALID_BATCH = []
INVALID_ONLY_BATCH = []


def _load_fixtures():
    fixtures = {}
    for vendor in REQUIRED_PLATFORMS:
        path = os.path.join(FIXTURES_DIR, f"{vendor}_events.json")
        with open(path, encoding="utf-8") as f:
            fixtures[vendor] = json.load(f)
    return fixtures


FIXTURES = _load_fixtures()
SPLUNK_EVENT = FIXTURES["splunk"][0]
SENTINEL_EVENT = FIXTURES["sentinel"][0]
MIXED_BATCH = [SPLUNK_EVENT, INVALID_EVENT, SENTINEL_EVENT]


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


# ---------------------------------------------------------------------------
# Unit: empty state
# ---------------------------------------------------------------------------

def test_empty_snapshot_is_valid_zero_json():
    collector = MetricsCollector()
    snapshot = collector.snapshot()

    assert snapshot["total_events"] == 0
    assert snapshot["succeeded"] == 0
    assert snapshot["failed"] == 0
    assert snapshot["total_batches"] == 0
    assert snapshot["throughput_events_per_sec"]["window"] == 0.0
    assert snapshot["throughput_events_per_sec"]["lifetime"] == 0.0
    assert snapshot["latency_ms"]["single_event"] is None
    assert snapshot["latency_ms"]["batch_duration"] is None
    assert snapshot["latency_ms"]["per_event_in_batch"] is None

    # Must be valid, serializable JSON.
    json.dumps(snapshot)


# ---------------------------------------------------------------------------
# Unit: latency statistics / p95
# ---------------------------------------------------------------------------

def test_latency_stats_single_sample():
    collector = MetricsCollector()
    collector.record_single(7.5, ok=True)

    stats = collector.snapshot()["latency_ms"]["single_event"]
    assert stats == {"min": 7.5, "avg": 7.5, "max": 7.5, "p95": 7.5}


def test_p95_with_two_samples():
    collector = MetricsCollector()
    collector.record_single(1.0, ok=True)
    collector.record_single(100.0, ok=True)

    p95 = collector.snapshot()["latency_ms"]["single_event"]["p95"]
    assert p95 == 100.0


def test_p95_with_many_samples():
    collector = MetricsCollector()
    for i in range(1, 101):
        collector.record_single(float(i), ok=True)

    stats = collector.snapshot()["latency_ms"]["single_event"]
    assert stats["min"] == 1.0
    assert stats["max"] == 100.0
    assert abs(stats["avg"] - 50.5) < 1e-6
    assert stats["p95"] == 95.0


def test_p95_odd_sample_count():
    collector = MetricsCollector()
    for value in (1.0, 2.0, 3.0, 4.0, 5.0):
        collector.record_single(value, ok=True)

    p95 = collector.snapshot()["latency_ms"]["single_event"]["p95"]
    assert p95 == 5.0


def test_batch_stats_and_per_event_latency():
    collector = MetricsCollector()
    collector.record_batch(size=4, duration_ms=40.0, succeeded=3, failed=1)
    collector.record_batch(size=5, duration_ms=100.0, succeeded=5, failed=0)
    snapshot = collector.snapshot()
    assert snapshot["total_events"] == 9
    assert snapshot["succeeded"] == 8
    assert snapshot["failed"] == 1
    assert snapshot["total_batches"] == 2

    batch_stats = snapshot["latency_ms"]["batch_duration"]
    assert batch_stats == {"min": 40.0, "avg": 70.0, "max": 100.0, "p95": 100.0}

    per_event = snapshot["latency_ms"]["per_event_in_batch"]
    assert per_event == {"min": 10.0, "avg": 15.0, "max": 20.0, "p95": 20.0}


# ---------------------------------------------------------------------------
# Unit: rolling throughput window
# ---------------------------------------------------------------------------

def test_window_keeps_events_inside_window():
    clock = FakeClock()
    collector = MetricsCollector(window_seconds=60.0, clock=clock)

    collector.record_single(1.0, ok=True)
    collector.record_single(1.0, ok=True)
    clock.now = 10.0
    collector.record_single(1.0, ok=True)

    snapshot = collector.snapshot()
    assert snapshot["total_events"] == 3
    assert abs(snapshot["throughput_events_per_sec"]["window"] - 3.0 / 60.0) < 1e-9


def test_window_removes_expired_events():
    clock = FakeClock()
    collector = MetricsCollector(window_seconds=60.0, clock=clock)

    collector.record_single(1.0, ok=True)
    collector.record_single(1.0, ok=True)
    clock.now = 10.0
    collector.record_single(1.0, ok=True)

    clock.now = 61.0
    snapshot = collector.snapshot()
    # Only the event recorded at t=10 is still inside the window.
    # (snapshot values are rounded to 3 decimals)
    assert abs(snapshot["throughput_events_per_sec"]["window"] - 1.0 / 60.0) < 0.001
    # Lifetime throughput still accounts for all three events.
    assert snapshot["total_events"] == 3
    assert snapshot["throughput_events_per_sec"]["lifetime"] > 0.0


def test_window_fully_empty_after_all_events_expire():
    clock = FakeClock()
    collector = MetricsCollector(window_seconds=60.0, clock=clock)

    collector.record_single(1.0, ok=True)
    clock.now = 120.0

    snapshot = collector.snapshot()
    assert snapshot["throughput_events_per_sec"]["window"] == 0.0
    assert snapshot["total_events"] == 1


# ---------------------------------------------------------------------------
# Unit: concurrency
# ---------------------------------------------------------------------------

def test_concurrent_updates_do_not_corrupt_counters():
    collector = MetricsCollector()
    threads = 8
    per_thread = 250

    def worker():
        for i in range(per_thread):
            collector.record_single(latency_ms=float(i % 50), ok=(i % 2 == 0))
        collector.record_batch(size=10, duration_ms=5.0, succeeded=8, failed=2)

    pool = [threading.Thread(target=worker) for _ in range(threads)]
    for t in pool:
        t.start()
    for t in pool:
        t.join()

    snapshot = collector.snapshot()
    expected_single = threads * per_thread
    expected_batch_events = threads * 10
    assert snapshot["total_events"] == expected_single + expected_batch_events
    assert snapshot["succeeded"] == threads * per_thread // 2 + threads * 8
    assert snapshot["failed"] == threads * per_thread // 2 + threads * 2
    assert snapshot["total_batches"] == threads

    stats = snapshot["latency_ms"]["single_event"]
    assert stats["min"] == 0.0
    assert stats["max"] == 49.0


# ---------------------------------------------------------------------------
# Unit: reset
# ---------------------------------------------------------------------------

def test_reset_clears_all_state():
    collector = MetricsCollector()
    collector.record_single(5.0, ok=True)
    collector.record_batch(size=3, duration_ms=9.0, succeeded=2, failed=1)

    collector.reset()

    snapshot = collector.snapshot()
    assert snapshot["total_events"] == 0
    assert snapshot["succeeded"] == 0
    assert snapshot["failed"] == 0
    assert snapshot["total_batches"] == 0
    assert snapshot["throughput_events_per_sec"]["window"] == 0.0
    assert snapshot["latency_ms"]["single_event"] is None
    assert snapshot["latency_ms"]["batch_duration"] is None

    # Collector remains usable after reset.
    collector.record_single(1.0, ok=True)
    assert collector.snapshot()["total_events"] == 1


# ---------------------------------------------------------------------------
# Integration: API behavior unchanged + exactly-once accounting
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    main_mod.metrics.reset()
    try:
        from fastapi.testclient import TestClient

        with TestClient(app) as test_client:
            yield test_client
    except Exception:  # pragma: no cover - fastapi must be installed
        pytest.skip("fastapi is not installed")
    finally:
        main_mod.metrics.reset()


def _snapshot():
    return main_mod.metrics.snapshot()


def test_single_endpoint_behavior_unchanged(client):
    response = client.post("/api/v2/ocsf/normalize", json={"log": SPLUNK_EVENT})
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    assert body.get("class_uid") == 3002
    assert isinstance(body.get("time"), int)

    invalid = client.post("/api/v2/ocsf/normalize", json={"log": INVALID_EVENT})
    assert invalid.status_code == 400
    assert "unable to detect" in invalid.json()["detail"].lower()


def test_single_valid_request_counted_exactly_once(client):
    response = client.post("/api/v2/ocsf/normalize", json={"log": SPLUNK_EVENT})
    assert response.status_code == 200

    snapshot = _snapshot()
    assert snapshot["total_events"] == 1
    assert snapshot["succeeded"] == 1
    assert snapshot["failed"] == 0
    assert snapshot["total_batches"] == 0
    assert snapshot["latency_ms"]["single_event"] is not None
    assert snapshot["latency_ms"]["single_event"]["p95"] is not None
    assert snapshot["latency_ms"]["single_event"]["min"] >= 0.0


def test_invalid_single_request_counted_exactly_once(client):
    first = client.post("/api/v2/ocsf/normalize", json={"log": INVALID_EVENT})
    assert first.status_code == 400

    snapshot = _snapshot()
    assert snapshot["total_events"] == 1
    assert snapshot["failed"] == 1
    assert snapshot["succeeded"] == 0

    second = client.post("/api/v2/ocsf/normalize", json={"log": INVALID_EVENT})
    assert second.status_code == 400

    snapshot = _snapshot()
    assert snapshot["total_events"] == 2
    assert snapshot["failed"] == 2
    assert snapshot["succeeded"] == 0


def test_batch_endpoint_behavior_unchanged(client):
    response = client.post(
        "/api/v2/ocsf/normalize/batch",
        json={"logs": MIXED_BATCH},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert body["success_count"] == 2
    assert body["failure_count"] == 1
    assert body["results"][0]["success"] is True
    assert body["results"][1]["success"] is False
    assert body["results"][2]["success"] is True

    oversized = [{"some_key": i} for i in range(2001)]
    rejected = client.post(
        "/api/v2/ocsf/normalize/batch",
        json={"logs": oversized},
    )
    assert rejected.status_code == 422


def test_batch_counts_exactly_once(client):
    response = client.post(
        "/api/v2/ocsf/normalize/batch",
        json={"logs": MIXED_BATCH},
    )
    assert response.status_code == 200

    snapshot = _snapshot()
    assert snapshot["total_events"] == 3
    assert snapshot["succeeded"] == 2
    assert snapshot["failed"] == 1
    assert snapshot["total_batches"] == 1
    assert snapshot["latency_ms"]["batch_duration"] is not None
    assert snapshot["latency_ms"]["per_event_in_batch"] is not None


def test_rejected_payloads_are_not_counted(client):
    client.post("/api/v2/ocsf/normalize/batch", json={"logs": [{"x": i} for i in range(2001)]})
    client.post("/api/v2/ocsf/normalize", json={})

    snapshot = _snapshot()
    assert snapshot["total_events"] == 0
    assert snapshot["total_batches"] == 0


def test_batch_handler_exception_counted_exactly_once(client):
    original_pool = app.state.process_pool
    try:
        app.state.process_pool = None
        response = client.post(
            "/api/v2/ocsf/normalize/batch",
            json={"logs": [SPLUNK_EVENT, SENTINEL_EVENT]},
        )
        assert response.status_code == 500
    finally:
        app.state.process_pool = original_pool

    snapshot = _snapshot()
    assert snapshot["total_events"] == 2
    assert snapshot["succeeded"] == 0
    assert snapshot["failed"] == 2
    assert snapshot["total_batches"] == 1


def test_mixed_traffic_aggregates_correctly(client):
    client.post("/api/v2/ocsf/normalize", json={"log": SPLUNK_EVENT})
    client.post("/api/v2/ocsf/normalize", json={"log": INVALID_EVENT})
    client.post("/api/v2/ocsf/normalize/batch", json={"logs": MIXED_BATCH})

    snapshot = _snapshot()
    assert snapshot["total_events"] == 1 + 1 + 3
    assert snapshot["succeeded"] == 1 + 2
    assert snapshot["failed"] == 1 + 1
    assert snapshot["total_batches"] == 1
    assert snapshot["throughput_events_per_sec"]["window"] > 0.0
    assert snapshot["latency_ms"]["single_event"]["p95"] is not None
    assert snapshot["latency_ms"]["batch_duration"]["p95"] is not None


def test_metrics_endpoint_shape(client):
    client.post("/api/v2/ocsf/normalize", json={"log": SPLUNK_EVENT})

    response = client.get("/api/v2/ocsf/normalize/metrics")
    assert response.status_code == 200

    body = response.json()
    assert set(body.keys()) == {
        "uptime_seconds",
        "total_events",
        "succeeded",
        "failed",
        "total_batches",
        "throughput_events_per_sec",
        "latency_ms",
    }
    assert set(body["throughput_events_per_sec"].keys()) == {
        "window_seconds",
        "window",
        "lifetime",
    }
    assert body["throughput_events_per_sec"]["window_seconds"] == 60.0
    assert set(body["latency_ms"].keys()) == {
        "single_event",
        "batch_duration",
        "per_event_in_batch",
    }
    json.dumps(body)
