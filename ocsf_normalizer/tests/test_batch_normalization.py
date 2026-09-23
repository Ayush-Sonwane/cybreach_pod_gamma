"""
Batch Normalization Mode tests.

Verifies ``BaseNormalizer.process_batch``:

  - mixed-vendor batches preserve input order and produce valid OCSF events
  - per-event failures are isolated (they never abort the batch)
  - results are identical regardless of the injected executor's worker count
  - the executor is a required parameter (no hidden internal pool fallback)

FastAPI endpoint ``POST /api/v2/ocsf/normalize/batch``:
    batches over the 2000-event cap are rejected with 422
  - the shared startup pool is reused across sequential requests
"""
import json
import os
from concurrent.futures import ProcessPoolExecutor

import pytest

from src.normalizer.base import BaseNormalizer, _worker_init
from src.validator import OCSFValidator

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
REQUIRED_PLATFORMS = ["splunk", "sentinel", "ecs", "qradar", "logscale"]

# One unknown-vendor event mixed into an otherwise valid batch.
VALID_INVALID_MIX = [
    {"vendor_severity": "high", "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2",
     "_time": 1700000000, "user": "alice"},
    {"some_random_key": "value"},
    {"vendor_severity": "low", "src_ip": "10.0.0.3", "_time": 1700000001},
]


def load_fixtures():
    fixtures = {}
    for vendor in REQUIRED_PLATFORMS:
        path = os.path.join(FIXTURES_DIR, f"{vendor}_events.json")
        with open(path, encoding="utf-8") as f:
            fixtures[vendor] = json.load(f)
    return fixtures


FIXTURES = load_fixtures()

ALL_EVENTS = [raw for events in FIXTURES.values() for raw in events]


@pytest.fixture(scope="module")
def normalizer():
    return BaseNormalizer()


@pytest.fixture(scope="module")
def validator():
    return OCSFValidator()


def make_executor(max_workers=2):
    return ProcessPoolExecutor(max_workers=max_workers, initializer=_worker_init)


# ---------------------------------------------------------------------------
# process_batch() library-level behavior
# ---------------------------------------------------------------------------

def test_batch_empty_returns_zeroed_summary(normalizer):
    with make_executor() as executor:
        result = normalizer.process_batch([], executor)
    assert result == {"total": 0, "success_count": 0, "failure_count": 0,
                      "results": []}


def test_batch_mixed_vendor_preserves_order_and_validates(normalizer, validator):  #  mixed-vendor batches preserve input order and produce valid OCSF events
    batch = ALL_EVENTS
    expected = [normalizer.process_log(raw) for raw in batch]

    with make_executor(max_workers=4) as executor:
        result = normalizer.process_batch(batch, executor)

    assert result["total"] == len(batch)
    assert result["success_count"] == len(batch)
    assert result["failure_count"] == 0
    assert len(result["results"]) == len(batch)

    for i, (res, exp) in enumerate(zip(result["results"], expected)):
        assert res["success"] is True, f"result[{i}] reported failure"
        assert res["event"] == exp, f"result[{i}] out of order or mismatched"
        is_valid, errors = validator.validate_event(res["event"])
        assert is_valid, f"result[{i}] failed OCSF validation: {errors}"


def test_batch_isolates_per_event_failures(normalizer):
    batch = VALID_INVALID_MIX
    with make_executor(max_workers=2) as executor:
        result = normalizer.process_batch(batch, executor)

    assert result["total"] == len(batch)
    assert result["success_count"] == len(batch) - 1
    assert result["failure_count"] == 1

    assert result["results"][0]["success"] is True
    assert result["results"][1]["success"] is False
    assert "error" in result["results"][1]
    assert "unable to detect" in result["results"][1]["error"].lower()
    assert result["results"][2]["success"] is True


def test_results_identical_across_worker_counts(normalizer):
    batch = ALL_EVENTS[:10]
    expected = [normalizer.process_log(raw) for raw in batch]

    outputs = []
    for workers in (1, 4):
        with make_executor(max_workers=workers) as executor:
            outputs.append(normalizer.process_batch(batch, executor))

    for result in outputs:
        assert result["success_count"] == len(batch)
        assert [r["event"] for r in result["results"]] == expected


def test_process_batch_requires_explicit_executor(normalizer):
    with pytest.raises((AttributeError, TypeError)):
        normalizer.process_batch(ALL_EVENTS[:1], None)


# ---------------------------------------------------------------------------
# FastAPI endpoint-level behavior
# ---------------------------------------------------------------------------

try:
    from fastapi.testclient import TestClient  # noqa: E402

    from src.main import app  # noqa: E402

    HAS_FASTAPI = True
except Exception:  # pragma: no cover - depends on local env
    HAS_FASTAPI = False

skip_without_fastapi = pytest.mark.skipif(
    not HAS_FASTAPI, reason="fastapi is not installed"
)


@skip_without_fastapi
def test_batch_endpoint_rejects_oversized_payload():      # batches over the 2000-event cap are rejected with 422
    oversized = [{"some_key": i} for i in range(2001)]
    with TestClient(app) as client:
        response = client.post("/api/v2/ocsf/normalize/batch", json={"logs": oversized})
    assert response.status_code == 422


@skip_without_fastapi
def test_batch_endpoint_processes_batch_with_lifespan_pool():
    with TestClient(app) as client:
        response = client.post(
            "/api/v2/ocsf/normalize/batch",
            json={"logs": VALID_INVALID_MIX},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert body["success_count"] == 2
    assert body["failure_count"] == 1
    assert body["results"][0]["success"] is True
    assert body["results"][1]["success"] is False


@skip_without_fastapi
def test_shared_pool_reused_across_requests():
    with TestClient(app) as client:
        pool_before = app.state.process_pool

        first = client.post(
            "/api/v2/ocsf/normalize/batch",
            json={"logs": VALID_INVALID_MIX},
        )
        assert first.status_code == 200
        pool_after_first = app.state.process_pool

        second = client.post(
            "/api/v2/ocsf/normalize/batch",
            json={"logs": VALID_INVALID_MIX},
        )
        assert second.status_code == 200
        pool_after_second = app.state.process_pool

    assert pool_before is pool_after_first is pool_after_second
