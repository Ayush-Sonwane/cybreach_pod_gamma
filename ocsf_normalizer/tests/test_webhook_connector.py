"""
Automated test suite for the Generic Webhook Connector (custom SIEM solutions).

Covers:
  1. Webhook schema detection routes payloads to the WebhookAdapter
  2. Payload schema validation (accept/reject contract)
  3. Webhook -> OCSF mapping (provenance, severity/status/time, user, endpoints)
  4. Required per-connector security (shared secret + HMAC, constant-time checks)
  5. Persisted health monitoring (connectors + webhook_health tables)
  6. FastAPI endpoints (ingest + health + connector management)
"""
import hashlib
import hmac
import json
import os

import pytest

from src.adapters.webhook_adapter import WebhookAdapter
from src.detector import SchemaDetector
from src.normalizer.base import BaseNormalizer
from src.validator import OCSFValidator
from src.webhook.repository import ConnectorRepository
from src.webhook.security import WebhookSecurity
from src.webhook.validator import WebhookSchemaValidator

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

SEV_STR_MAP = {
    "debug": 1, "info": 1, "informational": 1, "notice": 1, "low": 2,
    "medium": 3, "moderate": 3, "warning": 3, "warn": 3,
    "high": 4,
    "critical": 5, "fatal": 5, "emergency": 5,
}

SUCCESS_WORDS = {"success", "successful", "succeeded", "allowed", "allow", "ok", "true"}
FAILURE_WORDS = {"failure", "failed", "fail", "error", "blocked", "block", "denied", "deny", "false"}


def load_fixtures():
    with open(os.path.join(FIXTURES_DIR, "webhook_events.json"), encoding="utf-8") as f:
        return json.load(f)


FIXTURES = load_fixtures()


@pytest.fixture(scope="module")
def normalizer():
    return BaseNormalizer()


@pytest.fixture(scope="module")
def validator():
    return OCSFValidator()


def expected_time_ms(raw):
    raw_time = None
    for key in ("occurred_at", "event_time", "timestamp", "@timestamp", "time", "datetime"):
        if key in raw and raw[key] is not None:
            raw_time = raw[key]
            break
    if raw_time is None:
        return None
    if isinstance(raw_time, (int, float)):
        return int(raw_time) if raw_time > 10**12 else int(raw_time * 1000)
    text = str(raw_time).strip()
    if text.lstrip("-").isdigit():
        value = int(text)
        return value if value > 10**12 else value * 1000
    return None


def expected_severity_id(raw):
    raw_val = None
    for key in ("severity_id", "severity", "level", "priority"):
        if key in raw and raw[key] is not None:
            raw_val = raw[key]
            break
    if raw_val is None:
        return 1
    if isinstance(raw_val, bool):
        return 2 if raw_val else 1
    if isinstance(raw_val, (int, float)):
        value = int(raw_val)
        if value <= 5:
            return max(1, value)
        return 5 if value >= 9 else (4 if value >= 7 else (3 if value >= 5 else (2 if value >= 3 else 1)))
    return SEV_STR_MAP.get(str(raw_val).strip().lower(), 1)


def expected_status_id(raw):
    raw_val = None
    for key in ("status", "outcome", "result", "action"):
        if key in raw and raw[key] is not None:
            raw_val = raw[key]
            break
    if raw_val is None:
        return 99
    status = str(raw_val).strip().lower()
    if status in SUCCESS_WORDS:
        return 1
    if status in FAILURE_WORDS:
        return 2
    return 99


def expected_src_ip(raw):
    for key in ("src_ip", "source_ip", "src", "source", "source.ip"):
        if key in raw and raw[key] is not None:
            return raw[key]
    return None


def expected_dst_ip(raw):
    for key in ("dst_ip", "dest_ip", "destination_ip", "dst", "dest", "destination", "destination.ip"):
        if key in raw and raw[key] is not None:
            return raw[key]
    return None


def expected_user(raw):
    for key in ("user", "username", "user_name", "src_user", "target_username", "subject_username"):
        if key in raw and raw[key] is not None:
            return raw[key]
    return None


def expected_message(raw):
    for key in ("message", "msg", "description", "details"):
        if key in raw and raw[key] is not None:
            return raw[key]
    for key in ("event_type", "event_name", "event_id", "event", "type"):
        if key in raw and raw[key] is not None:
            return raw[key]
    return None


# ---------------------------------------------------------------------------
# Stage 1: detection
# ---------------------------------------------------------------------------

def test_webhook_payloads_detect_as_webhook():
    for raw in FIXTURES:
        assert SchemaDetector.detect_vendor(raw) == "webhook"


@pytest.mark.parametrize("raw", FIXTURES)
def test_schema_detection_routes_to_webhook(raw):
    assert SchemaDetector.detect_vendor(raw) == "webhook"


# ---------------------------------------------------------------------------
# Stage 2 & 3: mapping + validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw", FIXTURES)
def test_normalization_returns_valid_ocsf(raw, validator):
    ocsf = WebhookAdapter.normalize(raw)
    is_valid, errors = validator.validate_event(ocsf)
    assert is_valid, f"validation failed: {errors}"


@pytest.mark.parametrize("raw", FIXTURES)
def test_class_uid_and_mandatory_fields(raw):
    ocsf = WebhookAdapter.normalize(raw)
    for field in ("class_uid", "category_uid", "activity_id", "severity_id",
                  "status_id", "time"):
        assert field in ocsf and isinstance(ocsf[field], int), f"missing numeric '{field}'"
    assert ocsf["class_uid"] == 3002


@pytest.mark.parametrize("raw", FIXTURES)
def test_severity_mapping(raw):
    ocsf = WebhookAdapter.normalize(raw)
    expected = expected_severity_id(raw)
    assert ocsf["severity_id"] == expected


@pytest.mark.parametrize("raw", FIXTURES)
def test_status_mapping(raw):
    ocsf = WebhookAdapter.normalize(raw)
    assert ocsf["status_id"] == expected_status_id(raw)


@pytest.mark.parametrize("raw", FIXTURES)
def test_user_mapping(raw):
    ocsf = WebhookAdapter.normalize(raw)
    expected = expected_user(raw)
    actor = ocsf.get("actor") or {}
    user = actor.get("user") if isinstance(actor, dict) else None
    if user is None:
        assert expected is None
    else:
        assert user.get("name") == expected


@pytest.mark.parametrize("raw", FIXTURES)
def test_src_endpoint_mapping(raw):
    ocsf = WebhookAdapter.normalize(raw)
    expected = expected_src_ip(raw)
    src = ocsf.get("src_endpoint")
    if src is None:
        assert expected is None
    else:
        assert src.get("ip") == expected


@pytest.mark.parametrize("raw", FIXTURES)
def test_dst_endpoint_mapping(raw):
    ocsf = WebhookAdapter.normalize(raw)
    expected = expected_dst_ip(raw)
    dst = ocsf.get("dst_endpoint")
    if dst is None:
        assert expected is None
    else:
        assert dst.get("ip") == expected


@pytest.mark.parametrize("raw", FIXTURES)
def test_message_mapping(raw):
    ocsf = WebhookAdapter.normalize(raw)
    assert ocsf.get("message") == expected_message(raw)


@pytest.mark.parametrize("raw", FIXTURES)
def test_time_is_epoch_ms(raw):
    ocsf = WebhookAdapter.normalize(raw)
    assert isinstance(ocsf["time"], int)
    assert ocsf["time"] > 0
    expected = expected_time_ms(raw)
    if expected is not None:
        assert abs(ocsf["time"] - expected) <= 1


@pytest.mark.parametrize("raw", FIXTURES)
def test_provenance_records_consumed_fields(raw):
    ocsf = WebhookAdapter.normalize(raw)
    entries = ocsf["metadata"]["provenance"]
    recorded_raw_fields = {e["raw_field"] for e in entries}
    assert "time" in {e["ocsf_field"] for e in entries}
    for key in ("severity_id", "status_id"):
        assert key in {e["ocsf_field"] for e in entries}
    if expected_src_ip(raw) is not None:
        src_keys = {k for k in ("src_ip", "source_ip", "src", "source") if k in raw}
        assert recorded_raw_fields.intersection(src_keys)
    if expected_user(raw) is not None:
        assert any(e["ocsf_field"] == "actor.user.name" for e in entries)


@pytest.mark.parametrize("raw", FIXTURES)
def test_end_to_end_pipeline(raw, normalizer, validator):
    ocsf = normalizer.process_log(raw)
    is_valid, errors = validator.validate_event(ocsf)
    assert is_valid, f"end-to-end failed: {errors}"


def test_empty_payload_does_not_crash(validator):
    ocsf = WebhookAdapter.normalize({})
    for field in ("class_uid", "category_uid", "activity_id", "severity_id",
                  "status_id", "time"):
        assert field in ocsf and isinstance(ocsf[field], int)
    assert isinstance(ocsf["metadata"]["provenance"], list)


# ---------------------------------------------------------------------------
# Webhook payload schema validation
# ---------------------------------------------------------------------------

def test_valid_payloads_pass_schema_validation():
    for raw in FIXTURES:
        valid, errors = WebhookSchemaValidator.validate_payload(raw)
        assert valid, f"payload rejected: {errors}"


@pytest.mark.parametrize("payload", [
    "not a dict",
    42,
    None,
    [],
    {},
])
def test_schema_validation_rejects_non_objects(payload):
    valid, errors = WebhookSchemaValidator.validate_payload(payload)
    assert not valid
    assert errors


def test_schema_validation_rejects_missing_timestamp():
    valid, errors = WebhookSchemaValidator.validate_payload({"event_type": "auth"})
    assert not valid
    assert any("timestamp" in e for e in errors)


def test_schema_validation_rejects_bare_context_without_descriptor():
    valid, errors = WebhookSchemaValidator.validate_payload({"event_time": "2024-01-01T00:00:00Z"})
    assert not valid


def test_schema_validation_accepts_context_only_payload():
    valid, _ = WebhookSchemaValidator.validate_payload({
        "event_time": "2024-01-01T00:00:00Z",
        "src_ip": "10.0.0.1",
        "user": "alice",
    })
    assert valid


def test_schema_validation_rejects_invalid_timestamp():
    valid, errors = WebhookSchemaValidator.validate_payload({
        "event_type": "auth",
        "event_time": "not-a-date",
    })
    assert not valid
    assert any("timestamp" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# Per-connector security (shared secret + HMAC)
# ---------------------------------------------------------------------------

def make_connector(secret="s3cr3t"):
    return {
        "id": "c1",
        "name": "Demo SIEM",
        "secret": secret,
        "hmac_enabled": True,
        "is_active": True,
        "created_at": "2024-01-01T00:00:00+00:00",
    }


def test_shared_secret_authenticates():
    connector = make_connector()
    ok, method = WebhookSecurity.verify(connector, b"{}", "s3cr3t", None)
    assert ok and method == "secret"


def test_wrong_shared_secret_rejected():
    connector = make_connector()
    ok, _ = WebhookSecurity.verify(connector, b"{}", "wrong", None)
    assert not ok


def test_missing_credentials_rejected():
    connector = make_connector()
    ok, _ = WebhookSecurity.verify(connector, b"{}", None, None)
    assert not ok


def test_hmac_signature_authenticates():
    connector = make_connector()
    body = b'{"event_type":"auth"}'
    signature = hmac.new(b"s3cr3t", body, hashlib.sha256).hexdigest()
    ok, method = WebhookSecurity.verify(connector, body, None, signature)
    assert ok and method == "hmac"


def test_hmac_signature_with_sha256_prefix():
    connector = make_connector()
    body = b'{"event_type":"auth"}'
    signature = "sha256=" + hmac.new(b"s3cr3t", body, hashlib.sha256).hexdigest()
    ok, _ = WebhookSecurity.verify(connector, body, None, signature)
    assert ok


def test_hmac_tampered_body_rejected():
    connector = make_connector()
    body = b'{"event_type":"auth"}'
    signature = hmac.new(b"s3cr3t", b'{"event_type":"evil"}', hashlib.sha256).hexdigest()
    ok, _ = WebhookSecurity.verify(connector, body, None, signature)
    assert not ok


def test_inactive_connector_rejected():
    connector = make_connector()
    connector["is_active"] = False
    ok, _ = WebhookSecurity.verify(connector, b"{}", "s3cr3t", None)
    assert not ok


def test_sign_helper_matches_verify():
    connector = make_connector()
    body = b'{"hello":"world"}'
    signature = WebhookSecurity.sign(connector["secret"], body)
    ok, _ = WebhookSecurity.verify(connector, body, None, signature)
    assert ok


# ---------------------------------------------------------------------------
# Persisted health monitoring (connectors + webhook_health)
# ---------------------------------------------------------------------------

@pytest.fixture
def repo(tmp_path):
    return ConnectorRepository(database_path=str(tmp_path / "test_connectors.db"))


def test_repository_creates_and_retrieves_connector(repo):
    repo.create_connector("c1", "Demo SIEM", "s3cr3t", hmac_enabled=True)
    connector = repo.get_connector("c1")
    assert connector["id"] == "c1"
    assert connector["name"] == "Demo SIEM"
    assert connector["secret"] == "s3cr3t"
    assert connector["hmac_enabled"] is True
    assert repo.get_connector("missing") is None


def test_repository_lists_connectors_without_secret_by_default(repo):
    repo.create_connector("c1", "Demo SIEM", "s3cr3t")
    listed = repo.list_connectors()
    assert len(listed) == 1
    assert "secret" not in listed[0]
    listed_with_secret = repo.list_connectors(include_secret=True)
    assert listed_with_secret[0]["secret"] == "s3cr3t"


def test_duplicate_connector_raises(repo):
    repo.create_connector("c1", "A", "s3cr3t")
    with pytest.raises(Exception):
        repo.create_connector("c1", "B", "other")


def test_repository_records_health_deliveries(repo):
    repo.create_connector("c1", "Demo SIEM", "s3cr3t")
    repo.record_delivery("c1", status="valid", latency_ms=10)
    repo.record_delivery("c1", status="valid", latency_ms=30)
    repo.record_delivery("c1", status="invalid", error="schema_validation_failed", dlq=True)
    repo.record_delivery("c1", status="auth_failed", error="unauthorized")

    health = repo.get_health_by_connector("c1")
    assert health["delivered"] == 4
    assert health["valid_count"] == 2
    assert health["invalid_count"] == 1
    assert health["auth_failures"] == 1
    assert health["dlq_count"] == 1
    assert health["avg_latency_ms"] == 10
    assert health["last_status"] == "auth_failed"


def test_repository_health_is_persisted(repo, tmp_path):
    repo.create_connector("c1", "Demo SIEM", "s3cr3t")
    repo.record_delivery("c1", status="valid", latency_ms=5)

    reopened = ConnectorRepository(database_path=str(tmp_path / "test_connectors.db"))
    health = reopened.get_health_by_connector("c1")
    assert health["delivered"] == 1
    assert health["valid_count"] == 1


def test_repository_get_health_aggregates(repo):
    repo.create_connector("c1", "A", "s3cr3t")
    repo.create_connector("c2", "B", "other")
    repo.record_delivery("c1", status="valid", latency_ms=50)
    repo.record_delivery("c2", status="invalid", error="bad")
    health = repo.get_health()
    assert len(health) == 2
    assert {h["connector_id"] for h in health} == {"c1", "c2"}


# ---------------------------------------------------------------------------
# FastAPI endpoints
# ---------------------------------------------------------------------------

try:
    from fastapi.testclient import TestClient  # noqa: E402

    from src.main import app, connector_repository, dlq  # noqa: E402

    HAS_FASTAPI = True
except Exception:  # pragma: no cover - depends on local env
    HAS_FASTAPI = False

skip_without_fastapi = pytest.mark.skipif(
    not HAS_FASTAPI, reason="fastapi is not installed"
)


@pytest.fixture
def client(tmp_path, monkeypatch):
    if not HAS_FASTAPI:
        pytest.skip("fastapi is not installed")
    repo = ConnectorRepository(database_path=str(tmp_path / "api_connectors.db"))
    monkeypatch.setattr("src.main.connector_repository", repo)
    monkeypatch.setattr(dlq, "queue", [])
    repo.create_connector("c1", "Demo SIEM", "s3cr3t")
    return TestClient(app)


@skip_without_fastapi
def test_ingest_valid_payload_returns_ocsf(client):
    payload = {"event_type": "auth_success", "event_time": "2024-01-01T10:00:00Z",
               "status": "success", "src_ip": "10.0.0.1", "user": "alice"}
    response = client.post(
        "/api/v2/webhook/ingest",
        json=payload,
        headers={"X-Connector-Id": "c1", "X-Webhook-Secret": "s3cr3t"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["class_uid"] == 3002
    assert body["status_id"] == 1


@skip_without_fastapi
def test_ingest_hmac_authenticated(client):
    payload = {"event_type": "auth_failure", "event_time": "2024-01-01T10:00:00Z",
               "status": "failure", "user": "bob"}
    raw_body = json.dumps(payload).encode("utf-8")
    signature = hmac.new(b"s3cr3t", raw_body, hashlib.sha256).hexdigest()
    response = client.post(
        "/api/v2/webhook/ingest",
        content=raw_body,
        headers={"X-Connector-Id": "c1", "X-Webhook-Signature": signature},
    )
    assert response.status_code == 200


@skip_without_fastapi
def test_ingest_rejects_missing_credentials(client):
    response = client.post(
        "/api/v2/webhook/ingest",
        json={"event_type": "auth", "event_time": "2024-01-01T10:00:00Z"},
        headers={"X-Connector-Id": "c1"},
    )
    assert response.status_code == 401


@skip_without_fastapi
def test_ingest_rejects_wrong_secret(client):
    response = client.post(
        "/api/v2/webhook/ingest",
        json={"event_type": "auth", "event_time": "2024-01-01T10:00:00Z"},
        headers={"X-Connector-Id": "c1", "X-Webhook-Secret": "wrong"},
    )
    assert response.status_code == 401


@skip_without_fastapi
def test_ingest_rejects_unknown_connector(client):
    response = client.post(
        "/api/v2/webhook/ingest",
        json={"event_type": "auth", "event_time": "2024-01-01T10:00:00Z"},
        headers={"X-Connector-Id": "nope", "X-Webhook-Secret": "s3cr3t"},
    )
    assert response.status_code == 404


@skip_without_fastapi
def test_ingest_rejects_invalid_json(client):
    response = client.post(
        "/api/v2/webhook/ingest",
        content=b"{not json",
        headers={"X-Connector-Id": "c1", "X-Webhook-Secret": "s3cr3t"},
    )
    assert response.status_code == 400


@skip_without_fastapi
def test_ingest_rejects_schema_invalid_payload(client):
    response = client.post(
        "/api/v2/webhook/ingest",
        json={"event_type": "auth"},
        headers={"X-Connector-Id": "c1", "X-Webhook-Secret": "s3cr3t"},
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "SCHEMA_VALIDATION_FAILED"


@skip_without_fastapi
def test_health_endpoint_returns_counters(client):
    client.post(
        "/api/v2/webhook/ingest",
        json={"event_type": "auth", "event_time": "2024-01-01T10:00:00Z", "user": "x"},
        headers={"X-Connector-Id": "c1", "X-Webhook-Secret": "s3cr3t"},
    )
    client.post(
        "/api/v2/webhook/ingest",
        json={"event_type": "auth"},
        headers={"X-Connector-Id": "c1", "X-Webhook-Secret": "s3cr3t"},
    )
    response = client.get("/api/v2/webhook/health")
    assert response.status_code == 200
    connectors = response.json()["connectors"]
    assert len(connectors) == 1
    assert connectors[0]["connector_id"] == "c1"
    assert connectors[0]["delivered"] == 2
    assert connectors[0]["valid_count"] == 1
    assert connectors[0]["invalid_count"] == 1


@skip_without_fastapi
def test_connector_management_endpoints(client):
    create = client.post("/api/v2/webhook/connectors", json={
        "id": "c2", "name": "Second SIEM", "secret": "abc123", "hmac_enabled": True,
    })
    assert create.status_code == 200
    duplicate = client.post("/api/v2/webhook/connectors", json={
        "id": "c2", "name": "Duplicate", "secret": "x",
    })
    assert duplicate.status_code == 409
    listed = client.get("/api/v2/webhook/connectors")
    assert listed.status_code == 200
    ids = [c["id"] for c in listed.json()["connectors"]]
    assert "c2" in ids
    assert all("secret" not in c for c in listed.json()["connectors"])


@skip_without_fastapi
def test_ingest_invalid_payload_goes_to_dlq(client):
    client.post(
        "/api/v2/webhook/ingest",
        json={"event_type": "auth"},
        headers={"X-Connector-Id": "c1", "X-Webhook-Secret": "s3cr3t"},
    )
    assert len(dlq.get_queue()) == 1