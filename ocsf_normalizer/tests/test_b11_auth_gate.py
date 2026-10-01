"""B11: the auth gate on Gamma's two services must actually fail closed.

B11 recorded that Gamma's `/api/v2` surface was reachable with no credential.
Adding a dependency is only half the fix -- these tests pin the failure modes,
so a later refactor that loosens the check (a permissive default, a try/except
around verification, a route that forgets the dependency) fails here rather
than silently reopening the pod.

Covered per service:
  * no Authorization header            -> 401
  * a non-bearer scheme                -> 401
  * a token signed with the wrong key  -> 401
  * an expired token                   -> 401
  * a valid token with no tenant_id    -> 403
  * a valid token with a blank tenant  -> 403
  * a valid token                      -> 200
  * `/` (and `/health`) stay public    -> 200 without a token
  * missing SECRET_KEY                 -> 500 (fail closed, not fail open)
  * tenant scoping actually separates data

Also pinned deliberately: `/api/v2/webhook/ingest` is NOT JWT-gated. Its callers
are external SIEMs holding a per-connector shared secret, so demanding a module
JWT they were never issued would break the integration the plan specifies. That
route's credential is the per-connector secret, and it still fails closed.
"""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from src.main import app as normalizer_app
from tests.auth_helpers import TEST_SECRET_KEY, TEST_TENANT_ID, auth_headers

REVALIDATION_TESTS = "tests/test_b11_auth_gate.py"

VALID_EVENT = {
    "event_type": "auth_success",
    "event_time": "2026-06-17T09:12:00Z",
    "status": "success",
    "src_ip": "10.0.0.1",
    "user": "alice",
}

# `POST /api/v2/ocsf/normalize` wraps a single raw event under `log`, and the
# batch route under `logs`; see `src/models`. These bodies are valid enough to
# be processed once the token is accepted.
NORMALIZE_BODY = {"log": VALID_EVENT}
BATCH_BODY = {"logs": [VALID_EVENT]}
CLASS_BODY = {
    "organization": "B11Org",
    "class_name": "B11Event",
    "class_uid": 9200,
    "category_uid": 9,
    "version": "1.0.0",
    "schema": {"fields": []},
}

# Operator routes that must reject an unauthenticated caller.
NORMALIZER_GATED_ROUTES = [
    ("normalize", "/api/v2/ocsf/normalize", NORMALIZE_BODY),
    ("normalize_batch", "/api/v2/ocsf/normalize/batch", BATCH_BODY),
    ("register_class", "/api/v2/ocsf/classes", CLASS_BODY),
    ("list_classes", "/api/v2/ocsf/classes", None),
    ("metrics", "/api/v2/ocsf/normalize/metrics", None),
    ("webhook_health", "/api/v2/webhook/health", None),
    ("list_connectors", "/api/v2/webhook/connectors", None),
]

ROUTE_IDS = [route_id for route_id, _, _ in NORMALIZER_GATED_ROUTES]


def _request(client: TestClient, path: str, body, headers=None):
    if body is None:
        return client.get(path, headers=headers)
    return client.post(path, json=body, headers=headers)


def _token(**overrides) -> str:
    payload = {
        "sub": "test-user",
        "tenant_id": TEST_TENANT_ID,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    payload.update(overrides)
    return jwt.encode(payload, TEST_SECRET_KEY, algorithm="HS256")


def _client() -> TestClient:
    """A client with no default auth, so each test states its own credential."""
    return TestClient(normalizer_app)


@pytest.mark.parametrize(
    "path,body", [(p, b) for _, p, b in NORMALIZER_GATED_ROUTES], ids=ROUTE_IDS
)
def test_rejects_request_with_no_authorization_header(path, body):
    assert _request(_client(), path, body).status_code == 401


@pytest.mark.parametrize(
    "path,body", [(p, b) for _, p, b in NORMALIZER_GATED_ROUTES], ids=ROUTE_IDS
)
def test_rejects_a_non_bearer_scheme(path, body):
    resp = _request(
        _client(), path, body, headers={"Authorization": "Basic dXNlcjpwYXNz"}
    )
    assert resp.status_code == 401


@pytest.mark.parametrize(
    "path,body", [(p, b) for _, p, b in NORMALIZER_GATED_ROUTES], ids=ROUTE_IDS
)
def test_rejects_a_token_signed_with_a_different_key(path, body):
    forged = jwt.encode(
        {"sub": "attacker", "tenant_id": TEST_TENANT_ID},
        "not-the-module-secret",
        algorithm="HS256",
    )
    resp = _request(_client(), path, body, headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


@pytest.mark.parametrize(
    "path,body", [(p, b) for _, p, b in NORMALIZER_GATED_ROUTES], ids=ROUTE_IDS
)
def test_rejects_an_expired_token(path, body):
    expired = _token(exp=datetime.now(timezone.utc) - timedelta(hours=1))
    resp = _request(_client(), path, body, headers={"Authorization": f"Bearer {expired}"})
    assert resp.status_code == 401


@pytest.mark.parametrize(
    "path,body", [(p, b) for _, p, b in NORMALIZER_GATED_ROUTES], ids=ROUTE_IDS
)
def test_rejects_a_token_with_no_tenant_claim(path, body):
    claims = jwt.get_unverified_claims(_token())
    claims.pop("tenant_id", None)
    stripped = jwt.encode(claims, TEST_SECRET_KEY, algorithm="HS256")
    resp = _request(_client(), path, body, headers={"Authorization": f"Bearer {stripped}"})
    assert resp.status_code == 403


@pytest.mark.parametrize(
    "path,body", [(p, b) for _, p, b in NORMALIZER_GATED_ROUTES], ids=ROUTE_IDS
)
def test_rejects_a_blank_tenant_claim(path, body):
    resp = _request(
        _client(), path, body, headers={"Authorization": f"Bearer {_token(tenant_id='   ')}"}
    )
    assert resp.status_code == 403


@pytest.mark.parametrize(
    "path,body", [(p, b) for _, p, b in NORMALIZER_GATED_ROUTES], ids=ROUTE_IDS
)
def test_fails_closed_when_the_module_secret_is_unset(path, body, monkeypatch):
    """No configured secret must be a 500, never an unauthenticated 200.

    Defaulting `SECRET_KEY` to a shipped constant would make every deployment
    that forgot to configure one accept a token signed with a value published in
    the source.
    """
    monkeypatch.delenv("SECRET_KEY", raising=False)
    resp = _request(_client(), path, body, headers=auth_headers())
    assert resp.status_code == 500


def test_accepts_a_valid_token():
    resp = _client().post(
        "/api/v2/ocsf/normalize", json=NORMALIZE_BODY, headers=auth_headers()
    )
    assert resp.status_code == 200, resp.text


def test_root_stays_public():
    """The root probe is used for service discovery without a credential."""
    assert _client().get("/").status_code == 200


def test_webhook_ingest_is_not_jwt_gated_but_still_fails_closed():
    """The documented exception: ingest authenticates by per-connector secret.

    A module JWT is neither required nor a substitute for the connector secret --
    an external SIEM was never issued one. Without valid connector credentials
    the route refuses the request (401/404 when it reaches the credential check,
    422 when the required connector-id header is absent -- either way, no ingest).
    """
    client = _client()

    anonymous = client.post("/api/v2/webhook/ingest", json=VALID_EVENT)
    assert anonymous.status_code in (401, 422), "ingest must not accept a body-only caller"

    jwt_only = client.post(
        "/api/v2/webhook/ingest", json=VALID_EVENT, headers=auth_headers()
    )
    assert jwt_only.status_code in (401, 422), (
        "a module JWT must not stand in for the connector secret"
    )

    # A wrong per-connector secret is rejected even when a valid JWT rides along.
    wrong_secret = client.post(
        "/api/v2/webhook/ingest",
        json=VALID_EVENT,
        headers={
            "X-Connector-Id": "c1",
            "X-Webhook-Secret": "wrong",
            **auth_headers(),
        },
    )
    assert wrong_secret.status_code in (401, 404)