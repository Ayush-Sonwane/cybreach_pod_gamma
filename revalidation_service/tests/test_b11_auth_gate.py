"""B11: the auth gate on Gamma's re-validation service must actually fail closed.

Companion to the normalizer's gate tests in `ocsf_normalizer/tests`. This suite
lives in the re-validation service's own tests directory because both services
export a top-level package literally named `src`, so only one can be imported per
pytest process (see the repo-root `pytest.ini`).

Covered:
  * no Authorization header            -> 401
  * a non-bearer scheme                -> 401
  * a token signed with the wrong key  -> 401
  * an expired token                   -> 401
  * a valid token with no tenant_id    -> 403
  * a valid token with a blank tenant  -> 403
  * a valid token                      -> 200
  * `/` and `/health` stay public      -> 200 without a token
  * missing SECRET_KEY                 -> 500 (fail closed, not fail open)
"""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from src.main import app
from tests.auth_helpers import TEST_SECRET_KEY, auth_headers
from tests.samples import EVENT_ID, VENDOR

VALID_EVENT = {
    "activity_id": 1,
    "category_uid": 3,
    "class_uid": 3002,
    "severity_id": 1,
    "status_id": 1,
    "time": 1780000000000,
    "message": "auth ok",
}

REVALIDATE_BODY = {
    "event_id": EVENT_ID,
    "vendor": VENDOR,
    "normalized": VALID_EVENT,
}
COMPARE_BODY = {
    "event_id": EVENT_ID,
    "vendor": VENDOR,
    "before": VALID_EVENT,
    "normalized": VALID_EVENT,
}

# (route id, method, path, body)
GATED_ROUTES = [
    ("revalidate", "POST", "/api/v2/revalidate", REVALIDATE_BODY),
    ("compare", "POST", "/api/v2/revalidate/compare", COMPARE_BODY),
    ("wallet", "GET", "/api/v2/revalidate/wallet", None),
    ("runs", "GET", "/api/v2/revalidate/runs", None),
    ("run_detail", "GET", "/api/v2/revalidate/runs/does-not-exist", None),
    ("metrics", "GET", "/api/v2/revalidate/metrics", None),
    ("rules_compare", "GET", "/api/v2/revalidate/rules/compare", None),
]

ROUTE_IDS = [route_id for route_id, _, _, _ in GATED_ROUTES]


def _request(client: TestClient, method: str, path: str, body, headers=None):
    if method == "GET":
        return client.get(path, headers=headers)
    return client.post(path, json=body, headers=headers)


def _token(**overrides) -> str:
    payload = {
        "sub": "test-user",
        "tenant_id": "tenant-test-0001",
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    payload.update(overrides)
    return jwt.encode(payload, TEST_SECRET_KEY, algorithm="HS256")


def _client() -> TestClient:
    """A client with no default auth, so each test states its own credential."""
    return TestClient(app)


@pytest.mark.parametrize(
    "method,path,body", [(m, p, b) for _, m, p, b in GATED_ROUTES], ids=ROUTE_IDS
)
def test_rejects_request_with_no_authorization_header(method, path, body):
    assert _request(_client(), method, path, body).status_code == 401


@pytest.mark.parametrize(
    "method,path,body", [(m, p, b) for _, m, p, b in GATED_ROUTES], ids=ROUTE_IDS
)
def test_rejects_a_non_bearer_scheme(method, path, body):
    resp = _request(
        _client(), method, path, body, headers={"Authorization": "Basic dXNlcjpwYXNz"}
    )
    assert resp.status_code == 401


@pytest.mark.parametrize(
    "method,path,body", [(m, p, b) for _, m, p, b in GATED_ROUTES], ids=ROUTE_IDS
)
def test_rejects_a_token_signed_with_a_different_key(method, path, body):
    forged = jwt.encode(
        {"sub": "attacker", "tenant_id": "tenant-test-0001"},
        "not-the-module-secret",
        algorithm="HS256",
    )
    resp = _request(
        _client(), method, path, body, headers={"Authorization": f"Bearer {forged}"}
    )
    assert resp.status_code == 401


@pytest.mark.parametrize(
    "method,path,body", [(m, p, b) for _, m, p, b in GATED_ROUTES], ids=ROUTE_IDS
)
def test_rejects_an_expired_token(method, path, body):
    expired = _token(exp=datetime.now(timezone.utc) - timedelta(hours=1))
    resp = _request(_client(), method, path, body, headers={"Authorization": f"Bearer {expired}"})
    assert resp.status_code == 401


@pytest.mark.parametrize(
    "method,path,body", [(m, p, b) for _, m, p, b in GATED_ROUTES], ids=ROUTE_IDS
)
def test_rejects_a_token_with_no_tenant_claim(method, path, body):
    claims = jwt.get_unverified_claims(_token())
    claims.pop("tenant_id", None)
    stripped = jwt.encode(claims, TEST_SECRET_KEY, algorithm="HS256")
    resp = _request(
        _client(), method, path, body, headers={"Authorization": f"Bearer {stripped}"}
    )
    assert resp.status_code == 403


@pytest.mark.parametrize(
    "method,path,body", [(m, p, b) for _, m, p, b in GATED_ROUTES], ids=ROUTE_IDS
)
def test_rejects_a_blank_tenant_claim(method, path, body):
    resp = _request(
        _client(),
        method,
        path,
        body,
        headers={"Authorization": f"Bearer {_token(tenant_id='   ')}"},
    )
    assert resp.status_code == 403


@pytest.mark.parametrize(
    "method,path,body", [(m, p, b) for _, m, p, b in GATED_ROUTES], ids=ROUTE_IDS
)
def test_fails_closed_when_the_module_secret_is_unset(method, path, body, monkeypatch):
    """No configured secret must be a 500, never an unauthenticated 200."""
    monkeypatch.delenv("SECRET_KEY", raising=False)
    resp = _request(_client(), method, path, body, headers=auth_headers())
    assert resp.status_code == 500


def test_accepts_a_valid_token():
    resp = _client().post("/api/v2/revalidate", json=REVALIDATE_BODY, headers=auth_headers())
    assert resp.status_code == 200, resp.text


def test_home_and_health_stay_public():
    """The run plan probes pods without holding a credential."""
    client = _client()
    assert client.get("/").status_code == 200
    assert client.get("/health").status_code == 200