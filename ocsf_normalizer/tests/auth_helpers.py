"""Shared auth helpers for the OCSF normalizer suite.

B11: the operator `/api/v2` routes now verify the module's shared JWT, so
client-based tests have to present a token. `SECRET_KEY` is assigned (not
`setdefault`) before the app is imported, because the security dependency reads
it at call time while the `TestClient` is built at module import -- and forcing
the test value keeps the suite hermetic against a developer's real `SECRET_KEY`.

`/api/v2/webhook/ingest` is deliberately *not* covered by this: that path's
callers are external SIEMs holding a per-connector shared secret, not a module
JWT (see `src/security.py`).
"""
import os

TEST_SECRET_KEY = "test-secret-key-0123456789abcdef"
TEST_TENANT_ID = "tenant-test-0001"

os.environ["SECRET_KEY"] = TEST_SECRET_KEY


def make_token(
    tenant_id: str = TEST_TENANT_ID,
    secret_key: str = TEST_SECRET_KEY,
    **claims,
) -> str:
    from datetime import datetime, timedelta, timezone

    from jose import jwt

    payload = {
        "sub": "test-user",
        "tenant_id": tenant_id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    payload.update(claims)
    return jwt.encode(payload, secret_key, algorithm="HS256")


def auth_headers(tenant_id: str = TEST_TENANT_ID, **claims) -> dict:
    return {"Authorization": f"Bearer {make_token(tenant_id, **claims)}"}


def authed_client(app, tenant_id: str = TEST_TENANT_ID):
    """A TestClient that sends a valid bearer token on every request."""
    from fastapi.testclient import TestClient

    client = TestClient(app)
    client.headers.update(auth_headers(tenant_id))
    return client
