# src/webhook/security.py
import hashlib
import hmac
import os
import secrets
from typing import Any, Dict, Optional, Tuple

# Header names used by the generic webhook connector.
CONNECTOR_ID_HEADER = "X-Connector-Id"
SECRET_HEADER = "X-Webhook-Secret"
SIGNATURE_HEADER = "X-Webhook-Signature"

# Header and env var for connector *administration* (N-G10).
ADMIN_TOKEN_HEADER = "X-Admin-Token"
ADMIN_TOKEN_ENV = "WEBHOOK_ADMIN_TOKEN"


def verify_admin_token(provided: Optional[str]) -> bool:
    """Authorise a privileged connector-administration call.

    N-G10: ``POST /api/v2/webhook/connectors`` lets a caller mint a connector
    with a secret of its choosing, which is an unauthenticated write on a pod
    that guards every other route -- the per-connector HMAC on ``ingest`` is
    only as strong as an open registration endpoint. Administration is
    therefore gated on a shared admin token, env-only with no fallback so no
    credential is committed, and compared in constant time.

    Fails closed: with no token configured, administration is unavailable.
    """

    expected = os.getenv(ADMIN_TOKEN_ENV, "")
    if not expected:
        return False

    return bool(provided) and secrets.compare_digest(provided.strip(), expected)


class WebhookSecurity:
    """
    Required per-connector authentication for webhook deliveries.

    Authentication is never optional. Each registered connector owns a shared
    secret that is used to verify either:

    - ``X-Webhook-Secret``  - shared secret passed verbatim in the header.
    - ``X-Webhook-Signature`` - HMAC-SHA256 of the raw request body keyed with
      the connector secret (hex digest, optional ``sha256=`` prefix).

    Both comparisons are constant-time to avoid timing attacks.
    """

    @staticmethod
    def verify(
        connector: Dict[str, Any],
        raw_body: bytes,
        secret_header: Optional[str],
        signature_header: Optional[str],
    ) -> Tuple[bool, str]:
        """
        Returns ``(ok, reason)``.

        Authentication is required: a request that provides neither a valid
        shared secret nor a valid HMAC signature is rejected.
        """
        if connector is None:
            return False, "connector_not_found"

        if not connector.get("is_active", True):
            return False, "connector_inactive"

        stored_secret = connector.get("secret", "")

        if secret_header:
            provided = (secret_header or "").strip()
            if provided and secrets.compare_digest(provided, stored_secret):
                return True, "secret"

        if signature_header:
            expected = hmac.new(
                stored_secret.encode("utf-8"),
                raw_body,
                hashlib.sha256,
            ).hexdigest()
            provided = (signature_header or "").strip()
            if provided.lower().startswith("sha256="):
                provided = provided[len("sha256="):]
            if provided and secrets.compare_digest(provided.lower(), expected):
                return True, "hmac"

        return False, "unauthorized"

    @staticmethod
    def sign(
        secret: str,
        raw_body: bytes,
    ) -> str:
        """Computes the expected HMAC-SHA256 signature for a raw body."""
        return hmac.new(
            secret.encode("utf-8"),
            raw_body,
            hashlib.sha256,
        ).hexdigest()