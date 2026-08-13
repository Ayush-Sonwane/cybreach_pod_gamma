# src/webhook/security.py
import hashlib
import hmac
import secrets
from typing import Any, Dict, Optional, Tuple

# Header names used by the generic webhook connector.
CONNECTOR_ID_HEADER = "X-Connector-Id"
SECRET_HEADER = "X-Webhook-Secret"
SIGNATURE_HEADER = "X-Webhook-Signature"


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