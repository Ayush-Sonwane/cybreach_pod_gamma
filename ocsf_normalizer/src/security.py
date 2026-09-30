"""B11: shared JWT authentication and tenant scoping for this service.

B11 recorded that Gamma's `/api/v2` routes were reachable with no credential --
`grep` for `Depends|OAuth2|APIKeyHeader|Authorization` across both services
returned nothing, so normalization, re-validation and the connector registry
were all open. Alpha, Delta and (as of this change) Beta are gated; this closes
Gamma's half and makes one token valid across the whole module.

The scheme is the same one the other pods use, deliberately: HS256 verified
against an env-only `SECRET_KEY` with no shipped default, so a deployment that
forgot to configure one fails closed with a 500 instead of accepting a token
signed with a value published in this repository.

Two identities exist in this service and they are not interchangeable:

* **operators** -- humans and services acting on the platform's data, who
  present the module JWT and are scoped by its `tenant_id` claim. The routes
  gated below are theirs.
* **connectors** -- external SIEMs posting through `/api/v2/webhook/ingest`,
  which authenticate with their own registered shared secret or HMAC signature.
  That route is deliberately *not* JWT-gated: a webhook sender is a machine that
  was issued a per-connector credential, and demanding a module JWT it was never
  given would break the integration the plan specifies. Its per-connector
  secret is the scope for that path.
"""

import os
from typing import Dict

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

ALGORITHM = "HS256"
security_scheme = HTTPBearer(auto_error=False)


def _require_secret_key() -> str:
    secret_key = os.environ.get("SECRET_KEY", "")
    if not secret_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SECRET_KEY is not configured",
        )
    return secret_key


def get_current_claims(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
) -> Dict[str, object]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        return jwt.decode(
            credentials.credentials,
            _require_secret_key(),
            algorithms=[ALGORITHM],
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def get_current_tenant(
    claims: Dict[str, object] = Depends(get_current_claims),
) -> str:
    tenant_id = claims.get("tenant_id")
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="tenant_id claim is required",
        )
    return tenant_id
