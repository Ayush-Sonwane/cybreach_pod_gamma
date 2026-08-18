import os
from contextlib import asynccontextmanager
from concurrent.futures import ProcessPoolExecutor
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel, Field

from src.normalizer.base import BaseNormalizer, _worker_init
from src.validator import OCSFValidator
from src.detector import SchemaDetector
from src.dlq import DeadLetterQueue
from src.webhook.repository import ConnectorRepository
from src.webhook.security import WebhookSecurity
from src.webhook.validator import WebhookSchemaValidator


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Creates one shared ProcessPoolExecutor at startup (avoiding per-request
    Windows "spawn" overhead) and shuts it down cleanly at exit.

    Pool size is startup-only configuration, from the OCSF_POOL_WORKERS env
    var (default: CPU count). It's intentionally not exposed as a
    per-request parameter, a running pool cannot be resized per call.
    """
    pool_size = int(os.getenv("OCSF_POOL_WORKERS", os.cpu_count() or 1))
    pool = ProcessPoolExecutor(max_workers=pool_size, initializer=_worker_init)
    app.state.process_pool = pool
    try:
        yield
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


app = FastAPI(
    title="OCSF Normalization API",
    version="2.0.0",
    lifespan=lifespan,
)

normalizer = BaseNormalizer()
connector_repository = ConnectorRepository()
dlq = DeadLetterQueue()


class NormalizeRequest(BaseModel):
    log: Dict[str, Any]


class NormalizeBatchRequest(BaseModel):
    logs: List[Dict[str, Any]] = Field(
        ...,
        max_length=2000,
        description="Raw vendor events to normalize. Bounded to protect the "
                    "shared process pool from being monopolized by one caller.",
    )


class WebhookConnectorRequest(BaseModel):
    id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    secret: str = Field(..., min_length=1)
    hmac_enabled: bool = False
    is_active: bool = True


@app.get("/")
def home():
    return {
        "message": "OCSF Normalization API is running"
    }


@app.post("/api/v2/ocsf/normalize")
def normalize(request: NormalizeRequest):
    try:
        event = normalizer.process_log(request.log)

        if isinstance(event, dict):
            return event

        if hasattr(event, "model_dump"):
            return event.model_dump()

    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )


@app.post("/api/v2/ocsf/normalize/batch")
def normalize_batch(request: NormalizeBatchRequest):
    """
    Batch normalization mode: normalizes many raw vendor events in parallel
    using the shared startup process pool, preserving input order.

    Per-event normalization failures are expected and returned inside
    ``results`` -- they are NOT HTTP errors. Only genuine server-side
    failures surface as 500.
    """
    try:
        return normalizer.process_batch(
            request.logs,
            app.state.process_pool,
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


@app.post("/api/v2/webhook/ingest")
async def webhook_ingest(
    request: Request,
    x_connector_id: str = Header(..., alias="X-Connector-Id"),
    x_webhook_secret: str = Header(None, alias="X-Webhook-Secret"),
    x_webhook_signature: str = Header(None, alias="X-Webhook-Signature"),
):
    """
    Generic webhook ingestion endpoint for custom SIEM solutions.

    Authentication is required and per-connector: every request must identify
    a registered connector via ``X-Connector-Id`` and authenticate with either
    the connector's shared secret (``X-Webhook-Secret``) or an HMAC-SHA256
    signature (``X-Webhook-Signature``) computed over the raw request body.

    On success the normalized OCSF event is returned; failures are recorded in
    the connector health counters and pushed to the dead-letter queue.
    """
    import json as _json
    import time as _time

    start = _time.time()

    connector = connector_repository.get_connector(x_connector_id)
    if connector is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "CONNECTOR_NOT_FOUND",
                "message": f"Connector '{x_connector_id}' is not registered",
            },
        )

    raw_body = await request.body()

    authenticated, method = WebhookSecurity.verify(
        connector,
        raw_body,
        x_webhook_secret,
        x_webhook_signature,
    )
    if not authenticated:
        connector_repository.record_delivery(
            connector_id=x_connector_id,
            status="auth_failed",
            error=method,
        )
        raise HTTPException(
            status_code=401,
            detail={
                "code": "UNAUTHORIZED",
                "message": "Missing or invalid webhook credentials",
            },
        )

    # 1. Parse JSON payload
    try:
        payload = _json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, _json.JSONDecodeError) as e:
        connector_repository.record_delivery(
            connector_id=x_connector_id,
            status="invalid",
            error="invalid_json",
            dlq=True,
        )
        dlq.push({"raw_body": raw_body.decode("utf-8", errors="replace")},
                 "invalid_json", [str(e)])
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_JSON",
                "message": "Webhook payload is not valid JSON",
            },
        )

    # 2. Validate against the generic webhook schema
    is_schema_valid, schema_errors = WebhookSchemaValidator.validate_payload(payload)
    if not is_schema_valid:
        connector_repository.record_delivery(
            connector_id=x_connector_id,
            status="invalid",
            error="schema_validation_failed",
            dlq=True,
        )
        dlq.push(payload, "schema_validation_failed", schema_errors)
        raise HTTPException(
            status_code=422,
            detail={
                "code": "SCHEMA_VALIDATION_FAILED",
                "message": "Webhook payload failed schema validation",
                "errors": schema_errors,
            },
        )

    # 3. Map webhook payload to canonical OCSF
    try:
        event = normalizer.process_log(payload)
    except Exception as e:
        connector_repository.record_delivery(
            connector_id=x_connector_id,
            status="invalid",
            error="normalization_failed",
            dlq=True,
        )
        dlq.push(payload, "normalization_failed", [str(e)])
        raise HTTPException(
            status_code=422,
            detail={
                "code": "NORMALIZATION_FAILED",
                "message": str(e),
            },
        )

    # 4. Validate the normalized OCSF event
    is_ocsf_valid, ocsf_errors = OCSFValidator.validate_event(event)
    if not is_ocsf_valid:
        connector_repository.record_delivery(
            connector_id=x_connector_id,
            status="invalid",
            error="ocsf_validation_failed",
            dlq=True,
        )
        dlq.push(payload, "ocsf_validation_failed", ocsf_errors)
        raise HTTPException(
            status_code=422,
            detail={
                "code": "OCSF_VALIDATION_FAILED",
                "message": "Normalized event failed OCSF validation",
                "errors": ocsf_errors,
            },
        )

    latency_ms = int((_time.time() - start) * 1000)
    connector_repository.record_delivery(
        connector_id=x_connector_id,
        status="valid",
        latency_ms=latency_ms,
    )

    if isinstance(event, dict):
        return event
    return event.model_dump()


@app.get("/api/v2/webhook/health")
def webhook_health():
    """
    Health monitoring for the generic webhook connector.

    Returns persisted per-connector delivery counters (delivered, valid,
    invalid, auth failures, dead-lettered events and average latency).
    """
    return {
        "connectors": connector_repository.get_health(),
    }


@app.post("/api/v2/webhook/connectors")
def create_webhook_connector(request: WebhookConnectorRequest):
    """Registers a new webhook connector with its own shared secret."""
    try:
        connector_repository.create_connector(
            connector_id=request.id,
            name=request.name,
            secret=request.secret,
            hmac_enabled=request.hmac_enabled,
            is_active=request.is_active,
        )
    except Exception:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "CONNECTOR_EXISTS",
                "message": f"Connector '{request.id}' is already registered",
            },
        )
    return {
        "id": request.id,
        "name": request.name,
        "hmac_enabled": request.hmac_enabled,
        "is_active": request.is_active,
    }


@app.get("/api/v2/webhook/connectors")
def list_webhook_connectors():
    """Lists registered webhook connectors (secrets are never returned)."""
    return {
        "connectors": connector_repository.list_connectors(),
    }