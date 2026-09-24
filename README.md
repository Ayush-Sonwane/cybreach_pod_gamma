# cybreach_pod_gamma

A cyber event pipeline that normalizes raw SIEM/vendor telemetry into the
[OCSF](https://schema.ocsf.io/) (Open Cybersecurity Schema Framework) format and
continuously re-validates stored events for drift or corruption.

The repository is a monorepo containing two FastAPI microservices, a React
frontend, SQL migrations, and a small contract-publishing utility.

## Repository layout

```
cybreach_pod_gamma/
├── ocsf_normalizer/        Microservice 1 — OCSF Normalization API (port 8005)
│   ├── src/                Production code (adapters, validators, webhook, DLQ)
│   ├── tests/              Pytest suite + fixtures
│   ├── schemas/            Vendor → OCSF mapping JSON (asim, ecs, splunk)
│   └── migration/          SQL migrations (webhook & custom OCSF classes)
├── revalidation_service/   Microservice 2 — OCSF Re-Validation API (port 8006)
│   ├── src/                Production code (delta engine, history store, wallet)
│   └── tests/              Pytest suite
├── frontend/               React + Vite UI for webhook connector management (port 5174)
├── migration/              Shared SQL migrations
├── contracts/              Published OCSF schema contract (JSON Schema)
├── shared_registry/v1/     Cross-pod contract samples
└── publish_contract.py     Publishes contract JSON into contracts/
```


## Services

### 1. OCSF Normalizer (`ocsf_normalizer/`)

Normalizes raw events from multiple SIEM sources into OCSF v2 and exposes a
generic webhook ingestion path.

Supported sources (adapters in `src/adapters/`):

- Splunk
- QRadar
- Azure Sentinel / ASIM
- Elastic ECS
- LogScale
- Generic webhook (`src/webhook/`)

Key modules:

| Module | Purpose |
|--------|---------|
| `src/normalizer/` | Detection, transformation, and batch normalization pipeline |
| `src/validator.py` | OCSF event validation |
| `src/provenance_validator.py` | Provenance / metadata integrity checks |
| `src/dlq.py` | Dead-letter queue for failed events |
| `src/webhook/` | Connector registry, HMAC/shared-secret auth, payload validation |
| `src/ocsf_registry/` | Custom OCSF class registration per organization |
| `src/schema/` | OCSF schema handling |
| `schemas/` | Vendor → OCSF field mapping JSON |

#### Run

```bash
cd ocsf_normalizer
pip install -r requirements.txt
uvicorn src.main:app --host 0.0.0.0 --port 8005
```

Environment variables: `OCSF_POOL_WORKERS` (process pool size for batch
normalization, default: CPU count).

#### API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Service banner |
| POST | `/api/v2/ocsf/normalize` | Normalize a single raw event |
| POST | `/api/v2/ocsf/normalize/batch` | Parallel batch normalization (max 2000 logs) |
| POST | `/api/v2/ocsf/classes` | Register a custom OCSF class |
| GET | `/api/v2/ocsf/classes` | List custom classes (filter by `?organization=`) |
| GET | `/api/v2/ocsf/classes/{class_id}` | Get a custom class by ID |
| POST | `/api/v2/webhook/ingest` | Authenticated generic webhook ingestion |
| GET | `/api/v2/webhook/health` | Per-connector delivery counters |
| POST | `/api/v2/webhook/connectors` | Register a webhook connector |
| GET | `/api/v2/webhook/connectors` | List connectors (secrets never returned) |

Webhook requests authenticate with an `X-Connector-Id` plus either
`X-Webhook-Secret` (shared secret) or `X-Webhook-Signature` (HMAC-SHA256 of the
raw body). Failed events are pushed to the DLQ and reflected in the health
counters.

#### Tests

```bash
cd ocsf_normalizer
pytest
```

### 2. Re-Validation Service (`revalidation_service/`)

Re-validates OCSF events previously stored by the normalizer, computes
before/after deltas, and schedules automated re-validation passes.

Key modules:

| Module | Purpose |
|--------|---------|
| `src/service/delta_engine.py` | Deep before/after event comparison (nested changes) |
| `src/service/history_store.py` | SQLite persistence of re-validation runs |
| `src/service/scoring.py` | Snapshot building (validation + confidence) |
| `src/wallet.py` | Mock credit wallet (plan Section 9: 1 credit per re-validation) |
| `src/core/contracts.py` | Re-validation / delta report schemas |

#### Run

```bash
cd revalidation_service
pip install -r requirements.txt
uvicorn src.main:app --host 0.0.0.0 --port 8006
```

Credit behavior: each `POST /api/v2/revalidate` debits 1 credit; an
`UNCHANGED` run is refunded. A run with no credits returns HTTP 402.

#### API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Service banner |
| GET | `/health` | Liveness probe |
| POST | `/api/v2/revalidate` | Re-validate an event (debits 1 credit, refunds on `UNCHANGED`) |
| GET | `/api/v2/revalidate/wallet` | Mock wallet balance |
| POST | `/api/v2/revalidate/compare` | Stateless before/after comparison |
| GET | `/api/v2/revalidate/runs` | List stored runs |
| GET | `/api/v2/revalidate/runs/{run_id}` | Get a stored run |
| GET | `/api/v2/revalidate/metrics` | Aggregate improvement report |
| GET | `/api/v2/revalidate/rules/compare` | Rule/version comparison (requires `v1`/`v2` query params) |

#### Tests

```bash
cd revalidation_service
pytest
```

### 3. Frontend (`frontend/`)

React + Vite dashboard for managing webhook connectors and viewing ingestion
health metrics from the normalizer service. It proxies `/api` to the OCSF
normalizer on port `8005`.

```bash
cd frontend
npm install
npm run dev        # http://localhost:5174
```

## Database migrations

`migration/` contains the shared SQL DDL:

- `001_initial_schema.sql` — raw log ingestion and normalized event tables
- `002_revalidation_schedules.sql` — automated re-validation schedule config

`ocsf_normalizer/migration/` adds normalizer-specific tables (webhook
connectors, custom OCSF class registry).

## Contract publishing

`publish_contract.py` writes the frozen OCSF normalized-event schema contract
(JSON Schema Draft-07) into `contracts/ocsf_normalizer_schema.v1.json`. This
`contracts/` directory is the pod's cross-pod publish target (per the Module 2
integration plan):

```bash
python publish_contract.py
```

`shared_registry/v1/windows_auth.json` is a field-mapping sample retained for
cross-pod reference.

## Testing all services

Run from the repository root (root `pytest.ini` targets
`ocsf_normalizer/tests` and `revalidation_service/tests`):

```bash
pytest
```

Each service also carries its own `pytest.ini` / suite and can be run
independently.