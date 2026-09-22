# cybreach_pod_gamma

A cyber event pipeline that normalizes raw SIEM/vendor telemetry into the
[OCSF](https://schema.ocsf.io/) (Open Cybersecurity Schema Framework) format and
continuously re-validates stored events for drift or corruption.

The repository is a monorepo containing two FastAPI microservices, a React
frontend, SQL migrations, and a small contract-publishing utility.

## Repository layout

```
cybreach_pod_gamma/
├── ocsf_normalizer/        Microservice 1 — OCSF Normalization API
│   ├── src/                Production code (adapters, validators, webhook, DLQ)
│   ├── tests/              Pytest suite + fixtures
│   ├── schemas/            Vendor → OCSF mapping JSON (asim, ecs, splunk)
│   └── migration/          SQL migrations (webhook & custom OCSF classes)
├── revalidation_service/   Microservice 2 — OCSF Re-Validation API + scheduler
│   ├── src/                Production code (delta engine, scheduler, schedules API)
│   ├── tests/              Pytest suite
│   └── SCHEDULER_CONTRACT.md   Frozen scheduler behavior contract (v1)
├── frontend/               React + Vite UI for webhook connector management
├── migration/              Shared SQL migrations
└── publish_contract.py     Publishes contract JSON into shared_registry/v1/
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
uvicorn src.main:app --reload
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
| `src/service/scheduler.py` | Fixed-delay background scheduler |
| `src/scheduling/` | Schedule CRUD API, interval models, missed-run policy |
| `src/repository.py` | SQLite persistence with idempotency & history |

Behavioral guarantees are frozen in `SCHEDULER_CONTRACT.md` (single execution
path, no overlapping runs, run-now always available, failures recorded as data).

#### Run

```bash
cd revalidation_service
pip install -r requirements.txt
uvicorn src.main:app --reload
```

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `REVALIDATION_SCHEDULER_ENABLED` | `false` | Enable automatic scheduling at startup |
| `REVALIDATION_SCHEDULER_INTERVAL_SECONDS` | `300` | Delay between run end and next run start |

#### API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Service banner |
| GET | `/health` | Liveness probe |
| POST | `/api/v2/revalidate` | Re-validate an event (requires `Idempotency-Key` header) |
| GET | `/api/v2/revalidate/{re_run_id}/delta` | Field-by-field delta for a run |
| GET | `/api/v2/revalidate/scheduler/status` | Scheduler settings, state, and run history |
| POST | `/api/v2/revalidate/scheduler/run-now` | Trigger exactly one manual run |
| PUT | `/api/v2/revalidate/scheduler/config` | Update `enabled` / `interval_seconds` at runtime |
| POST | `/api/v2/revalidate/schedules` | Create an automated schedule |
| GET | `/api/v2/revalidate/schedules` | List schedules |
| GET | `/api/v2/revalidate/schedules/{id}` | Get a schedule |
| DELETE | `/api/v2/revalidate/schedules/{id}` | Delete a schedule |

#### Tests

```bash
cd revalidation_service
pytest
```

### 3. Frontend (`frontend/`)

React + Vite dashboard for managing webhook connectors and viewing ingestion
health metrics from the normalizer service. It proxies to
`/api/v2/webhook/*`.

```bash
cd frontend
npm install
npm run dev
```

## Database migrations

`migration/` contains the shared SQL DDL:

- `001_initial_schema.sql` — raw log ingestion and normalized event tables
- `002_revalidation_schedules.sql` — automated re-validation schedule config

`ocsf_normalizer/migration/` adds normalizer-specific tables (webhook
connectors, custom OCSF class registry).

## Contract publishing

`publish_contract.py` copies a validated contract draft from
`ocsf_normalizer/src/contracts/schemas/` into `shared_registry/v1/`:

```bash
python publish_contract.py   # publishes windows_auth.json by default
```

The registry is intentionally safe: invalid JSON is rejected and nothing is
overwritten implicitly.

## Testing all services

Run from the repository root (root `pytest.ini` targets `ocsf_normalizer/tests`):

```bash
pytest
```

Each service also carries its own `pytest.ini` / suite and can be run
independently.