# Re-Validation Scheduler Contract (v1)

Status: **ACTIVE v1** — implementation contract for the revalidation scheduler.

Once merged, this document is the authoritative interface for anyone building on or
beside the scheduler. The #5 interval-configuration work codes against the
"Configuration" section below — do not bypass `SchedulerSettings`.

## Scope of this contract

Defines the boundary between the scheduler engine (#4), the interval configuration
layer (#5), and the existing re-validation service. It freezes **behaviors**, not
internals.

## Work selection (input source)

`updated_event` stored in `revalidation_runs` is the input to the
`RevalidationRunner`. The runner re-validates each stored `updated_event` using the
existing `validate_ocsf_event` logic. The scheduler itself owns NO
selection/revalidation semantics beyond this agreed source; it only decides WHEN a
run happens.

## Frozen behaviors

| # | Clause | Meaning |
|---|--------|---------|
| 1 | SINGLE PATH | `run_once(trigger)` is the only execution path. Scheduled ticks and `run-now` both call it. No divergent logic may be added. |
| 2 | FIXED DELAY | Scheduling is fixed-delay: the `interval_seconds` timer starts AFTER the previous run finishes. Runs never overlap. The FIRST automatic run happens one full interval after startup. |
| 3 | RUN-NOW CONFLICT | `POST /api/v2/revalidate/scheduler/run-now` returns HTTP 409 (`SCHEDULER_RUN_IN_PROGRESS`) while ANY run (scheduled or manual) is active. |
| 4 | TICK SKIP | A scheduled tick that encounters an active run SKIPS: it records a `skipped_tick` history row and never queues another run. |
| 5 | HISTORY | `scheduler_history` records BOTH successful AND failed runs. Failures are data (a `failed` row), not exceptions. Statuses: `running`, `completed`, `failed`. |
| 6 | TIME SEMANTICS | `duration_ms` derives from a monotonic clock (`perf_counter`). `started_at`/`finished_at` are UTC wall-clock ISO timestamps. Never derive duration from wall-clock subtraction. |
| 7 | ENABLED FLAG | `enabled=false` disables automatic scheduling ONLY. `run-now` remains available in every mode. |
| 8 | FAIL FAST | Missing env vars → documented defaults. Present-but-invalid values → startup failure with a clear error message (never silent fallback). |
| 9 | SINGLE WORKER | v1 assumes exactly ONE scheduler-owning process/worker. Running multiple workers with `enabled=true` duplicates runs. DB-backed leasing is future work, out of scope for v1. |
| 10 | BUSY TIMEOUT | SQLite connections set `PRAGMA busy_timeout = 5000`. Connections stay short-lived per operation and are never shared across threads. |
| 11 | WAL DEFERRED | Deliberately excluded from v1 for deployment simplicity. Adding `journal_mode=WAL` later requires explicit coordination with the service owner. |

## Configuration (the #5 seam)

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `enabled` | bool | `false` | `REVALIDATION_SCHEDULER_ENABLED` |
| `interval_seconds` | int | `300` | `REVALIDATION_SCHEDULER_INTERVAL_SECONDS` |

Validation rules:
- Booleans accepted: `true`, `false`, `1`, `0` (case-insensitive, whitespace-trimmed). Anything else fails startup.
- `interval_seconds` must be an integer `>= 1`. Anything else fails startup.

Semantics:
- `enabled=false`: no automatic scheduling; manual `run-now` still works.
- `enabled=true`: automatic fixed-delay scheduling starts with the application lifespan.
- `interval_seconds=N`: delay between the END of one automatic run and the START of the next.

## API surface

- `GET  /api/v2/revalidate/scheduler/status` — settings, whether the background
  scheduler is running, counters, last run, recent history.
- `POST /api/v2/revalidate/scheduler/run-now` — triggers exactly one run through the
  same `run_once("manual")` path; `409` if a run is active; a runner failure is
  returned as HTTP 200 with `"status": "failed"` plus the recorded error (failures
  are data).
- RESERVED for #5: `PUT /api/v2/revalidate/scheduler/config` — must operate through
  `SchedulerSettings`; must not mutate engine internals directly.

## History schema (v1)

```sql
scheduler_history (
  run_id         TEXT PRIMARY KEY,
  trigger        TEXT NOT NULL,   -- 'scheduled' | 'manual' | 'skipped_tick'
  status         TEXT NOT NULL,   -- 'running' | 'completed' | 'failed'
  started_at     TEXT NOT NULL,
  finished_at    TEXT,            -- NULL until the run finishes
  checked_count  INTEGER NOT NULL DEFAULT 0,
  valid_count    INTEGER NOT NULL DEFAULT 0,
  invalid_count  INTEGER NOT NULL DEFAULT 0,
  duration_ms    REAL,
  error          TEXT
)
```

Reserved for future need (not built in v1): `configuration_snapshot` column.
