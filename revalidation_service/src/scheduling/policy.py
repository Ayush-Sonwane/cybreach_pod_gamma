"""Run-timing policy helpers for automated re-validation.

Pure functions only: they compute whether a schedule is due, how to
handle missed intervals while the service was down, and what the
Idempotency-Key for an automated run should look like. The scheduler
engine calls these; keeping them isolated makes them testable without
a running scheduler.
"""

import math

MISSED_RUN_POLICIES = ("skip", "run_once")


def is_due(
    next_run_at,
    now: float,
    enabled: bool = True,
    is_running: bool = False,
) -> bool:
    """A never-run schedule is immediately due once enabled."""

    if not enabled or is_running:
        return False

    if next_run_at is None:
        return True

    return now >= next_run_at


def apply_missed_run_policy(
    missed_run_policy: str,
    last_run_at: float,
    interval_seconds: int,
    now: float,
):
    """Decide the next run time after a due tick was detected.

    Returns (should_run, next_run_at).

    - 'skip': drop every missed tick; cadence restarts from now.
    - 'run_once': run at most one catch-up run, but keep the original
      cadence anchored to last_run_at so the phase never drifts.

    Both policies trigger at most a single run per check regardless of
    how many intervals were missed.
    """

    if missed_run_policy not in MISSED_RUN_POLICIES:
        raise ValueError(
            f"Unknown missed-run policy: '{missed_run_policy}'"
        )

    if missed_run_policy == "skip":
        next_run_at = now + interval_seconds
        return True, next_run_at

    elapsed = max(now - last_run_at, 0.0)
    missed_periods = math.floor(elapsed / interval_seconds)
    next_run_at = last_run_at + (missed_periods + 1) * interval_seconds

    return True, next_run_at


def build_scheduled_idempotency_key(
    schedule_id: str,
    tick_epoch_seconds: float,
) -> str:
    """Deterministic Idempotency-Key for an automated run.

    Keying on (schedule, scheduled tick) instead of a random UUID means
    retries within the same tick reuse the cached result instead of
    duplicating work, while distinct ticks get fresh validation that
    reflects current rules. This avoids the service's 409 conflict path,
    since identical keys are always paired with identical payloads.
    """

    return f"auto-{schedule_id}-{int(tick_epoch_seconds)}"
