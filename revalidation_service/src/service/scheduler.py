"""
Re-validation scheduler engine (#4) and runner.

Contract: see revalidation_service/SCHEDULER_CONTRACT.md (authoritative).

The scheduler owns WHEN to run. RevalidationRunner owns WHAT to run.

Frozen behaviors implemented here:
  - clause 1: run_once(trigger) is the single execution path for scheduled AND manual runs
  - clause 2: fixed-delay loop; the interval timer starts after the previous run finishes
  - clause 3: manual run while active raises SchedulerBusyError (mapped to HTTP 409)
  - clause 4: a scheduled tick during an active run records a skipped_tick row
  - clause 5: successful AND failed runs are recorded as data in scheduler_history
  - clause 6: duration from a monotonic clock; timestamps are UTC wall-clock ISO
  - clause 7: enabled=false gates automatic scheduling only; run_once("manual") always works
  - clause 8: invalid configuration fails fast at startup (src/core/config.py)
  - clause 9: v1 assumes exactly one scheduler-owning process/worker
"""

import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

TRIGGER_SCHEDULED = "scheduled"
TRIGGER_MANUAL = "manual"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"


class SchedulerBusyError(RuntimeError):
    """Raised when a manual run is requested while another run is already active."""


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class RevalidationRunner:
    """Knows WHAT to revalidate.

    Re-validates every stored run's updated_event using the provided validator
    callable (the existing validate_ocsf_event logic). Per-event exceptions are
    isolated and counted as invalid events; they never abort the whole pass.
    """

    def __init__(self, repository, validator: Callable[[Dict[str, Any]], Any]) -> None:
        self._repository = repository
        self._validator = validator

    def run(self) -> Dict[str, int]:
        checked = valid = invalid = 0
        for stored in self._repository.list_runs():
            checked += 1
            try:
                outcome = self._validator(stored["updated_event"])
                ok = bool(outcome[0])
            except Exception:
                ok = False
            if ok:
                valid += 1
            else:
                invalid += 1
        return {
            "checked_count": checked,
            "valid_count": valid,
            "invalid_count": invalid,
        }


class RevalidationScheduler:
    """Knows WHEN to run.

    One background thread performs fixed-delay scheduling. All execution goes
    through run_once(trigger) behind a shared execution lock, so scheduled and
    manual runs can never overlap.
    """

    def __init__(
        self,
        settings,
        runner,
        repository,
        time_source: Callable[[], float] = time.perf_counter,
        wall_clock: Callable[[], str] = _utcnow_iso,
    ) -> None:
        self._settings = settings
        self._runner = runner
        self._repository = repository
        self._time_source = time_source
        self._wall_clock = wall_clock

        self._state_lock = threading.Lock()
        self._execution_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self._runs_started = 0
        self._skipped_ticks = 0
        self._last_run: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------ #
    # Introspection                                                      #
    # ------------------------------------------------------------------ #

    @property
    def settings(self):
        return self._settings

    def is_running(self) -> bool:
        with self._state_lock:
            return self._thread is not None and self._thread.is_alive()

    def counters(self) -> Dict[str, int]:
        with self._state_lock:
            return {
                "runs_started": self._runs_started,
                "skipped_ticks": self._skipped_ticks,
            }

    def last_run(self) -> Optional[Dict[str, Any]]:
        with self._state_lock:
            return dict(self._last_run) if self._last_run else None

    # ------------------------------------------------------------------ #
    # Lifecycle                                                          #
    # ------------------------------------------------------------------ #

    def start(self) -> bool:
        """Start the background scheduling thread.

        Returns False if it is already running (double-start guard).
        The first automatic run happens one full interval after startup
        (fixed-delay semantics, contract clause 2).
        """
        with self._state_lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._stop_event = threading.Event()
            thread = threading.Thread(
                target=self._loop,
                name="revalidation-scheduler",
                daemon=True,
            )
            self._thread = thread
        thread.start()
        return True

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the background thread to stop and wait for it to exit."""
        with self._state_lock:
            thread = self._thread
        if thread is None:
            return
        self._stop_event.set()
        thread.join(timeout=timeout)

    def _loop(self) -> None:
        stop_event = self._stop_event
        while not stop_event.is_set():
            try:
                self.run_once(TRIGGER_SCHEDULED)
            except Exception:
                # A tick must never kill the scheduling loop; failures that
                # escape run_once (e.g. history-write errors) are swallowed
                # here. Runner-level failures are already recorded as data.
                pass
            stop_event.wait(self._settings.interval_seconds)

    # ------------------------------------------------------------------ #
    # Single execution path                                              #
    # ------------------------------------------------------------------ #

    def run_once(self, trigger: str) -> Dict[str, Any]:
        """Execute exactly one re-validation pass.

        trigger: 'scheduled' or 'manual'. This is the ONLY execution path
        (contract clause 1). Returns the run snapshot dict. Runner failures do
        NOT raise: they are recorded as 'failed' history rows (clause 5).
        Raises SchedulerBusyError only when a MANUAL run collides with an
        active run (clause 3); scheduled ticks skip instead (clause 4).
        """
        if trigger not in (TRIGGER_SCHEDULED, TRIGGER_MANUAL):
            raise ValueError(
                f"Invalid trigger {trigger!r}: expected '{TRIGGER_SCHEDULED}' or '{TRIGGER_MANUAL}'"
            )

        if not self._execution_lock.acquire(blocking=False):
            if trigger == TRIGGER_MANUAL:
                raise SchedulerBusyError(
                    "A re-validation run is already in progress"
                )
            self._record_skipped_tick()
            return {
                "run_id": None,
                "trigger": TRIGGER_SCHEDULED,
                "status": "skipped",
            }

        try:
            return self._execute(trigger)
        finally:
            self._execution_lock.release()

    # ------------------------------------------------------------------ #
    # Internals                                                          #
    # ------------------------------------------------------------------ #

    def _execute(self, trigger: str) -> Dict[str, Any]:
        run_id = f"sched-{uuid.uuid4().hex}"
        started_at = self._wall_clock()
        started_counter = self._time_source()

        with self._state_lock:
            self._runs_started += 1

        self._repository.start_scheduler_history(
            run_id=run_id,
            trigger=trigger,
            started_at=started_at,
        )

        counts = {"checked_count": 0, "valid_count": 0, "invalid_count": 0}
        status = STATUS_COMPLETED
        error_text: Optional[str] = None
        try:
            counts = self._runner.run()
        except Exception as exc:  # failures are data, never raised outward
            status = STATUS_FAILED
            error_text = f"{type(exc).__name__}: {exc}"

        finished_counter = self._time_source()
        duration_ms = round((finished_counter - started_counter) * 1000.0, 3)
        finished_at = self._wall_clock()

        self._repository.finish_scheduler_history(
            run_id=run_id,
            status=status,
            finished_at=finished_at,
            checked_count=counts["checked_count"],
            valid_count=counts["valid_count"],
            invalid_count=counts["invalid_count"],
            duration_ms=duration_ms,
            error=error_text,
        )

        snapshot = {
            "run_id": run_id,
            "trigger": trigger,
            "status": status,
            "started_at": started_at,
            "finished_at": finished_at,
            **counts,
            "duration_ms": duration_ms,
            "error": error_text,
        }
        with self._state_lock:
            self._last_run = dict(snapshot)
        return snapshot

    def _record_skipped_tick(self) -> None:
        run_id = f"sched-{uuid.uuid4().hex}"
        now = self._wall_clock()
        try:
            self._repository.record_skipped_scheduler_tick(
                run_id=run_id,
                trigger="skipped_tick",
                timestamp=now,
            )
        except Exception:
            # Never let bookkeeping of a skipped tick break the caller.
            return
        with self._state_lock:
            self._skipped_ticks += 1
