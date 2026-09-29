"""
Normalization performance monitoring.

Thread-safe collection of throughput and processing-latency statistics for
the OCSF normalizer (single and batch normalization paths). Statistics are
derived from the API layer: latency is measured with a monotonic clock at the
handler boundary and every event is accounted exactly once.
"""

import math
import threading
import time
from collections import deque
from typing import Callable, Dict, List, Optional


class MetricsCollector:
    """
    Thread-safe collector for normalization throughput and latency.

    Records:
      - per-request (single event) latencies in milliseconds
      - per-batch durations in milliseconds and derived per-event latency
      - event counters (total / succeeded / failed)
      - batch counter
      - rolling throughput window (events/sec over the last ``window_seconds``)
        plus lifetime average throughput

    ``clock`` is injectable for deterministic window tests; it must be
    monotonic (``time.monotonic`` by default).
    """

    DEFAULT_WINDOW_SECONDS = 60.0

    def __init__(
        self,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        clock: Optional[Callable[[], float]] = None,
    ):
        self._window_seconds = float(window_seconds)
        self._clock = clock or time.monotonic

        self._lock = threading.Lock()
        self._started_at = self._clock()

        self._total_events = 0
        self._succeeded = 0
        self._failed = 0
        self._total_batches = 0

        self._single_latencies_ms: List[float] = []
        self._batch_durations_ms: List[float] = []
        self._batch_per_event_ms: List[float] = []

        # (timestamp, event_count) per recorded event; pruned in snapshot().
        self._events_window: deque = deque()

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_single(self, latency_ms: float, ok: bool) -> None:
        """
        Record one single-event normalization request.

        Args:
            latency_ms: handler wall-clock latency in milliseconds.
            ok: True when normalization succeeded, False on failure.
        """
        with self._lock:
            self._total_events += 1
            if ok:
                self._succeeded += 1
            else:
                self._failed += 1
            self._single_latencies_ms.append(float(latency_ms))
            self._events_window.append((self._clock(), 1))

    def record_batch(
        self,
        size: int,
        duration_ms: float,
        succeeded: int,
        failed: int,
    ) -> None:
        """
        Record one completed batch normalization request.

        The success/failure counts come straight from
        ``BaseNormalizer.process_batch`` and are recorded exactly once here.

        Args:
            size: total events in the batch.
            duration_ms: handler wall-clock latency in milliseconds.
            succeeded: events that normalized successfully.
            failed: events that failed normalization.
        """
        with self._lock:
            self._total_events += int(size)
            self._succeeded += int(succeeded)
            self._failed += int(failed)
            self._total_batches += 1
            self._batch_durations_ms.append(float(duration_ms))
            if size > 0:
                self._batch_per_event_ms.append(float(duration_ms) / float(size))
            self._events_window.append((self._clock(), int(size)))

    def record_batch_failure(self, size: int, duration_ms: float) -> None:
        """
        Record a batch request that failed at the handler level (no per-event
        results were produced). The attempted events are counted as failed
        exactly once so the batch is never double-accounted.
        """
        with self._lock:
            self._total_events += int(size)
            self._failed += int(size)
            self._total_batches += 1
            self._batch_durations_ms.append(float(duration_ms))
            self._events_window.append((self._clock(), int(size)))

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    @staticmethod
    def _percentile(sorted_values: List[float], percent: float) -> Optional[float]:
        """Nearest-rank percentile over an already-sorted list."""
        n = len(sorted_values)
        if n == 0:
            return None
        rank = max(1, int(math.ceil(percent / 100.0 * n)))
        return sorted_values[rank - 1]

    @staticmethod
    def _stats(values: List[float]) -> Optional[Dict[str, float]]:
        if not values:
            return None
        sorted_values = sorted(values)
        total = sum(sorted_values)
        return {
            "min": round(sorted_values[0], 3),
            "avg": round(total / len(sorted_values), 3),
            "max": round(sorted_values[-1], 3),
            "p95": round(float(MetricsCollector._percentile(sorted_values, 95)), 3),
        }

    # ------------------------------------------------------------------
    # Snapshot / reset
    # ------------------------------------------------------------------

    def snapshot(self) -> Dict[str, object]:
        """Return a JSON-ready snapshot of all collected metrics."""
        with self._lock:
            now = self._clock()
            cutoff = now - self._window_seconds
            while self._events_window and self._events_window[0][0] < cutoff:
                self._events_window.popleft()

            recent_events = sum(count for _, count in self._events_window)
            elapsed = max(now - self._started_at, 1e-9)

            window_throughput = recent_events / self._window_seconds
            lifetime_throughput = self._total_events / elapsed

            return {
                "uptime_seconds": round(elapsed, 3),
                "total_events": self._total_events,
                "succeeded": self._succeeded,
                "failed": self._failed,
                "total_batches": self._total_batches,
                "throughput_events_per_sec": {
                    "window_seconds": self._window_seconds,
                    "window": round(window_throughput, 3),
                    "lifetime": round(lifetime_throughput, 3),
                },
                "latency_ms": {
                    "single_event": self._stats(self._single_latencies_ms),
                    "batch_duration": self._stats(self._batch_durations_ms),
                    "per_event_in_batch": self._stats(self._batch_per_event_ms),
                },
            }

    def reset(self) -> None:
        """Clear all recorded metrics. The uptime clock keeps running."""
        with self._lock:
            self._total_events = 0
            self._succeeded = 0
            self._failed = 0
            self._total_batches = 0
            self._single_latencies_ms.clear()
            self._batch_durations_ms.clear()
            self._batch_per_event_ms.clear()
            self._events_window.clear()
