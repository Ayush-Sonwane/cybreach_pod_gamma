# normalizer/base.py
import os
from concurrent.futures import ProcessPoolExecutor
from typing import Dict, Any, List, Optional

# Import schema detector (adjust path if detector.py lives elsewhere, e.g., src.detector)
from src.detector import SchemaDetector

# Import all 5 SIEM Adapters
from src.adapters.splunk_adapter import SplunkAdapter
from src.adapters.asim_adapter import ASIMAdapter
from src.adapters.ecs_adapter import ECSAdapter
from src.adapters.qradar_adapter import QRadarAdapter
from src.adapters.logscale_adapter import LogScaleAdapter
from src.adapters.webhook_adapter import WebhookAdapter

# Import canonical OCSF model
from src.models.ocsf_models import OCSFAuthenticationEvent

# Module-level state for ProcessPoolExecutor workers.
# Worker functions MUST be top-level (picklable) so they survive Windows "spawn".
_WORKER_NORMALIZER = None


def _worker_init():
    """Initializer for each process-pool worker: build one normalizer per process."""
    global _WORKER_NORMALIZER
    _WORKER_NORMALIZER = BaseNormalizer()


def _normalize_single(raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Worker entry point: normalize a single raw vendor event inside a worker
    process. Never raises -- failures are captured per-event so one bad event
    cannot abort the whole batch. 
    Note: a crashed worker is replaced automatically by ProcessPoolExecutor on the next submission.
    """
    global _WORKER_NORMALIZER
    if _WORKER_NORMALIZER is None:
        _worker_init()
    try:
        event = _WORKER_NORMALIZER.process_log(raw_payload)
        if hasattr(event, "model_dump"):
            event = event.model_dump()
        return {"success": True, "event": event}
    except Exception as e:
        return {"success": False, "error": str(e)}


class BaseNormalizer:
    """
    Core Normalizer Engine
    
    Executes the 3-Stage Pipeline:
      Stage 1: Schema Auto-Detection
      Stage 2: Vendor Field Mapping
      Stage 3: OCSF v1.2+ Validation & Field-Level Provenance Tracking
    """

    def __init__(self):
        # Register adapter instances for all 5 vendors
        self.adapters = {
            "splunk": SplunkAdapter(),
            "sentinel": ASIMAdapter(),
            "ecs": ECSAdapter(),
            "qradar": QRadarAdapter(),
            "logscale": LogScaleAdapter(),
            "webhook": WebhookAdapter(),
        }

    def process_log(self, raw_payload: Dict[str, Any]) -> OCSFAuthenticationEvent:
        """
        Main entry point: Converts any incoming raw vendor log into canonical OCSF format.
        """
        # 1. Stage 1: Auto-detect vendor schema
        vendor_type = SchemaDetector.detect_vendor(raw_payload)

        adapter = self.adapters.get(vendor_type)
        if not adapter:
            raise ValueError(
                f"Normalization Failed: Unable to detect vendor schema or unsupported format for payload: {raw_payload}"
            )

        # 2 & 3. Stage 2 & 3: Map fields, capture provenance, and return validated OCSF event
        ocsf_event = adapter.normalize(raw_payload)
        return ocsf_event

    def process_batch(
        self,
        raw_events: List[Dict[str, Any]],
        executor: ProcessPoolExecutor,
        chunksize: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Batch Normalization Mode (high-throughput, parallel event processing).

        Normalizes many raw vendor events in parallel using the injected
        ``executor``, while preserving input order (``results[i]`` always
        maps back to ``raw_events[i]``).

        The caller owns the executor lifecycle: the shared pool is created
        once at application startup (see ``main.py`` lifespan) and passed in
        here. This method never constructs or tears down a pool itself.

        Per-event isolation: every event is normalized independently, so a
        single malformed/unsupported payload is reported as a failure entry
        instead of aborting the entire batch.

        Args:
            raw_events: list of raw vendor log event dictionaries.
            executor: an already-running ProcessPoolExecutor to submit work to.
            chunksize: number of events dispatched to a worker per task
                       (default: balanced split across pool workers).

        Returns:
            {
                "total": int,
                "success_count": int,
                "failure_count": int,
                "results": [
                    {"success": True, "event": { ...OCSF event dict... }},
                    {"success": False, "error": "reason"},
                    ...
                ]
            }
        """
        total = len(raw_events)
        if total == 0:
            return {
                "total": 0,
                "success_count": 0,
                "failure_count": 0,
                "results": [],
            }

        if chunksize is None:
            workers = getattr(executor, "_max_workers", os.cpu_count() or 1)
            chunksize = max(1, (total + workers - 1) // workers)

        # executor.map() yields results in input order; per-event failures are
        # captured by _normalize_single so a bad event never raises here.
        results = list(executor.map(_normalize_single, raw_events, chunksize=chunksize))

        success_count = sum(1 for r in results if r.get("success"))
        return {
            "total": total,
            "success_count": success_count,
            "failure_count": total - success_count,
            "results": results,
        }