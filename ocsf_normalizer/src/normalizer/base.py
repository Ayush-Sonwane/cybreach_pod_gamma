# normalizer/base.py
from typing import Dict, Any, Optional

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


class BaseNormalizer:
    """
    Core Normalizer Engine (Service 3.5)
    
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