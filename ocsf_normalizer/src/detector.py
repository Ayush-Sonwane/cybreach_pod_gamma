from typing import Dict, Any, Optional, Tuple, Union
from src.adapters.asim_adapter import AsimAdapter
from src.adapters.ecs_adapter import EcsAdapter
from src.adapters.splunk_adapter import SplunkOCSFAdapter
from src.validator import OCSFValidator
from src.dlq import DeadLetterQueue

class SchemaDetector:
    """
    Inspects raw incoming payloads to detect vendor log formats
    and routes them to the appropriate OCSF Adapter.
    """

    @staticmethod
    def detect_schema(payload: Dict[str, Any]) -> Optional[str]:
        if SplunkOCSFAdapter.is_splunk_payload(payload):
            return "SPLUNK"

        asim_signatures = ["TimeGenerated", "SrcIpAddr", "DstIpAddr", "EventVendor", "EventProduct"]
        if any(key in payload for key in asim_signatures):
            return "ASIM"

        ecs_signatures = ["@timestamp", "observer", "network", "destination"]
        if any(key in payload for key in ecs_signatures):
            return "ECS"

        return None


class OCSFNormalizerPipeline:
    """
    Production entry point combining Auto-Detection, Normalization, 
    Validation, and Dead-Letter Queue (DLQ) routing.
    """

    def __init__(self):
        self.asim_adapter = AsimAdapter()
        self.ecs_adapter = EcsAdapter()
        self.splunk_adapter = SplunkOCSFAdapter()
        self.dlq = DeadLetterQueue()

    def process_event(self, raw_payload: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """
        Processes a single event cleanly.
        Returns: 
            ("SUCCESS", ocsf_payload) or ("DLQ", dlq_record)
        """
        # 1. Detect Schema
        detected_schema = SchemaDetector.detect_schema(raw_payload)

        if not detected_schema:
            dlq_record = self.dlq.push(
                raw_payload=raw_payload,
                reason="UNKNOWN_SCHEMA_FORMAT",
                errors=["Payload did not match any known signature (ASIM, ECS, SPLUNK)."]
            )
            return "DLQ", dlq_record

        # 2. Transform Payload
        try:
            if detected_schema == "SPLUNK":
                ocsf_model = self.splunk_adapter.map_to_ocsf(raw_payload)
                normalized_event = ocsf_model.model_dump()
            elif detected_schema == "ASIM":
                normalized_event = self.asim_adapter.transform_network_session(raw_payload)
            elif detected_schema == "ECS":
                normalized_event = self.ecs_adapter.transform_network_session(raw_payload)
        except Exception as e:
            dlq_record = self.dlq.push(
                raw_payload=raw_payload,
                reason="TRANSFORMATION_ERROR",
                errors=[str(e)]
            )
            return "DLQ", dlq_record

        # 3. Validate Normalized OCSF Output
        is_valid, errors = OCSFValidator.validate_event(normalized_event)

        if not is_valid:
            dlq_record = self.dlq.push(
                raw_payload=raw_payload,
                reason="SCHEMA_VALIDATION_FAILURE",
                errors=errors
            )
            return "DLQ", dlq_record

        # 4. Return Normalized OCSF
        return "SUCCESS", normalized_event