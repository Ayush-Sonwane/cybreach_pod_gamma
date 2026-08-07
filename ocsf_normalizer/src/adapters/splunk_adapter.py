import time
from typing import Dict, Any

try:
    from src.models.ocsf_models import OCSFAuthenticationEvent, FieldProvenance
    from src.normalizer.complex_objects import (
        build_actor,
        build_device,
        build_endpoint,
        build_file,
        build_process,
        build_user,
    )
except (ModuleNotFoundError, ImportError):
    from src.models import OCSFAuthenticationEvent, FieldProvenance
    from src.normalizer import complex_objects

    build_actor = complex_objects.build_actor
    build_device = complex_objects.build_device
    build_endpoint = complex_objects.build_endpoint
    build_file = complex_objects.build_file
    build_process = complex_objects.build_process
    build_user = complex_objects.build_user


class SplunkAdapter:
    """
    Adapter to detect Splunk CIM payloads and convert them into standard OCSF Authentication Events.
    """

    @staticmethod
    def is_splunk_payload(payload: Dict[str, Any]) -> bool:
        """
        Schema Detection Logic: Identifies whether an incoming payload is a Splunk event/CIM format.
        """
        splunk_indicators = ["sourcetype", "eventtype", "_raw", "_time"]
        cim_auth_indicators = ["action", "user", "src", "dest"]

        has_splunk_keys = any(key in payload for key in splunk_indicators)
        has_cim_keys = any(key in payload for key in cim_auth_indicators)

        return has_splunk_keys or has_cim_keys

    @classmethod
    def map_to_ocsf(cls, payload: Dict[str, Any]) -> OCSFAuthenticationEvent:
        """
        Maps Splunk CIM fields directly into the standard OCSF Authentication Event schema.
        """
        provenance: Dict[str, FieldProvenance] = {}

        # 1. Map Action/Status -> Status ID (1 = Success, 2 = Failure, 99 = Unknown)
        raw_action = str(payload.get("action", "")).lower()
        raw_status = str(payload.get("status", "")).lower()
        # Prefer explicit status; fall back to action (e.g. "login" -> Unknown)
        combined = raw_status or raw_action
        if combined in ["success", "successful", "succeeded", "allowed"]:
            status_id = 1
        elif combined in ["failure", "failed", "error", "blocked"]:
            status_id = 2
        else:
            status_id = 99

        # 2. Extract User details (complex object)
        user = build_user(
            payload,
            {"name": ["user", "src_user"], "uid": ["user_id", "user_sid"]},
            provenance,
        )

        # 3. Extract Device/Endpoint details (complex objects)
        src_endpoint = build_endpoint(
            payload,
            {"ip": ["src_ip", "src"], "port": "src_port", "hostname": "src_host"},
            provenance,
        )
        dst_endpoint = build_endpoint(
            payload,
            {"ip": ["dest_ip", "dest"], "port": "dest_port", "hostname": "dest_host"},
            provenance,
        )

        # 4. Build device + actor from CIM fields
        device = build_device(
            payload,
            {"ip": ["src_ip", "src"], "hostname": "host", "name": "device_name"},
            provenance,
        )
        actor = build_actor(
            payload,
            {"user": {"name": ["user", "src_user"]}, "type_id": "actor_type_id"},
            provenance,
        )

        # 5. Extract process/file if present
        process = build_process(
            payload,
            {
                "pid": "process_id",
                "name": "process_name",
                "path": "process_path",
                "cmd_line": "cmd_line",
            },
            provenance,
        )
        file = build_file(
            payload,
            {"name": "file_name", "path": "file_path", "size": "file_size"},
            provenance,
        )

        # 6. Construct Normalized OCSF Object
        return OCSFAuthenticationEvent(
            activity_id=1,        # 1 = Logon in OCSF Authentication
            category_uid=3,       # 3 = Identity & Access Management
            class_uid=3002,       # 3002 = Authentication
            severity_id=1,        # 1 = Informational / Low
            status_id=status_id,
            time=int(time.time() * 1000),
            user=user,
            src_endpoint=src_endpoint,
            dst_endpoint=dst_endpoint,
            device=device,
            actor=actor,
            process=process,
            file=file,
            provenance=provenance,
        )

    def normalize(self, payload: Dict[str, Any]) -> OCSFAuthenticationEvent:
        """
        Standard normalizer interface wrapper.
        """
        return self.map_to_ocsf(payload)

