import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

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

logger = logging.getLogger("ocsf_normalizer")


class ASIMAdapter:
    """
    Adapter to normalize Microsoft Sentinel logs (ASIM schema) 
    into the standard OCSF format (v1.1.0+).
    """

    @staticmethod
    def _to_epoch_ms(timestamp_str: Optional[str]) -> int:
        """Converts ISO 8601 string to Unix Epoch Milliseconds."""
        if not timestamp_str:
            return int(datetime.now(timezone.utc).timestamp() * 1000)
        try:
            ts = str(timestamp_str).replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts)
            return int(dt.timestamp() * 1000)
        except Exception as e:
            logger.warning(f"Failed to parse ASIM timestamp '{timestamp_str}': {e}")
            return int(datetime.now(timezone.utc).timestamp() * 1000)

    def normalize(self, raw_event: Dict[str, Any]) -> OCSFAuthenticationEvent:
        """
        Transforms ASIM Authentication -> OCSF Authentication Event
        """
        provenance: Dict[str, FieldProvenance] = {}

        event_result = raw_event.get("EventResult", "Unknown")
        status_id = 1 if event_result == "Success" else (2 if event_result == "Failure" else 99)

        time_val = self._to_epoch_ms(raw_event.get("EventStartTime") or raw_event.get("TimeGenerated"))

        # Complex User object (ASIM Target* conventions)
        user = build_user(
            raw_event,
            {
                "name": ["TargetUsername", "Username"],
                "uid": ["TargetUserId", "TargetUserSid"],
                "domain": ["TargetDomainName", "DomainName"],
            },
            provenance,
        )

        # Complex Endpoint objects (ASIM Src* / Dst* conventions)
        src_endpoint = build_endpoint(
            raw_event,
            {
                "ip": ["SrcIpAddr", "SrcIP"],
                "port": "SrcPortNumber",
                "hostname": "SrcHostname",
                "mac": "SrcMacAddr",
                "name": "SrcDeviceName",
            },
            provenance,
        )
        dst_endpoint = build_endpoint(
            raw_event,
            {
                "ip": ["DstIpAddr", "TargetIpAddr", "DstIP"],
                "port": "DstPortNumber",
                "hostname": "DstHostname",
                "mac": "DstMacAddr",
                "name": "DstDeviceName",
            },
            provenance,
        )

        # Device object from ASIM Device* fields
        device = build_device(
            raw_event,
            {
                "name": ["EventProduct", "DeviceProduct"],
                "uid": "EventProductId",
                "hostname": "Hostname",
                "ip": "DstIpAddr",
            },
            provenance,
        )

        # Actor (subject / initiator)
        actor = build_actor(
            raw_event,
            {
                "user": {"name": ["ActorUsername", "Username"], "uid": "ActorUserId"},
                "type_id": "ActorTypeId",
            },
            provenance,
        )

        # Process object from ASIM ActingProcess* fields
        process = build_process(
            raw_event,
            {
                "pid": "ActingProcessId",
                "name": ["ActingProcessName", "ProcessName"],
                "path": "ActingProcessPath",
                "cmd_line": "ActingProcessCommandLine",
            },
            provenance,
        )

        # File object from ASIM TargetFile* / File* fields
        file = build_file(
            raw_event,
            {
                "name": ["TargetFileName", "FileName"],
                "path": "FilePath",
                "size": "FileSize",
                "hashes": {
                    "sha256": ["FileHash", "TargetFileSHA256"],
                    "md5": "TargetFileMD5",
                },
            },
            provenance,
        )

        return OCSFAuthenticationEvent(
            class_uid=3002,
            category_uid=3,
            activity_id=1,
            severity_id=1,
            status_id=status_id,
            time=time_val,
            user=user,
            src_endpoint=src_endpoint,
            dst_endpoint=dst_endpoint,
            device=device,
            actor=actor,
            process=process,
            file=file,
            provenance=provenance,
        )

