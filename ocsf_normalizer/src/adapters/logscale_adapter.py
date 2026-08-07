# src/adapters/logscale_adapter.py
from typing import Dict, Any
from datetime import datetime, timezone
from src.adapters.base_adapter import BaseAdapter
from src.models.ocsf_models import OCSFAuthenticationEvent, FieldProvenance
from src.normalizer.complex_objects import (
    build_actor,
    build_device,
    build_endpoint,
    build_file,
    build_process,
    build_user,
)


class LogScaleAdapter(BaseAdapter):
    """Converts CrowdStrike LogScale (LQL Schema) raw logs to canonical OCSF v1.2+."""

    @property
    def vendor_name(self) -> str:
        return "CrowdStrike LogScale"

    def normalize(self, raw_event: Dict[str, Any]) -> OCSFAuthenticationEvent:
        provenance: Dict[str, FieldProvenance] = {}

        def extract_field(primary_key: str, fallback_key: str = None, default: Any = None) -> Any:
            """Extracts values from primary or fallback keys while recording field provenance."""
            if primary_key in raw_event and raw_event[primary_key] is not None:
                val = raw_event[primary_key]
                provenance[primary_key] = FieldProvenance(original_field=primary_key, original_value=val)
                return val
            elif fallback_key and fallback_key in raw_event and raw_event[fallback_key] is not None:
                val = raw_event[fallback_key]
                provenance[fallback_key] = FieldProvenance(original_field=fallback_key, original_value=val)
                return val
            return default

        # 1. Parse Timestamp (@timestamp)
        raw_ts = extract_field("@timestamp")
        epoch_ms = self._parse_timestamp(raw_ts)

        # 2. Map Severity (Text loglevel -> OCSF 1-5)
        raw_level = str(extract_field("loglevel", fallback_key="severity", default="info")).lower()
        severity_id = self._map_severity(raw_level)

        # 3. Activity & Status
        raw_event_type = str(extract_field("event_type", fallback_key="action", default="")).lower()
        raw_status = str(extract_field("status", fallback_key="outcome", default="")).lower()

        status_id = 1 if raw_status in ["success", "successful"] else (2 if raw_status in ["failure", "failed"] else 99)
        activity_id = 2 if "logout" in raw_event_type else 1

        # 4. Extract Endpoints & User (complex objects)
        user = build_user(
            raw_event,
            {"name": ["user", "user_name"], "uid": "user_uid", "domain": "user_domain"},
            provenance,
        )
        src_endpoint = build_endpoint(
            raw_event,
            {"ip": ["aip", "src_ip"], "port": "src_port", "hostname": "src_hostname"},
            provenance,
        )
        dst_endpoint = build_endpoint(
            raw_event,
            {"ip": ["endpoint_ip", "dst_ip"], "port": "dst_port", "hostname": "dst_hostname"},
            provenance,
        )

        # 5. Device + Actor
        device = build_device(
            raw_event,
            {"ip": ["endpoint_ip", "aip"], "name": "device_name", "hostname": "device_hostname"},
            provenance,
        )
        actor = build_actor(
            raw_event,
            {"user": {"name": ["user", "user_name"]}, "type_id": "actor_type_id"},
            provenance,
        )

        # 6. Process + File (CrowdStrike Falcon ProcessRollup conventions)
        process = build_process(
            raw_event,
            {
                "pid": ["pid", "ProcessId"],
                "name": ["process_name", "ProcessName"],
                "path": ["process_path", "ImageFileName"],
                "cmd_line": "process_cmd_line",
            },
            provenance,
        )
        file = build_file(
            raw_event,
            {
                "name": "file_name",
                "path": ["file_path", "ImageFileName"],
                "size": "file_size",
                "hashes": {"sha256": "file_sha256", "md5": "file_md5"},
            },
            provenance,
        )

        return OCSFAuthenticationEvent(
            class_uid=3001,
            category_uid=3,
            activity_id=activity_id,
            severity_id=severity_id,
            status_id=status_id,
            time=epoch_ms,
            user=user,
            src_endpoint=src_endpoint,
            dst_endpoint=dst_endpoint,
            device=device,
            actor=actor,
            process=process,
            file=file,
            provenance=provenance,
        )

    def _parse_timestamp(self, ts: Any) -> int:
        if isinstance(ts, (int, float)):
            return int(ts)
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                return int(dt.timestamp() * 1000)
            except ValueError:
                pass
        return int(datetime.now(timezone.utc).timestamp() * 1000)

    def _map_severity(self, level: str) -> int:
        mapping = {
            "debug": 1, "info": 1, "informational": 1,
            "warn": 2, "warning": 2,
            "error": 3,
            "high": 4,
            "critical": 5, "fatal": 5
        }
        return mapping.get(level, 99)

