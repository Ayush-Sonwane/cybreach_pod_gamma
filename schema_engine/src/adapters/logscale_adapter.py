# src/adapters/logscale_adapter.py
from typing import Dict, Any
from datetime import datetime, timezone
from src.adapters.base_adapter import BaseAdapter
from src.models.ocsf_models import OCSFAuthenticationEvent, FieldProvenance


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

        # 4. Extract Endpoints & User
        src_ip = extract_field("aip", fallback_key="src_ip")
        dst_ip = extract_field("endpoint_ip", fallback_key="dst_ip")
        username = extract_field("user", fallback_key="user_name")

        return OCSFAuthenticationEvent(
            class_uid=3001,
            category_uid=3,
            activity_id=activity_id,
            severity_id=severity_id,
            status_id=status_id,
            time=epoch_ms,
            user={"name": username} if username else {},
            src_endpoint={"ip": src_ip} if src_ip else {},
            dst_endpoint={"ip": dst_ip} if dst_ip else {},
            provenance=provenance
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