# src/adapters/qradar_adapter.py
from typing import Dict, Any
from datetime import datetime, timezone
from src.adapters.base_adapter import BaseAdapter
from src.models.ocsf_models import OCSFAuthenticationEvent, FieldProvenance


class QRadarAdapter(BaseAdapter):
    """Converts IBM QRadar (AQL Schema) raw logs to canonical OCSF v1.2+."""

    @property
    def vendor_name(self) -> str:
        return "IBM QRadar"

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

        # 1. Map Severity (QRadar Magnitude 1-10 -> OCSF 1-5)
        raw_mag = extract_field("magnitude", fallback_key="severity", default=1)
        try:
            mag_val = int(raw_mag)
        except (ValueError, TypeError):
            mag_val = 1
        severity_id = self._map_severity(mag_val)

        # 2. Activity & Status
        raw_action = str(extract_field("action", default="")).lower()
        raw_status = str(extract_field("status", default="")).lower()

        status_id = 1 if raw_status in ["success", "succeeded"] else (2 if raw_status in ["failure", "failed"] else 99)
        activity_id = 2 if "logout" in raw_action else 1

        # 3. Timestamp (Epoch Milliseconds)
        fallback_time = int(datetime.now(timezone.utc).timestamp() * 1000)
        raw_time = extract_field("starttime", fallback_key="devicetime", default=fallback_time)

        # 4. Extract Endpoints & User
        src_ip = extract_field("sourceip")
        src_port = extract_field("sourceport")
        dst_ip = extract_field("destinationip")
        dst_port = extract_field("destinationport")
        username = extract_field("username", fallback_key="identityusername")

        src_ep = {}
        if src_ip:
            src_ep["ip"] = src_ip
            if src_port is not None:
                try:
                    src_ep["port"] = int(src_port)
                except (ValueError, TypeError):
                    pass

        dst_ep = {}
        if dst_ip:
            dst_ep["ip"] = dst_ip
            if dst_port is not None:
                try:
                    dst_ep["port"] = int(dst_port)
                except (ValueError, TypeError):
                    pass

        return OCSFAuthenticationEvent(
            class_uid=3001,
            category_uid=3,
            activity_id=activity_id,
            severity_id=severity_id,
            status_id=status_id,
            time=int(raw_time),
            user={"name": username} if username else {},
            src_endpoint=src_ep,
            dst_endpoint=dst_ep,
            provenance=provenance
        )

    def _map_severity(self, mag: int) -> int:
        if mag <= 2:
            return 1
        if mag <= 4:
            return 2
        if mag <= 6:
            return 3
        if mag <= 8:
            return 4
        return 5