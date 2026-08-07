# src/adapters/qradar_adapter.py
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

        # 4. Extract Endpoints & User (complex objects)
        user = build_user(
            raw_event,
            {"name": ["username", "identityusername"], "uid": "useruid"},
            provenance,
        )
        src_endpoint = build_endpoint(
            raw_event,
            {"ip": "sourceip", "port": "sourceport"},
            provenance,
        )
        dst_endpoint = build_endpoint(
            raw_event,
            {"ip": "destinationip", "port": "destinationport"},
            provenance,
        )

        # 5. Device + Actor
        device = build_device(
            raw_event,
            {"ip": ["deviceip", "sourceip"], "name": "devicename", "type_id": "devicetype"},
            provenance,
        )
        actor = build_actor(
            raw_event,
            {"user": {"name": ["username", "identityusername"]}, "type_id": "actortypeid"},
            provenance,
        )

        # 6. Process + File (if present in AQL event)
        process = build_process(
            raw_event,
            {"pid": "processid", "name": "processname", "path": "processpath"},
            provenance,
        )
        file = build_file(
            raw_event,
            {"name": "filename", "path": "filepath", "size": "filesize"},
            provenance,
        )

        return OCSFAuthenticationEvent(
            class_uid=3001,
            category_uid=3,
            activity_id=activity_id,
            severity_id=severity_id,
            status_id=status_id,
            time=int(raw_time),
            user=user,
            src_endpoint=src_endpoint,
            dst_endpoint=dst_endpoint,
            device=device,
            actor=actor,
            process=process,
            file=file,
            provenance=provenance,
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

