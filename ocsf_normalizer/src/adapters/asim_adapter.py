import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

try:
    from src.models.ocsf_models import OCSFAuthenticationEvent
except (ModuleNotFoundError, ImportError):
    from src.models import OCSFAuthenticationEvent

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
        event_result = raw_event.get("EventResult", "Unknown")
        status_id = 1 if event_result == "Success" else (2 if event_result == "Failure" else 99)

        time_val = self._to_epoch_ms(raw_event.get("EventStartTime") or raw_event.get("TimeGenerated"))
        username = raw_event.get("TargetUsername") or "Unknown"
        src_ip = raw_event.get("SrcIpAddr")

        return OCSFAuthenticationEvent(
            class_uid=3002,
            category_uid=3,
            activity_id=1,
            severity_id=1,
            status_id=status_id,
            time=time_val,
            user={"name": username},
            src_endpoint={"ip": src_ip} if src_ip else {}
        )