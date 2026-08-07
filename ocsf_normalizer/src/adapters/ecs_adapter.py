import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

try:
    from src.models.ocsf_models import OCSFAuthenticationEvent
except (ModuleNotFoundError, ImportError):
    from src.models import OCSFAuthenticationEvent

logger = logging.getLogger("ocsf_normalizer")


class ECSAdapter:
    """
    Adapter to normalize Elastic Security logs (ECS schema) 
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
            logger.warning(f"Failed to parse ECS timestamp '{timestamp_str}': {e}")
            return int(datetime.now(timezone.utc).timestamp() * 1000)

    def normalize(self, raw_event: Dict[str, Any]) -> OCSFAuthenticationEvent:
        """
        Transforms ECS Authentication -> OCSF Authentication Event
        """
        user = raw_event.get("user", {}) if isinstance(raw_event.get("user"), dict) else {}
        source = raw_event.get("source", {}) if isinstance(raw_event.get("source"), dict) else {}
        event = raw_event.get("event", {}) if isinstance(raw_event.get("event"), dict) else {}

        username = user.get("name") or raw_event.get("user.name") or "Unknown"
        src_ip = source.get("ip") or raw_event.get("source.ip")
        outcome = event.get("outcome") or raw_event.get("event.outcome", "unknown")

        status_id = 1 if outcome == "success" else (2 if outcome == "failure" else 99)
        time_val = self._to_epoch_ms(raw_event.get("@timestamp"))

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