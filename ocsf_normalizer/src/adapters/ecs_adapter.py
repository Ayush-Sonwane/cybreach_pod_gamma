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

    @staticmethod
    def _dot(raw: Dict[str, Any], dotted: str) -> Any:
        """Gets a value from a nested dict using dotted path, e.g. 'source.ip'."""
        value = raw.get(dotted)
        if value is not None:
            return value
        current = raw
        for part in dotted.split("."):
            if not isinstance(current, dict):
                return None
            current = current.get(part)
            if current is None:
                return None
        return current

    def normalize(self, raw_event: Dict[str, Any]) -> OCSFAuthenticationEvent:
        """
        Transforms ECS Authentication -> OCSF Authentication Event
        """
        provenance: Dict[str, FieldProvenance] = {}

        user_dict = raw_event.get("user", {}) if isinstance(raw_event.get("user"), dict) else {}
        source = raw_event.get("source", {}) if isinstance(raw_event.get("source"), dict) else {}
        destination = raw_event.get("destination", {}) if isinstance(raw_event.get("destination"), dict) else {}
        event = raw_event.get("event", {}) if isinstance(raw_event.get("event"), dict) else {}
        process_dict = raw_event.get("process", {}) if isinstance(raw_event.get("process"), dict) else {}
        file_dict = raw_event.get("file", {}) if isinstance(raw_event.get("file"), dict) else {}
        host_dict = raw_event.get("host", {}) if isinstance(raw_event.get("host"), dict) else {}

        username = user_dict.get("name") or self._dot(raw_event, "user.name") or "Unknown"
        outcome = event.get("outcome") or self._dot(raw_event, "event.outcome", ) or "unknown"

        status_id = 1 if outcome == "success" else (2 if outcome == "failure" else 99)
        time_val = self._to_epoch_ms(raw_event.get("@timestamp"))

        # Complex User object (ECS user.*)
        user = build_user(
            raw_event,
            {
                "name": lambda r: r.get("user", {}).get("name") if isinstance(r.get("user"), dict) else None,
                "uid": lambda r: r.get("user", {}).get("id") if isinstance(r.get("user"), dict) else None,
                "domain": lambda r: r.get("user", {}).get("domain") if isinstance(r.get("user"), dict) else None,
                "email_addr": lambda r: r.get("user", {}).get("email") if isinstance(r.get("user"), dict) else None,
            },
            provenance,
        )

        # Complex Endpoint objects (ECS source.* / destination.*)
        src_endpoint = build_endpoint(
            raw_event,
            {
                "ip": lambda r: self._dot(r, "source.ip"),
                "port": lambda r: self._dot(r, "source.port"),
                "mac": lambda r: self._dot(r, "source.mac"),
                "domain": lambda r: self._dot(r, "source.domain"),
            },
            provenance,
        )
        dst_endpoint = build_endpoint(
            raw_event,
            {
                "ip": lambda r: self._dot(r, "destination.ip"),
                "port": lambda r: self._dot(r, "destination.port"),
                "mac": lambda r: self._dot(r, "destination.mac"),
                "domain": lambda r: self._dot(r, "destination.domain"),
            },
            provenance,
        )

        # Device object (ECS host.*)
        device = build_device(
            raw_event,
            {
                "name": lambda r: r.get("host", {}).get("name") if isinstance(r.get("host"), dict) else None,
                "hostname": lambda r: r.get("host", {}).get("hostname") if isinstance(r.get("host"), dict) else None,
                "ip": lambda r: (r.get("host", {}).get("ip") or [None])[0] if isinstance(r.get("host", {}).get("ip"), list) else self._dot(r, "host.ip"),
            },
            provenance,
        )

        # Actor (ECS actor / user)
        actor = build_actor(
            raw_event,
            {
                "user": {
                    "name": lambda r: r.get("user", {}).get("name") if isinstance(r.get("user"), dict) else None,
                    "uid": lambda r: r.get("user", {}).get("id") if isinstance(r.get("user"), dict) else None,
                },
            },
            provenance,
        )

        # Process object (ECS process.*)
        process = build_process(
            raw_event,
            {
                "pid": lambda r: r.get("process", {}).get("pid") if isinstance(r.get("process"), dict) else None,
                "name": lambda r: r.get("process", {}).get("name") if isinstance(r.get("process"), dict) else None,
                "path": lambda r: r.get("process", {}).get("executable") if isinstance(r.get("process"), dict) else None,
                "cmd_line": lambda r: r.get("process", {}).get("command_line") if isinstance(r.get("process"), dict) else None,
            },
            provenance,
        )

        # File object (ECS file.*)
        file = build_file(
            raw_event,
            {
                "name": lambda r: r.get("file", {}).get("name") if isinstance(r.get("file"), dict) else None,
                "path": lambda r: r.get("file", {}).get("path") if isinstance(r.get("file"), dict) else None,
                "size": lambda r: r.get("file", {}).get("size") if isinstance(r.get("file"), dict) else None,
                "hashes": {
                    "sha256": lambda r: r.get("file", {}).get("hash") if isinstance(r.get("file"), dict) else None,
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

