# src/adapters/ecs_adapter.py
from datetime import datetime, timezone
from typing import Dict, Any

class ECSAdapter:
    """Adapter to map Elastic ECS events to OCSF Schema (Class UID: 3002)."""

    @staticmethod
    def _to_epoch_ms(raw_time) -> int:
        """Converts ECS '@timestamp' (ISO string) to epoch ms."""
        if raw_time is None:
            return int(datetime.now(timezone.utc).timestamp() * 1000)
        if isinstance(raw_time, (int, float)):
            return int(raw_time) if raw_time > 10**12 else int(raw_time * 1000)
        try:
            dt = datetime.fromisoformat(str(raw_time).replace("Z", "+00:00"))
            return int(dt.timestamp() * 1000)
        except ValueError:
            return int(datetime.now(timezone.utc).timestamp() * 1000)

    @staticmethod
    def normalize(raw_event: Dict[str, Any]) -> Dict[str, Any]:
        provenance = []

        # Helper to safely fetch flat or nested keys
        def get_field(key_path: str, default=None):
            parts = key_path.split(".")
            curr = raw_event
            for p in parts:
                if isinstance(curr, dict) and p in curr:
                    curr = curr[p]
                else:
                    return raw_event.get(key_path, default)
            return curr

        # 1. Event Time -> OCSF epoch ms
        event_time = ECSAdapter._to_epoch_ms(get_field("@timestamp"))
        provenance.append({"ocsf_field": "time", "raw_field": "@timestamp"})

        # 2. Map Severity: ECS 0-100 -> OCSF 1-5
        raw_sev = get_field("event.severity")
        try:
            sev = int(raw_sev)
            severity_id = min(5, max(1, 1 + sev // 20))
        except (ValueError, TypeError):
            severity_id = 1
        provenance.append({"ocsf_field": "severity_id", "raw_field": "event.severity"})

        # 3. Status Mapping (event.outcome -> 1/2/99)
        raw_outcome = str(get_field("event.outcome", "")).lower()
        status_id = 1 if raw_outcome in ["success", "succeeded", "allowed"] else (
            2 if raw_outcome in ["failure", "failed", "blocked", "denied"] else 99)
        provenance.append({"ocsf_field": "status_id", "raw_field": "event.outcome"})

        # 4. Source & Destination Endpoints
        src_ip = get_field("source.ip")
        dst_ip = get_field("destination.ip")

        src_endpoint = {"ip": src_ip} if src_ip else {}
        if src_ip:
            provenance.append({"ocsf_field": "src_endpoint.ip", "raw_field": "source.ip"})

        dst_endpoint = {"ip": dst_ip} if dst_ip else {}
        if dst_ip:
            provenance.append({"ocsf_field": "dst_endpoint.ip", "raw_field": "destination.ip"})

        # Build Normalized Record
        normalized = {
            "class_uid": 3002,
            "category_uid": 3,
            "activity_id": 1,
            "time": event_time,
            "severity_id": severity_id,
            "status_id": status_id,
            "metadata": {
                "version": "1.1.0",
                "product": {"name": "Elasticsearch", "vendor_name": "Elastic"},
                "provenance": provenance
            }
        }

        if src_endpoint:
            normalized["src_endpoint"] = src_endpoint
        if dst_endpoint:
            normalized["dst_endpoint"] = dst_endpoint

        user_name = get_field("user.name")
        if user_name:
            normalized["actor"] = {"user": {"name": user_name}}
            provenance.append({"ocsf_field": "actor.user.name", "raw_field": "user.name"})

        return normalized
