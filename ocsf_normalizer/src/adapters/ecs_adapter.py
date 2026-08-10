# src/adapters/ecs_adapter.py
from datetime import datetime
from typing import Dict, Any

class ECSAdapter:
    """Adapter to map Elastic ECS events to OCSF Schema (Class UID: 3002)."""

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

        # 1. Event Time
        event_time = get_field("@timestamp", datetime.utcnow().isoformat() + "Z")
        provenance.append({"ocsf_field": "time", "raw_field": "@timestamp"})

        # 2. Map Severity (Fixes Issue #7)
        raw_sev = get_field("event.severity", 1)
        try:
            severity_id = int(raw_sev)
            if severity_id not in [1, 2, 3, 4]:
                severity_id = 1
        except (ValueError, TypeError):
            severity_id = 1
        provenance.append({"ocsf_field": "severity_id", "raw_field": "event.severity"})

        # 3. Source & Destination Endpoints (Fixes Issue #8 & Issue #6)
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
            "metadata": {
                "version": "1.1.0",
                "product": {"name": "Elasticsearch", "vendor_name": "Elastic"},
                "provenance": provenance  # Fixes Issue #9
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