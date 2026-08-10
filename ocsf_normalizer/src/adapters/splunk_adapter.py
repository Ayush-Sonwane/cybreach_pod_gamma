# src/adapters/splunk_adapter.py
from datetime import datetime
from typing import Dict, Any

class SplunkAdapter:
    """Adapter to map Splunk CIM events to OCSF Schema (Class UID: 3002)."""

    @staticmethod
    def normalize(raw_event: Dict[str, Any]) -> Dict[str, Any]:
        provenance = []

        # 1. Parse Event Time (Fixes Issue #5)
        raw_time = raw_event.get("_time")
        if raw_time is not None:
            try:
                event_time = datetime.fromtimestamp(float(raw_time)).isoformat() + "Z"
            except (ValueError, TypeError):
                event_time = datetime.utcnow().isoformat() + "Z"
            provenance.append({"ocsf_field": "time", "raw_field": "_time"})
        else:
            event_time = datetime.utcnow().isoformat() + "Z"

        # 2. Map Severity (Fixes Issue #7)
        raw_sev = str(raw_event.get("vendor_severity", "")).lower()
        sev_map = {"informational": 1, "low": 1, "medium": 2, "high": 3, "critical": 4}
        severity_id = sev_map.get(raw_sev, 1)
        if "vendor_severity" in raw_event:
            provenance.append({"ocsf_field": "severity_id", "raw_field": "vendor_severity"})

        # 3. Source Endpoint
        src_endpoint = {}
        if "src_ip" in raw_event or "src" in raw_event:
            src_ip = raw_event.get("src_ip") or raw_event.get("src")
            src_endpoint["ip"] = src_ip
            provenance.append({"ocsf_field": "src_endpoint.ip", "raw_field": "src_ip" if "src_ip" in raw_event else "src"})

        # 4. Destination Endpoint (Fixes Issue #8)
        dst_endpoint = {}
        if "dest_ip" in raw_event or "dest" in raw_event:
            dst_ip = raw_event.get("dest_ip") or raw_event.get("dest")
            dst_endpoint["ip"] = dst_ip
            provenance.append({"ocsf_field": "dst_endpoint.ip", "raw_field": "dest_ip" if "dest_ip" in raw_event else "dest"})

        # Build Normalized OCSF Record (Class UID 3002 - Fixes Issue #10)
        normalized = {
            "class_uid": 3002,
            "category_uid": 3,
            "activity_id": 1,
            "time": event_time,
            "severity_id": severity_id,
            "metadata": {
                "version": "1.1.0",
                "product": {"name": "Splunk Enterprise", "vendor_name": "Splunk"},
                "provenance": provenance  # Fixes Issue #9
            }
        }

        if src_endpoint:
            normalized["src_endpoint"] = src_endpoint
        if dst_endpoint:
            normalized["dst_endpoint"] = dst_endpoint
        if "user" in raw_event:
            normalized["actor"] = {"user": {"name": raw_event["user"]}}
            provenance.append({"ocsf_field": "actor.user.name", "raw_field": "user"})

        return normalized