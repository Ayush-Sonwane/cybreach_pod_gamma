# src/adapters/asim_adapter.py
from datetime import datetime
from typing import Dict, Any

class ASIMAdapter:
    """Adapter to map MS Sentinel ASIM events to OCSF Schema (Class UID: 3002)."""

    @staticmethod
    def normalize(raw_event: Dict[str, Any]) -> Dict[str, Any]:
        provenance = []

        # 1. Event Time
        time_gen = raw_event.get("TimeGenerated")
        event_time = time_gen if time_gen else datetime.utcnow().isoformat() + "Z"
        if "TimeGenerated" in raw_event:
            provenance.append({"ocsf_field": "time", "raw_field": "TimeGenerated"})

        # 2. Map Severity (Fixes Issue #7)
        raw_sev = str(raw_event.get("SeverityLevel", "")).lower()
        sev_map = {"informational": 1, "low": 1, "medium": 2, "high": 3, "critical": 4}
        severity_id = sev_map.get(raw_sev, 1)
        if "SeverityLevel" in raw_event:
            provenance.append({"ocsf_field": "severity_id", "raw_field": "SeverityLevel"})

        # 3. Source & Destination Endpoints (Fixes Issue #8)
        src_endpoint = {}
        if "SrcIpAddr" in raw_event:
            src_endpoint["ip"] = raw_event["SrcIpAddr"]
            provenance.append({"ocsf_field": "src_endpoint.ip", "raw_field": "SrcIpAddr"})

        dst_endpoint = {}
        if "DstIpAddr" in raw_event:
            dst_endpoint["ip"] = raw_event["DstIpAddr"]
            provenance.append({"ocsf_field": "dst_endpoint.ip", "raw_field": "DstIpAddr"})

        # Build Normalized Record
        normalized = {
            "class_uid": 3002,
            "category_uid": 3,
            "activity_id": 1,
            "time": event_time,
            "severity_id": severity_id,
            "metadata": {
                "version": "1.1.0",
                "product": {"name": "Microsoft Sentinel", "vendor_name": "Microsoft"},
                "provenance": provenance  # Fixes Issue #9
            }
        }

        if src_endpoint:
            normalized["src_endpoint"] = src_endpoint
        if dst_endpoint:
            normalized["dst_endpoint"] = dst_endpoint
        if "TargetUsername" in raw_event:
            normalized["actor"] = {"user": {"name": raw_event["TargetUsername"]}}
            provenance.append({"ocsf_field": "actor.user.name", "raw_field": "TargetUsername"})

        return normalized