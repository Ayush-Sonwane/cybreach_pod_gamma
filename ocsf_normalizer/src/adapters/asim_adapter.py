# src/adapters/asim_adapter.py
from datetime import datetime, timezone
from typing import Dict, Any

class ASIMAdapter:
    """Adapter to map MS Sentinel ASIM events to OCSF Schema (Class UID: 3002)."""

    @staticmethod
    def _to_epoch_ms(raw_time) -> int:
        """Converts ASIM 'TimeGenerated' (ISO string) to epoch ms."""
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

        # 1. Event Time -> OCSF epoch ms (prefer EventStartTime, fall back to TimeGenerated)
        time_gen = raw_event.get("EventStartTime") or raw_event.get("TimeGenerated")
        event_time = ASIMAdapter._to_epoch_ms(time_gen)
        if time_gen is not None:
            provenance.append({"ocsf_field": "time",
                               "raw_field": "EventStartTime" if "EventStartTime" in raw_event else "TimeGenerated"})

        # 2. Map Severity to OCSF scale 1-5
        raw_sev = str(raw_event.get("SeverityLevel", "")).lower()
        sev_map = {"informational": 1, "info": 1, "low": 1,
                   "medium": 2, "high": 3,
                   "critical": 4, "fatal": 5}
        severity_id = sev_map.get(raw_sev, 1)
        if "SeverityLevel" in raw_event:
            provenance.append({"ocsf_field": "severity_id", "raw_field": "SeverityLevel"})

        # 3. Status Mapping (EventResult Success/Failure -> 1/2/99)
        raw_result = str(raw_event.get("EventResult", "")).lower()
        status_id = 1 if raw_result in ["success", "succeeded", "allowed"] else (
            2 if raw_result in ["failure", "failed", "blocked", "denied"] else 99)
        if "EventResult" in raw_event:
            provenance.append({"ocsf_field": "status_id", "raw_field": "EventResult"})

        # 4. Source & Destination Endpoints
        src_endpoint = {}
        if "SrcIpAddr" in raw_event:
            src_endpoint["ip"] = raw_event["SrcIpAddr"]
            provenance.append({"ocsf_field": "src_endpoint.ip", "raw_field": "SrcIpAddr"})

        dst_endpoint = {}
        if "DstIpAddr" in raw_event or "TargetIpAddr" in raw_event:
            dst_endpoint["ip"] = raw_event.get("DstIpAddr") or raw_event.get("TargetIpAddr")
            provenance.append({"ocsf_field": "dst_endpoint.ip",
                               "raw_field": "DstIpAddr" if "DstIpAddr" in raw_event else "TargetIpAddr"})

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
                "product": {"name": "Microsoft Sentinel", "vendor_name": "Microsoft"},
                "provenance": provenance
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
