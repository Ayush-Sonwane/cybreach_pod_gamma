# src/adapters/qradar_adapter.py
from datetime import datetime
from typing import Dict, Any

class QRadarAdapter:
    """Adapter to map IBM QRadar events to OCSF Schema (Class UID: 3002)."""

    @staticmethod
    def normalize(raw_event: Dict[str, Any]) -> Dict[str, Any]:
        provenance = []

        # Time Conversion (Epoch milliseconds)
        starttime = raw_event.get("starttime")
        if starttime:
            event_time = datetime.fromtimestamp(float(starttime) / 1000.0).isoformat() + "Z"
            provenance.append({"ocsf_field": "time", "raw_field": "starttime"})
        else:
            event_time = datetime.utcnow().isoformat() + "Z"

        # Magnitude to OCSF Severity ID
        mag = raw_event.get("magnitude", 1)
        severity_id = 4 if mag >= 8 else (3 if mag >= 6 else (2 if mag >= 4 else 1))
        provenance.append({"ocsf_field": "severity_id", "raw_field": "magnitude"})

        normalized = {
            "class_uid": 3002,  # Fixed Issue #10: Standardized from 3001 to 3002
            "category_uid": 3,
            "activity_id": 1,
            "time": event_time,
            "severity_id": severity_id,
            "src_endpoint": {"ip": raw_event.get("sourceip")},
            "dst_endpoint": {"ip": raw_event.get("destinationip")},
            "metadata": {
                "version": "1.1.0",
                "product": {"name": "QRadar SIEM", "vendor_name": "IBM"},
                "provenance": provenance
            }
        }
        provenance.append({"ocsf_field": "src_endpoint.ip", "raw_field": "sourceip"})
        provenance.append({"ocsf_field": "dst_endpoint.ip", "raw_field": "destinationip"})

        if "username" in raw_event:
            normalized["actor"] = {"user": {"name": raw_event["username"]}}
            provenance.append({"ocsf_field": "actor.user.name", "raw_field": "username"})

        return normalized