# src/adapters/logscale_adapter.py
from datetime import datetime
from typing import Dict, Any

class LogScaleAdapter:
    """Adapter to map CrowdStrike LogScale events to OCSF Schema (Class UID: 3002)."""

    @staticmethod
    def normalize(raw_event: Dict[str, Any]) -> Dict[str, Any]:
        provenance = []

        ts = raw_event.get("@timestamp")
        if isinstance(ts, (int, float)):
            event_time = datetime.fromtimestamp(float(ts) / 1000.0).isoformat() + "Z"
        else:
            event_time = ts if ts else datetime.utcnow().isoformat() + "Z"
        provenance.append({"ocsf_field": "time", "raw_field": "@timestamp"})

        loglevel = str(raw_event.get("loglevel", "")).upper()
        sev_map = {"INFO": 1, "WARN": 2, "WARNING": 2, "ERROR": 3, "FATAL": 4}
        severity_id = sev_map.get(loglevel, 1)
        provenance.append({"ocsf_field": "severity_id", "raw_field": "loglevel"})

        normalized = {
            "class_uid": 3002,  # Fixed Issue #10: Standardized from 3001 to 3002
            "category_uid": 3,
            "activity_id": 1,
            "time": event_time,
            "severity_id": severity_id,
            "src_endpoint": {"ip": raw_event.get("aip")},
            "dst_endpoint": {"ip": raw_event.get("endpoint")},
            "metadata": {
                "version": "1.1.0",
                "product": {"name": "LogScale", "vendor_name": "CrowdStrike"},
                "provenance": provenance
            }
        }
        provenance.append({"ocsf_field": "src_endpoint.ip", "raw_field": "aip"})
        provenance.append({"ocsf_field": "dst_endpoint.ip", "raw_field": "endpoint"})

        if "user" in raw_event:
            normalized["actor"] = {"user": {"name": raw_event["user"]}}
            provenance.append({"ocsf_field": "actor.user.name", "raw_field": "user"})

        return normalized