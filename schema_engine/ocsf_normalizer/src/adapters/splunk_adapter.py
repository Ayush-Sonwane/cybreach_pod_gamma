# src/adapters/splunk_adapter.py
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Dict, Any

class SplunkAdapter:
    """Adapter to map Splunk CIM events to OCSF Schema (Class UID: 3002)."""

    @staticmethod
    def _to_epoch_ms(raw_time) -> int:
        """Converts Splunk '_time' (epoch seconds/ms or ISO string) to epoch ms."""
        if raw_time is None:
            return int(datetime.now(timezone.utc).timestamp() * 1000)
        if isinstance(raw_time, (int, float)):
            return int(raw_time) if raw_time > 10**12 else int(raw_time * 1000)
        text = str(raw_time).strip()
        if text.lstrip("-").isdigit():
            value = int(text)
            return value if value > 10**12 else value * 1000
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
            return int(dt.timestamp() * 1000)
        except ValueError:
            return int(datetime.now(timezone.utc).timestamp() * 1000)

    @staticmethod
    def normalize(raw_event: Dict[str, Any]) -> Dict[str, Any]:
        provenance = []

        # 1. Parse Event Time to OCSF epoch milliseconds
        raw_time = raw_event.get("_time")
        event_time = SplunkAdapter._to_epoch_ms(raw_time)
        if raw_time is not None:
            provenance.append({"ocsf_field": "time", "raw_field": "_time"})

        # 2. Map Severity to OCSF scale 1-5
        raw_sev = str(raw_event.get("vendor_severity", "")).lower()
        sev_map = {"debug": 1, "info": 1, "informational": 1,
                   "low": 2, "medium": 3, "moderate": 3,
                   "high": 4, "critical": 5, "fatal": 5}
        severity_id = sev_map.get(raw_sev, 1)
        if "vendor_severity" in raw_event:
            provenance.append({"ocsf_field": "severity_id", "raw_field": "vendor_severity"})

        # 3. Status Mapping (Success/Failure -> 1/2/99)
        raw_action = str(raw_event.get("action") or raw_event.get("status") or "").lower()
        status_id = 1 if raw_action in ["success", "successful", "succeeded", "allowed"] else (
            2 if raw_action in ["failure", "failed", "error", "blocked"] else 99)
        if "action" in raw_event or "status" in raw_event:
            provenance.append({"ocsf_field": "status_id",
                               "raw_field": "action" if "action" in raw_event else "status"})

        # 4. Source Endpoint
        src_endpoint = {}
        if "src_ip" in raw_event or "src" in raw_event:
            src_ip = raw_event.get("src_ip") or raw_event.get("src")
            src_endpoint["ip"] = src_ip
            provenance.append({"ocsf_field": "src_endpoint.ip", "raw_field": "src_ip" if "src_ip" in raw_event else "src"})

        # 5. Destination Endpoint
        dst_endpoint = {}
        if "dest_ip" in raw_event or "dest" in raw_event:
            dst_ip = raw_event.get("dest_ip") or raw_event.get("dest")
            dst_endpoint["ip"] = dst_ip
            provenance.append({"ocsf_field": "dst_endpoint.ip", "raw_field": "dest_ip" if "dest_ip" in raw_event else "dest"})

        # Build Normalized OCSF Record (Class UID 3002)
        normalized = {
            "class_uid": 3002,
            "category_uid": 3,
            "activity_id": 1,
            "time": event_time,
            "severity_id": severity_id,
            "status_id": status_id,
            "metadata": {
                "version": "1.1.0",
                "product": {"name": "Splunk Enterprise", "vendor_name": "Splunk"},
                "provenance": provenance
            }
        }

        if src_endpoint:
            normalized["src_endpoint"] = src_endpoint
        if dst_endpoint:
            normalized["dst_endpoint"] = dst_endpoint
        if "user" in raw_event or "src_user" in raw_event:
            raw_user = raw_event.get("user") or raw_event.get("src_user")
            normalized["actor"] = {"user": {"name": raw_user}}
            provenance.append({"ocsf_field": "actor.user.name",
                               "raw_field": "user" if "user" in raw_event else "src_user"})

        return normalized


class SplunkOCSFAdapter(SplunkAdapter):
    """Backward-compatible Splunk adapter API used by legacy scripts/tests."""

    @staticmethod
    def is_splunk_payload(raw_event: Dict[str, Any]) -> bool:
        keys = set(raw_event.keys())
        return bool({"vendor_severity", "src_ip", "dest_ip", "src", "dest", "_time"} & keys)

    @staticmethod
    def map_to_ocsf(raw_event: Dict[str, Any]) -> SimpleNamespace:
        normalized = SplunkAdapter.normalize(raw_event)
        legacy_event = {
            **normalized,
            "user": {"name": raw_event.get("user") or raw_event.get("src_user")},
            "device": {"ip": raw_event.get("dest_ip") or raw_event.get("dest")},
        }

        def as_namespace(value):
            if isinstance(value, dict):
                return SimpleNamespace(**{k: as_namespace(v) for k, v in value.items()})
            if isinstance(value, list):
                return [as_namespace(item) for item in value]
            return value

        return as_namespace(legacy_event)
