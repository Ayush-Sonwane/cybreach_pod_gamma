# src/adapters/logscale_adapter.py
from datetime import datetime, timezone
from typing import Dict, Any

class LogScaleAdapter:
    """Adapter to map CrowdStrike LogScale events to OCSF Schema (Class UID: 3002)."""

    @staticmethod
    def _to_epoch_ms(raw_ts) -> int:
        """LogScale '@timestamp' is epoch ms (or ISO string); normalize to ms."""
        if raw_ts is None:
            return int(datetime.now(timezone.utc).timestamp() * 1000)
        if isinstance(raw_ts, (int, float)):
            value = int(raw_ts)
            return value if value > 10**12 else value * 1000
        text = str(raw_ts).strip()
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

        # 1. Event Time -> OCSF epoch ms
        event_time = LogScaleAdapter._to_epoch_ms(raw_event.get("@timestamp"))
        provenance.append({"ocsf_field": "time", "raw_field": "@timestamp"})

        # 2. Map Severity to OCSF scale 1-5
        loglevel = str(raw_event.get("loglevel", "")).upper()
        sev_map = {"DEBUG": 1, "INFO": 1, "NOTICE": 1,
                   "WARN": 2, "WARNING": 2,
                   "ERROR": 3, "ERR": 3,
                   "HIGH": 4, "CRITICAL": 5, "FATAL": 5}
        severity_id = sev_map.get(loglevel, 1)
        if "loglevel" in raw_event:
            provenance.append({"ocsf_field": "severity_id", "raw_field": "loglevel"})

        # 3. Status Mapping (status/outcome -> 1/2/99)
        raw_status = str(raw_event.get("status") or raw_event.get("outcome") or "").lower()
        status_id = 1 if raw_status in ["success", "successful", "succeeded", "allowed"] else (
            2 if raw_status in ["failure", "failed", "error", "blocked"] else 99)
        if "status" in raw_event or "outcome" in raw_event:
            provenance.append({"ocsf_field": "status_id",
                               "raw_field": "status" if "status" in raw_event else "outcome"})

        # 4. Source Endpoint (aip)
        src_endpoint = {}
        if "aip" in raw_event:
            src_endpoint["ip"] = raw_event["aip"]
            provenance.append({"ocsf_field": "src_endpoint.ip", "raw_field": "aip"})

        # 5. Destination Endpoint (endpoint_ip/dst_ip, fallback to endpoint)
        raw_dst = raw_event.get("endpoint_ip") or raw_event.get("dst_ip") or raw_event.get("endpoint")
        dst_endpoint = {"ip": raw_dst} if raw_dst else {}
        if raw_dst is not None:
            src_field = "endpoint_ip" if "endpoint_ip" in raw_event else ("dst_ip" if "dst_ip" in raw_event else "endpoint")
            provenance.append({"ocsf_field": "dst_endpoint.ip", "raw_field": src_field})

        normalized = {
            "class_uid": 3002,
            "category_uid": 3,
            "activity_id": 1,
            "time": event_time,
            "severity_id": severity_id,
            "status_id": status_id,
            "metadata": {
                "version": "1.1.0",
                "product": {"name": "LogScale", "vendor_name": "CrowdStrike"},
                "provenance": provenance
            }
        }

        if src_endpoint:
            normalized["src_endpoint"] = src_endpoint
        if dst_endpoint:
            normalized["dst_endpoint"] = dst_endpoint

        if "user" in raw_event or "user_name" in raw_event:
            raw_user = raw_event.get("user") or raw_event.get("user_name")
            normalized["actor"] = {"user": {"name": raw_user}}
            provenance.append({"ocsf_field": "actor.user.name",
                               "raw_field": "user" if "user" in raw_event else "user_name"})

        return normalized
