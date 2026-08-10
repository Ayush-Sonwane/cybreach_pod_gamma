# src/adapters/qradar_adapter.py
from datetime import datetime, timezone
from typing import Dict, Any

class QRadarAdapter:
    """Adapter to map IBM QRadar events to OCSF Schema (Class UID: 3002)."""

    @staticmethod
    def _to_epoch_ms(raw_time) -> int:
        """QRadar 'starttime'/'devicetime' are epoch ms (or sec); normalize to ms."""
        if raw_time is None:
            return int(datetime.now(timezone.utc).timestamp() * 1000)
        if isinstance(raw_time, (int, float)):
            value = int(raw_time)
        else:
            text = str(raw_time).strip()
            if text.lstrip("-").isdigit():
                value = int(text)
            else:
                try:
                    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
                    return int(dt.timestamp() * 1000)
                except ValueError:
                    return int(datetime.now(timezone.utc).timestamp() * 1000)
        return value if value > 10**12 else value * 1000

    @staticmethod
    def normalize(raw_event: Dict[str, Any]) -> Dict[str, Any]:
        provenance = []

        # 1. Event Time -> OCSF epoch ms (prefer starttime, fall back to devicetime)
        raw_time = raw_event.get("starttime") or raw_event.get("devicetime")
        event_time = QRadarAdapter._to_epoch_ms(raw_time)
        if raw_time is not None:
            provenance.append({"ocsf_field": "time", "raw_field": "starttime" if "starttime" in raw_event else "devicetime"})

        # 2. Map Severity: QRadar magnitude 1-10 -> OCSF 1-5
        raw_mag = raw_event.get("magnitude") or raw_event.get("severity")
        try:
            magnitude = int(raw_mag)
        except (ValueError, TypeError):
            magnitude = 1
        severity_id = 5 if magnitude >= 9 else (4 if magnitude >= 7 else (3 if magnitude >= 5 else (2 if magnitude >= 3 else 1)))
        if raw_mag is not None:
            provenance.append({"ocsf_field": "severity_id",
                               "raw_field": "magnitude" if "magnitude" in raw_event else "severity"})

        # 3. Status Mapping (status -> 1/2/99)
        raw_status = str(raw_event.get("status", "")).lower()
        status_id = 1 if raw_status in ["success", "successful", "succeeded", "allowed"] else (
            2 if raw_status in ["failure", "failed", "error", "blocked"] else 99)
        if "status" in raw_event:
            provenance.append({"ocsf_field": "status_id", "raw_field": "status"})

        # 4. Source & Destination Endpoints
        src_endpoint = {}
        if "sourceip" in raw_event:
            src_endpoint["ip"] = raw_event["sourceip"]
            provenance.append({"ocsf_field": "src_endpoint.ip", "raw_field": "sourceip"})

        dst_endpoint = {}
        if "destinationip" in raw_event:
            dst_endpoint["ip"] = raw_event["destinationip"]
            provenance.append({"ocsf_field": "dst_endpoint.ip", "raw_field": "destinationip"})

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
                "product": {"name": "QRadar SIEM", "vendor_name": "IBM"},
                "provenance": provenance
            }
        }

        if src_endpoint:
            normalized["src_endpoint"] = src_endpoint
        if dst_endpoint:
            normalized["dst_endpoint"] = dst_endpoint
        if "username" in raw_event or "identityusername" in raw_event:
            raw_user = raw_event.get("username") or raw_event.get("identityusername")
            normalized["actor"] = {"user": {"name": raw_user}}
            provenance.append({"ocsf_field": "actor.user.name",
                               "raw_field": "username" if "username" in raw_event else "identityusername"})

        return normalized
