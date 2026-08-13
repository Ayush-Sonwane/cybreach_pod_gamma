# src/adapters/webhook_adapter.py
from datetime import datetime, timezone
from typing import Any, Dict

# Generic signature keys accepted by the webhook connector. This lets custom
# SIEM solutions push events with their own field names and still be mapped.
TIME_KEYS = ["occurred_at", "event_time", "timestamp", "@timestamp", "time", "datetime"]
EVENT_KEYS = ["event_type", "event_name", "event_id", "event", "type"]
MESSAGE_KEYS = ["message", "msg", "description", "details"]

SOURCE_IP_KEYS = ["src_ip", "source_ip", "src", "source", "source.ip"]
DEST_IP_KEYS = ["dst_ip", "dest_ip", "destination_ip", "dst", "dest", "destination", "destination.ip"]
USER_KEYS = ["user", "username", "user_name", "src_user", "target_username", "subject_username"]


class WebhookAdapter:
    """
    Generic webhook adapter for custom SIEM solutions.

    Maps an arbitrary webhook payload to a canonical OCSF Authentication
    Event (Class UID: 3002) using best-effort, fallback-key extraction so a
    wide range of custom vendors can be onboarded without code changes.

    Field-level provenance is tracked in ``metadata.provenance`` in the same
    format used by the vendor adapters (Splunk, ECS, QRadar, etc.).
    """

    @staticmethod
    def _to_epoch_ms(raw_time) -> int:
        """Converts a webhook timestamp (epoch sec/ms, ISO string, numeric string) to epoch ms."""
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
    def _get(raw_event: Dict[str, Any], keys) -> Any:
        """Returns the first non-None value found among ``keys`` (supports dotted paths)."""
        for key in keys:
            parts = str(key).split(".")
            curr = raw_event
            for part in parts:
                if isinstance(curr, dict) and part in curr:
                    curr = curr[part]
                else:
                    curr = None
                    break
            if curr is not None:
                return curr
        return None

    @staticmethod
    def _which(raw_event: Dict[str, Any], keys):
        """Returns the first key from ``keys`` that is present and non-None in the payload."""
        for key in keys:
            value = WebhookAdapter._get(raw_event, [key])
            if value is not None:
                return key
        return None

    @staticmethod
    def _severity_id(raw_event: Dict[str, Any], provenance: list) -> int:
        """Maps a webhook severity (string level or numeric 1-10) to OCSF 1-5."""
        raw = WebhookAdapter._get(raw_event, ["severity_id", "severity", "level", "priority"])
        if raw is None:
            return 1
        source_key = WebhookAdapter._which(raw_event, ["severity_id", "severity", "level", "priority"])

        if isinstance(raw, bool):
            severity_id = 2 if raw else 1
        elif isinstance(raw, (int, float)):
            value = int(raw)
            if value <= 5:
                severity_id = max(1, value)
            else:
                # Numeric 1-10 magnitude style scaling (matches QRadar adapter).
                severity_id = 5 if value >= 9 else (4 if value >= 7 else (3 if value >= 5 else (2 if value >= 3 else 1)))
        else:
            sev_map = {
                "debug": 1, "info": 1, "informational": 1, "notice": 1, "low": 2,
                "medium": 3, "moderate": 3, "warning": 3, "warn": 3,
                "high": 4,
                "critical": 5, "fatal": 5, "emergency": 5,
            }
            severity_id = sev_map.get(str(raw).strip().lower(), 1)

        if source_key:
            provenance.append({"ocsf_field": "severity_id", "raw_field": source_key})
        return severity_id

    @staticmethod
    def _status_id(raw_event: Dict[str, Any], provenance: list) -> int:
        """Maps a webhook status/outcome to OCSF 1 (success) / 2 (failure) / 99 (unknown)."""
        raw = WebhookAdapter._get(raw_event, ["status", "outcome", "result", "action"])
        if raw is None:
            return 99
        source_key = WebhookAdapter._which(raw_event, ["status", "outcome", "result", "action"])
        raw_status = str(raw).strip().lower()
        status_id = 1 if raw_status in ["success", "successful", "succeeded", "allowed", "allow", "ok", "true"] else (
            2 if raw_status in ["failure", "failed", "fail", "error", "blocked", "block", "denied", "deny", "false"] else 99)
        if source_key:
            provenance.append({"ocsf_field": "status_id", "raw_field": source_key})
        return status_id

    @staticmethod
    def normalize(raw_event: Dict[str, Any]) -> Dict[str, Any]:
        provenance = []

        # 1. Event Time -> OCSF epoch ms
        time_key = WebhookAdapter._which(raw_event, TIME_KEYS)
        event_time = WebhookAdapter._to_epoch_ms(WebhookAdapter._get(raw_event, TIME_KEYS))
        if time_key:
            provenance.append({"ocsf_field": "time", "raw_field": time_key})

        # 2. Severity -> OCSF 1-5
        severity_id = WebhookAdapter._severity_id(raw_event, provenance)

        # 3. Status -> OCSF 1/2/99
        status_id = WebhookAdapter._status_id(raw_event, provenance)

        # 4. Source & Destination Endpoints
        src_endpoint = {}
        src_ip_key = WebhookAdapter._which(raw_event, SOURCE_IP_KEYS)
        if src_ip_key:
            src_endpoint["ip"] = WebhookAdapter._get(raw_event, [src_ip_key])
            provenance.append({"ocsf_field": "src_endpoint.ip", "raw_field": src_ip_key})

        dst_endpoint = {}
        dst_ip_key = WebhookAdapter._which(raw_event, DEST_IP_KEYS)
        if dst_ip_key:
            dst_endpoint["ip"] = WebhookAdapter._get(raw_event, [dst_ip_key])
            provenance.append({"ocsf_field": "dst_endpoint.ip", "raw_field": dst_ip_key})

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
                "product": {"name": "Generic Webhook", "vendor_name": "Custom SIEM"},
                "provenance": provenance,
            },
        }

        if src_endpoint:
            normalized["src_endpoint"] = src_endpoint
        if dst_endpoint:
            normalized["dst_endpoint"] = dst_endpoint

        # 5. User / Actor context
        user_key = WebhookAdapter._which(raw_event, USER_KEYS)
        if user_key:
            normalized["actor"] = {"user": {"name": WebhookAdapter._get(raw_event, [user_key])}}
            provenance.append({"ocsf_field": "actor.user.name", "raw_field": user_key})

        # 6. Message (fall back to the event type/name descriptor)
        message_key = WebhookAdapter._which(raw_event, MESSAGE_KEYS)
        if message_key:
            normalized["message"] = WebhookAdapter._get(raw_event, [message_key])
            provenance.append({"ocsf_field": "message", "raw_field": message_key})
        else:
            event_key = WebhookAdapter._which(raw_event, EVENT_KEYS)
            if event_key:
                normalized["message"] = WebhookAdapter._get(raw_event, [event_key])
                provenance.append({"ocsf_field": "message", "raw_field": event_key})

        return normalized