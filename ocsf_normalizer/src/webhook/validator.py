# src/webhook/validator.py
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

# The minimum generic webhook contract for custom SIEM solutions.
# A payload must be a non-empty JSON object carrying a timestamp plus at
# least one event descriptor (or enough endpoint/user context to be useful).
TIMESTAMP_KEYS = ["occurred_at", "event_time", "timestamp", "@timestamp", "time", "datetime"]
EVENT_DESCRIPTOR_KEYS = [
    "event_type", "event_name", "event_id", "event", "type",
    "message", "msg", "description",
]
CONTEXT_KEYS = [
    "src_ip", "source_ip", "src", "source",
    "dst_ip", "dest_ip", "destination_ip", "dst", "dest", "destination",
    "user", "username", "user_name",
]


class WebhookSchemaValidator:
    """
    Validates an incoming webhook payload against the generic webhook schema.

    Returns the same ``(is_valid, errors)`` contract used by OCSFValidator so
    callers can handle validation failures uniformly.
    """

    @classmethod
    def validate_payload(cls, payload: Any) -> Tuple[bool, List[str]]:
        errors = []

        # 1. Must be a JSON object
        if not isinstance(payload, dict):
            errors.append(
                f"Invalid payload: Expected a JSON object, got "
                f"{type(payload).__name__}"
            )
            return False, errors

        # 2. Must not be empty
        if not payload:
            errors.append("Invalid payload: Payload is empty")
            return False, errors

        # 3. Must contain a timestamp-like field
        ts_key = next((k for k in TIMESTAMP_KEYS if k in payload and payload[k] is not None), None)
        if ts_key is None:
            errors.append(
                f"Missing required timestamp field (one of: "
                f"{', '.join(TIMESTAMP_KEYS)})"
            )

        # 4. Must contain an event descriptor or endpoint/user context
        has_descriptor = any(
            k in payload and payload[k] not in (None, "") for k in EVENT_DESCRIPTOR_KEYS
        )
        has_context = any(
            k in payload and payload[k] not in (None, "") for k in CONTEXT_KEYS
        )
        if not (has_descriptor or has_context):
            errors.append(
                "Missing event descriptor or endpoint/user context "
                "(e.g. event_type, message, src_ip, username)"
            )

        # 5. Timestamp, when present, must be parseable to epoch milliseconds
        if ts_key is not None and not cls._valid_timestamp(payload[ts_key]):
            errors.append(
                f"Invalid timestamp for field '{ts_key}': "
                f"Expected epoch seconds/ms or ISO-8601 string, "
                f"got {type(payload[ts_key]).__name__}"
            )

        return len(errors) == 0, errors

    @staticmethod
    def _valid_timestamp(value: Any) -> bool:
        if isinstance(value, (int, float)):
            return True
        if isinstance(value, str):
            text = value.strip()
            if text.lstrip("-").isdigit():
                return True
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return True
            except ValueError:
                return False
        return False