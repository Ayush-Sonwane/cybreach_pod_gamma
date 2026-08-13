# src/transformer.py

from datetime import datetime, timezone
from typing import Any, Dict


class FieldTransformer:
    """
    Week 6 - OCSF Field Transformation Engine.

    Responsibilities:
        1. Vendor-specific field-name mapping
        2. Data type conversion
        3. Unit normalization
        4. Enumeration mapping
        5. Timestamp normalization
        6. Safe handling of None / unexpected values

    Input:
        vendor: vendor identifier
        raw_event: vendor-specific event dictionary

    Output:
        normalized intermediate dictionary
    """

    # =========================================================
    # FIELD NAME MAPPINGS
    # =========================================================

    FIELD_MAPPINGS = {

        "sentinel": {
            "SrcIpAddr": "src_ip",
            "DstIpAddr": "dst_ip",
            "SrcPortNumber": "src_port",
            "DstPortNumber": "dst_port",
            "TargetUsername": "user_name",
            "SeverityLevel": "severity",
            "TimeGenerated": "timestamp",
        },

        "splunk": {
            "src_ip": "src_ip",
            "dest_ip": "dst_ip",
            "src_port": "src_port",
            "dest_port": "dst_port",
            "user": "user_name",
            "vendor_severity": "severity",
            "_time": "timestamp",
        },

        "ecs": {
            "source.ip": "src_ip",
            "destination.ip": "dst_ip",
            "source.port": "src_port",
            "destination.port": "dst_port",
            "event.outcome": "outcome",
            "@timestamp": "timestamp",
        },

        "qradar": {
            "sourceip": "src_ip",
            "destinationip": "dst_ip",
            "sourceport": "src_port",
            "destinationport": "dst_port",
            "username": "user_name",
            "magnitude": "severity",
            "starttime": "timestamp",
        },

        "logscale": {
            "aip": "src_ip",
            "timestamp": "timestamp",
            "@timestamp": "timestamp",
            "loglevel": "severity",
        },
    }

    # =========================================================
    # ENUMERATION MAPPINGS
    # =========================================================

    ENUM_MAPPINGS = {

        "sentinel": {
            "severity": {
                "informational": 1,
                "info": 1,
                "low": 1,
                "medium": 2,
                "high": 3,
                "critical": 4,
            },
            "action": {
                "allow": "Allow",
                "allowed": "Allow",
                "block": "Block",
                "blocked": "Block",
                "deny": "Block",
                "denied": "Block",
            },
        },

        "splunk": {
            "severity": {
                "low": 1,
                "medium": 2,
                "high": 3,
                "critical": 4,
            },
            "action": {
                "allow": "Allow",
                "allowed": "Allow",
                "block": "Block",
                "blocked": "Block",
                "deny": "Block",
                "denied": "Block",
            },
        },

        "qradar": {
            "severity": {
                "low": 1,
                "medium": 2,
                "high": 3,
                "critical": 4,
            },
            "status": {
                "success": "Success",
                "failure": "Failure",
                "failed": "Failure",
                "unknown": "Unknown",
            },
        },

        "logscale": {
            "severity": {
                "debug": 0,
                "info": 1,
                "warning": 2,
                "warn": 2,
                "error": 3,
                "critical": 4,
            },
        },

        "ecs": {
            "outcome": {
                "success": "Success",
                "failure": "Failure",
                "unknown": "Unknown",
            },
        },
    }

    # =========================================================
    # MAIN TRANSFORMATION
    # =========================================================

    @classmethod
    def transform(
        cls,
        vendor: str,
        raw_event: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Transform a vendor-specific event into a normalized
        intermediate representation.
        """

        if not isinstance(raw_event, dict):
            raise TypeError("raw_event must be a dictionary")

        vendor = vendor.lower().strip()

        transformed = {}

        field_mapping = cls.FIELD_MAPPINGS.get(vendor, {})

        for source_field, raw_value in raw_event.items():

            # -------------------------------------------------
            # 1. FIELD NAME MAPPING
            # -------------------------------------------------

            target_field = field_mapping.get(
                source_field,
                source_field
            )

            # -------------------------------------------------
            # 2. DATA TYPE CONVERSION
            # -------------------------------------------------

            value = cls.convert_datatype(
                target_field,
                raw_value
            )

            # -------------------------------------------------
            # 3. UNIT NORMALIZATION
            # -------------------------------------------------

            value = cls.normalize_unit(
                target_field,
                value
            )

            # -------------------------------------------------
            # 4. ENUMERATION MAPPING
            # -------------------------------------------------

            value = cls.map_enum(
                vendor,
                target_field,
                value
            )

            transformed[target_field] = value

        return transformed

    # =========================================================
    # DATA TYPE CONVERSION
    # =========================================================

    @classmethod
    def convert_datatype(
        cls,
        field_name: str,
        value: Any,
    ) -> Any:

        if value is None:
            return None

        # -----------------------------------------------------
        # PORT
        # -----------------------------------------------------

        if field_name in {
            "src_port",
            "dst_port",
            "source_port",
            "destination_port",
        }:

            try:
                return int(value)

            except (ValueError, TypeError):
                return value

        # -----------------------------------------------------
        # SEVERITY
        # -----------------------------------------------------

        if field_name == "severity":

            try:
                return int(value)

            except (ValueError, TypeError):
                return value

        # -----------------------------------------------------
        # TIMESTAMP
        # -----------------------------------------------------

        if field_name in {
            "timestamp",
            "time",
        }:

            return cls.convert_timestamp(value)

        # -----------------------------------------------------
        # BOOLEAN
        # -----------------------------------------------------

        if field_name in {
            "success",
            "is_success",
            "enabled",
        }:

            return cls.convert_boolean(value)

        # -----------------------------------------------------
        # STRING FIELDS
        # -----------------------------------------------------

        if field_name in {
            "src_ip",
            "dst_ip",
            "user_name",
            "username",
            "action",
            "outcome",
        }:

            return str(value).strip()

        return value

    # =========================================================
    # BOOLEAN CONVERSION
    # =========================================================

    @staticmethod
    def convert_boolean(value: Any) -> Any:

        if isinstance(value, bool):
            return value

        if isinstance(value, str):

            value_lower = value.strip().lower()

            if value_lower in {
                "true",
                "yes",
                "1",
                "enabled",
                "success",
            }:
                return True

            if value_lower in {
                "false",
                "no",
                "0",
                "disabled",
                "failure",
                "failed",
            }:
                return False

        if isinstance(value, (int, float)):
            return value != 0

        return value

    # =========================================================
    # TIMESTAMP CONVERSION
    # =========================================================

    @staticmethod
    def convert_timestamp(value: Any) -> Any:

        if value is None:
            return None

        # Already datetime
        if isinstance(value, datetime):

            if value.tzinfo is None:
                value = value.replace(
                    tzinfo=timezone.utc
                )

            return int(
                value.timestamp() * 1000
            )

        # Numeric Unix timestamp
        if isinstance(value, (int, float)):

            # Seconds → milliseconds
            if value < 10_000_000_000:

                return int(value * 1000)

            # Already milliseconds
            return int(value)

        # String timestamp
        if isinstance(value, str):

            value = value.strip()

            # Numeric timestamp stored as string
            try:

                numeric_value = float(value)

                return FieldTransformer.convert_timestamp(
                    numeric_value
                )

            except ValueError:
                pass

            # ISO-8601 timestamp
            try:

                parsed = datetime.fromisoformat(
                    value.replace("Z", "+00:00")
                )

                if parsed.tzinfo is None:
                    parsed = parsed.replace(
                        tzinfo=timezone.utc
                    )

                return int(
                    parsed.timestamp() * 1000
                )

            except ValueError:
                return value

        return value

    # =========================================================
    # UNIT NORMALIZATION
    # =========================================================

    @staticmethod
    def normalize_unit(
        field_name: str,
        value: Any,
    ) -> Any:

        if value is None:
            return None

        # -----------------------------------------------------
        # Duration fields
        #
        # Internally normalize durations to milliseconds.
        # -----------------------------------------------------

        if field_name in {
            "duration_ms",
            "duration",
        }:

            try:
                return int(float(value))

            except (ValueError, TypeError):
                return value

        # -----------------------------------------------------
        # Size fields
        #
        # OCSF representation uses bytes.
        # -----------------------------------------------------

        if field_name in {
            "file_size",
            "size_bytes",
        }:

            try:
                return int(value)

            except (ValueError, TypeError):
                return value

        return value

    # =========================================================
    # ENUMERATION MAPPING
    # =========================================================

    @classmethod
    def map_enum(
        cls,
        vendor: str,
        field_name: str,
        value: Any,
    ) -> Any:

        if value is None:
            return None

        vendor_mapping = cls.ENUM_MAPPINGS.get(
            vendor,
            {}
        )

        field_mapping = vendor_mapping.get(
            field_name,
            {}
        )

        if not field_mapping:
            return value

        # Case-insensitive mapping
        if isinstance(value, str):

            normalized_value = value.strip().lower()

            # Build case-insensitive lookup
            for source_value, target_value in field_mapping.items():

                if normalized_value == str(
                    source_value
                ).lower():

                    return target_value

        return field_mapping.get(
            value,
            value
        )