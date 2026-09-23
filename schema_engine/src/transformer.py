# src/transformer.py

from typing import Dict, Any
from datetime import datetime, timezone


class FieldTransformer:
    """
    Stage 2: Field Transformation Engine.

    Supports:
        1. Data type conversion
        2. Unit normalization
        3. Enumeration value mapping
        4. Vendor-specific field mapping
    """

    # ---------------------------------------------------------
    # ENUMERATION MAPPINGS
    # ---------------------------------------------------------

    ENUM_MAPPINGS = {
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

        "splunk": {
            "severity": {
                "low": 1,
                "medium": 2,
                "high": 3,
                "critical": 4,
            },
            "action": {
                "allowed": "Allow",
                "allow": "Allow",
                "blocked": "Block",
                "block": "Block",
                "denied": "Block",
                "deny": "Block",
            },
        },

        "sentinel": {
            "severity": {
                "Informational": 1,
                "Low": 2,
                "Medium": 3,
                "High": 4,
            },
            "action": {
                "Allow": "Allow",
                "Allowed": "Allow",
                "Block": "Block",
                "Blocked": "Block",
                "Deny": "Block",
                "Denied": "Block",
            },
        },

        "logscale": {
            "severity": {
                "debug": 0,
                "info": 1,
                "warning": 2,
                "error": 3,
                "critical": 4,
            }
        },

        "ecs": {
            "event.outcome": {
                "success": "Success",
                "failure": "Failure",
                "unknown": "Unknown",
            }
        },
    }

    # ---------------------------------------------------------
    # FIELD NAME MAPPINGS
    # ---------------------------------------------------------

    FIELD_MAPPINGS = {
        "qradar": {
            "sourceip": "src_ip",
            "destinationip": "dst_ip",
            "sourceport": "src_port",
            "destinationport": "dst_port",
            "username": "user_name",
            "magnitude": "severity",
            "starttime": "timestamp",
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

        "sentinel": {
            "SrcIpAddr": "src_ip",
            "DstIpAddr": "dst_ip",
            "SrcPortNumber": "src_port",
            "DstPortNumber": "dst_port",
            "TargetUsername": "user_name",
            "TimeGenerated": "timestamp",
        },

        "logscale": {
            "aip": "src_ip",
            "timestamp": "timestamp",
            "@timestamp": "timestamp",
            "loglevel": "severity",
        },

        "ecs": {
            "source.ip": "src_ip",
            "destination.ip": "dst_ip",
            "source.port": "src_port",
            "destination.port": "dst_port",
            "event.outcome": "outcome",
        },
    }

    # ---------------------------------------------------------
    # MAIN TRANSFORMATION METHOD
    # ---------------------------------------------------------

    @classmethod
    def transform(
        cls,
        vendor: str,
        raw_event: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Transform vendor-specific event into a normalized
        intermediate representation.
        """

        if not isinstance(raw_event, dict):
            raise TypeError("raw_event must be a dictionary")

        transformed = {}

        field_mapping = cls.FIELD_MAPPINGS.get(vendor, {})

        for source_field, value in raw_event.items():

            # ---------------------------------------------
            # 1. FIELD NAME MAPPING
            # ---------------------------------------------

            target_field = field_mapping.get(
                source_field,
                source_field
            )

            # ---------------------------------------------
            # 2. DATA TYPE CONVERSION
            # ---------------------------------------------

            value = cls.convert_datatype(
                target_field,
                value
            )

            # ---------------------------------------------
            # 3. UNIT NORMALIZATION
            # ---------------------------------------------

            value = cls.normalize_unit(
                target_field,
                value
            )

            # ---------------------------------------------
            # 4. ENUMERATION MAPPING
            # ---------------------------------------------

            value = cls.map_enum(
                vendor,
                target_field,
                value
            )

            transformed[target_field] = value

        return transformed

    # ---------------------------------------------------------
    # DATA TYPE CONVERSION
    # ---------------------------------------------------------

    @staticmethod
    def convert_datatype(
        field_name: str,
        value: Any,
    ) -> Any:

        if value is None:
            return None

        # Port numbers → integer
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

        # Severity → integer
        if field_name == "severity":
            try:
                return int(value)
            except (ValueError, TypeError):
                return value

        # Timestamp → ISO 8601
        if field_name == "timestamp":
            return FieldTransformer.convert_timestamp(value)

        # Boolean fields
        if field_name in {
            "is_success",
            "success",
            "enabled",
        }:
            return FieldTransformer.convert_boolean(value)

        # String normalization
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

    # ---------------------------------------------------------
    # BOOLEAN CONVERSION
    # ---------------------------------------------------------

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

        if isinstance(value, int):
            return value != 0

        return value

    # ---------------------------------------------------------
    # TIMESTAMP CONVERSION
    # ---------------------------------------------------------

    @staticmethod
    def convert_timestamp(value: Any) -> Any:

        if value is None:
            return None

        # Already datetime
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)

            return value.isoformat()

        # Numeric Unix timestamp
        if isinstance(value, (int, float)):

            # milliseconds
            if value > 10_000_000_000:
                value = value / 1000

            try:
                return datetime.fromtimestamp(
                    value,
                    tz=timezone.utc
                ).isoformat()

            except (ValueError, OverflowError, OSError):
                return value

        # String timestamp
        if isinstance(value, str):

            value = value.strip()

            try:
                parsed = datetime.fromisoformat(
                    value.replace("Z", "+00:00")
                )

                if parsed.tzinfo is None:
                    parsed = parsed.replace(
                        tzinfo=timezone.utc
                    )

                return parsed.isoformat()

            except ValueError:
                return value

        return value

    # ---------------------------------------------------------
    # UNIT NORMALIZATION
    # ---------------------------------------------------------

    @staticmethod
    def normalize_unit(
        field_name: str,
        value: Any,
    ) -> Any:

        if value is None:
            return None

        # Network byte fields
        if field_name in {
            "bytes",
            "network_bytes",
        }:

            try:
                return int(value)
            except (ValueError, TypeError):
                return value

        # Duration normalization
        #
        # Standard output = milliseconds
        #
        if field_name in {
            "duration_ms",
            "duration",
        }:

            if isinstance(value, (int, float)):
                return float(value)

            if isinstance(value, str):

                value = value.strip().lower()

                try:
                    if value.endswith("ms"):
                        return float(
                            value[:-2].strip()
                        )

                    if value.endswith("s"):
                        return float(
                            value[:-1].strip()
                        ) * 1000

                    if value.endswith("m"):
                        return float(
                            value[:-1].strip()
                        ) * 60 * 1000

                except ValueError:
                    return value

        return value

    # ---------------------------------------------------------
    # ENUMERATION MAPPING
    # ---------------------------------------------------------

    @classmethod
    def map_enum(
        cls,
        vendor: str,
        field_name: str,
        value: Any,
    ) -> Any:

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

        if isinstance(value, str):

            for source_value, target_value in field_mapping.items():

                if value.lower() == source_value.lower():
                    return target_value

        return field_mapping.get(
            value,
            value
        )
if __name__ == "__main__":
    import json

    print("Enter raw event as JSON:")
    user_input = input(" ")

    try:
        raw_event = json.loads(user_input)

        result = FieldTransformer.transform("qradar", raw_event)

        print("\nRaw Event:")   
        print(raw_event)

        print("\nTransformed Event:")
        print(result)

    except json.JSONDecodeError:
        print("Invalid JSON input.")

    except Exception as e:
        print(f"Error: {e}")