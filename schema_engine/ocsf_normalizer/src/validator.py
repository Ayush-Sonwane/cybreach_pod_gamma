from typing import Dict, Any, Tuple, List


class OCSFValidator:
    """
    Validates normalized JSON payloads against core OCSF 1.1.0 schema requirements,
    including complex object (endpoint, user, file, process, device) validation.
    """

    # Core mandatory fields required across all OCSF event classes
    MANDATORY_BASE_FIELDS = ["class_uid", "category_uid", "time"]

    # Complex object fields that should be dictionaries when present
    COMPLEX_OBJECT_FIELDS = [
        "user",
        "actor",
        "src_endpoint",
        "dst_endpoint",
        "file",
        "process",
        "device",
    ]

    @classmethod
    def validate_event(cls, ocsf_event: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validates an OCSF event dictionary.
        Returns:
            (is_valid: bool, errors: List[str])
        """
        errors = []

        # 1. Check top-level mandatory OCSF fields
        for field in cls.MANDATORY_BASE_FIELDS:
            if field not in ocsf_event or ocsf_event[field] is None:
                errors.append(f"Missing mandatory OCSF field: '{field}'")

        # 2. Validate timestamp format (must be integer/unix epoch in ms or seconds)
        event_time = ocsf_event.get("time")
        if event_time is not None and not isinstance(event_time, (int, float)):
            errors.append(f"Invalid 'time' type: Expected numeric timestamp, got {type(event_time).__name__}")

        # 3. Validate complex objects
        cls._validate_complex_objects(ocsf_event, errors)

        # 4. Class-specific validation rules
        class_uid = ocsf_event.get("class_uid")

        # Class 4001: Network Activity
        if class_uid == 4001:
            if "src_endpoint" not in ocsf_event:
                errors.append("Class 4001 (Network Activity) missing 'src_endpoint'")
            if "dst_endpoint" not in ocsf_event:
                errors.append("Class 4001 (Network Activity) missing 'dst_endpoint'")

        # Class 3002: Authentication
        elif class_uid == 3002:
            if "user" not in ocsf_event and "actor" not in ocsf_event:
                errors.append("Class 3002 (Authentication) missing 'user' or 'actor' context")

        # 5. Final Verdict
        is_valid = len(errors) == 0
        return is_valid, errors

    @classmethod
    def _validate_complex_objects(cls, ocsf_event: Dict[str, Any], errors: List[str]) -> None:
        """Validates that complex object fields are well-formed."""
        for field in cls.COMPLEX_OBJECT_FIELDS:
            value = ocsf_event.get(field)
            if value is None:
                continue

            if not isinstance(value, dict):
                errors.append(f"Invalid '{field}': Expected object/dict, got {type(value).__name__}")
                continue

            # Nested object-type checks
            if field == "src_endpoint" or field == "dst_endpoint":
                cls._validate_endpoint(field, value, errors)

            elif field == "user":
                cls._validate_user(field, value, errors)

            elif field == "process":
                cls._validate_process(field, value, errors)

            elif field == "file":
                cls._validate_file(field, value, errors)

            elif field == "device":
                cls._validate_device(field, value, errors)

    @staticmethod
    def _validate_endpoint(field: str, ep: Dict[str, Any], errors: List[str]) -> None:
        ip = ep.get("ip")
        if ip is not None and not isinstance(ip, str):
            errors.append(f"Invalid '{field}.ip': Expected string, got {type(ip).__name__}")
        port = ep.get("port")
        if port is not None and not isinstance(port, (int, float)):
            errors.append(f"Invalid '{field}.port': Expected integer, got {type(port).__name__}")

    @staticmethod
    def _validate_user(field: str, user: Dict[str, Any], errors: List[str]) -> None:
        name = user.get("name")
        if name is not None and not isinstance(name, str):
            errors.append(f"Invalid '{field}.name': Expected string, got {type(name).__name__}")

    @staticmethod
    def _validate_process(field: str, process: Dict[str, Any], errors: List[str]) -> None:
        pid = process.get("pid")
        if pid is not None and not isinstance(pid, (int, float)):
            errors.append(f"Invalid '{field}.pid': Expected integer, got {type(pid).__name__}")

    @staticmethod
    def _validate_file(field: str, file: Dict[str, Any], errors: List[str]) -> None:
        size = file.get("size")
        if size is not None and not isinstance(size, (int, float)):
            errors.append(f"Invalid '{field}.size': Expected integer, got {type(size).__name__}")

    @staticmethod
    def _validate_device(field: str, device: Dict[str, Any], errors: List[str]) -> None:
        ip = device.get("ip")
        if ip is not None and not isinstance(ip, str):
            errors.append(f"Invalid '{field}.ip': Expected string, got {type(ip).__name__}")
        port = device.get("port")
        if port is not None and not isinstance(port, (int, float)):
            errors.append(f"Invalid '{field}.port': Expected integer, got {type(port).__name__}")

