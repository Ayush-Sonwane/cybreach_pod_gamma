from typing import Dict, Any, Tuple, List

class OCSFValidator:
    """
    Validates normalized JSON payloads against core OCSF 1.1.0 schema requirements.
    """

    # Core mandatory fields required across all OCSF event classes
    MANDATORY_BASE_FIELDS = ["class_uid", "category_uid", "time"]

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

        # 3. Class-specific validation rules
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

        # 4. Final Verdict
        is_valid = len(errors) == 0
        return is_valid, errors