from typing import Dict, Any, Tuple, Optional

REQUIRED_FIELDS = ["organization_id", "class_uid", "class_name", "category_uid", "attributes"]

def validate_ocsf_class_payload(data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Validates the incoming payload for creating or updating a Custom OCSF Class.
    Enforces custom UID range rules (class_uid >= 9000).
    """
    # 1. Check for missing required fields
    for field in REQUIRED_FIELDS:
        if field not in data or data[field] is None:
            return False, f"Missing required field: '{field}'"

    # 2. Validate Data Types
    if not isinstance(data["organization_id"], str) or not data["organization_id"].strip():
        return False, "'organization_id' must be a non-empty string"

    if not isinstance(data["class_uid"], int):
        return False, "'class_uid' must be an integer"

    # 3. Enforce Custom UID Range Rule (UID >= 9000)
    if data["class_uid"] < 9000:
        return False, "'class_uid' must be >= 9000 (reserved for custom extensions)"

    if not isinstance(data["class_name"], str) or not data["class_name"].strip():
        return False, "'class_name' must be a non-empty string"

    if not isinstance(data["category_uid"], int) or data["category_uid"] <= 0:
        return False, "'category_uid' must be a positive integer"

    if not isinstance(data["attributes"], dict):
        return False, "'attributes' must be a JSON object (dictionary)"

    return True, None