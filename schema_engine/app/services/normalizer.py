import json
from typing import Dict, Any, Tuple, Set
from sqlalchemy.orm import Session
from app.models.custom_ocsf_class import CustomOcsfClass

# Import Redis client (with fallback if unavailable)
try:
    from app.redis import redis_client
except ImportError:
    redis_client = None

# Base OCSF attributes present across standard logs
BASE_OCSF_ATTRIBUTES: Set[str] = {
    "class_uid", "activity_id", "severity_id", "status_id", 
    "src_ip", "dst_ip", "user_name", "user_id", "email_addr", 
    "status", "action", "severity"
}

# Mapping rules from nested raw paths to standard OCSF fields
FIELD_MAPPING_RULES: Dict[str, str] = {
    # Network objects
    "network.connection_info.src_ip": "src_ip",
    "network.connection_info.dst_ip": "dst_ip",
    "network.src_ip": "src_ip",
    "network.dst_ip": "dst_ip",
    "source.ip": "src_ip",
    "destination.ip": "dst_ip",
    # Actor / User objects
    "actor.user.name": "user_name",
    "actor.user.id": "user_id",
    "actor.user.email": "email_addr",
    "user.name": "user_name",
    # Event objects
    "event.outcome": "status",
    "event.action": "action",
    "device.ip": "dst_ip"
}


def unflatten_dict(nested_dict: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
    """
    Recursively flattens nested JSON objects into dot-separated keys.
    """
    items = []
    for key, value in nested_dict.items():
        new_key = f"{parent_key}{sep}{key}" if parent_key else key
        if isinstance(value, dict):
            items.extend(unflatten_dict(value, new_key, sep=sep).items())
        else:
            items.append((new_key, value))
    return dict(items)


def process_nested_mappings(raw_payload: Dict[str, Any], schema_attributes: Set[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Flattens raw payload and extracts valid OCSF keys based on dynamic schema rules.
    """
    flat_payload = unflatten_dict(raw_payload)
    normalized_data: Dict[str, Any] = {}
    unmapped_data: Dict[str, Any] = {}

    for raw_key, value in flat_payload.items():
        target_key = FIELD_MAPPING_RULES.get(raw_key, raw_key)
        leaf_key = raw_key.split('.')[-1]

        if target_key in schema_attributes:
            normalized_data[target_key] = value
        elif leaf_key in schema_attributes:
            normalized_data[leaf_key] = value
        else:
            unmapped_data[raw_key] = value

    return normalized_data, unmapped_data


def get_schema_attributes_cached(db: Session, org_id: str, class_uid: int) -> Set[str]:
    """
    Checks Redis cache first. On miss, queries PostgreSQL DB and caches the result.
    """
    cache_key = f"ocsf:schema:{org_id}:{class_uid}"
    
    # 1. Check Redis cache
    if redis_client:
        try:
            cached_data = redis_client.get(cache_key)
            if cached_data:
                attributes_list = json.loads(cached_data)
                return set(attributes_list)
        except Exception:
            pass

    # 2. Database query fallback
    schema_attributes = set(BASE_OCSF_ATTRIBUTES)

    custom_class = db.query(CustomOcsfClass).filter(
        CustomOcsfClass.organization_id == org_id,
        CustomOcsfClass.class_uid == class_uid
    ).first()

    if custom_class and custom_class.attributes:
        if isinstance(custom_class.attributes, list):
            schema_attributes.update(custom_class.attributes)
        elif isinstance(custom_class.attributes, dict):
            schema_attributes.update(custom_class.attributes.keys())

    # 3. Store result in Redis cache (1 hour TTL)
    if redis_client:
        try:
            redis_client.setex(cache_key, 3600, json.dumps(list(schema_attributes)))
        except Exception:
            pass

    return schema_attributes


def normalize_log(db: Session, org_id: str, class_uid: int, raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main normalizer entry point with input validation and error handling.
    """
    # Defensive Input Validation
    if not isinstance(raw_payload, dict) or not raw_payload:
        return {
            "organization_id": org_id,
            "class_uid": class_uid,
            "status": "failed",
            "error": "Payload must be a non-empty JSON object",
            "normalized_data": {"class_uid": class_uid},
            "unmapped_data": {}
        }
        
    if not org_id or not isinstance(class_uid, int):
        return {
            "organization_id": org_id,
            "class_uid": class_uid,
            "status": "failed",
            "error": "Invalid organization_id or class_uid",
            "normalized_data": {},
            "unmapped_data": {}
        }

    # Fetch schema & normalize
    schema_attributes = get_schema_attributes_cached(db, org_id, class_uid)
    normalized_data, unmapped_data = process_nested_mappings(raw_payload, schema_attributes)
    normalized_data["class_uid"] = class_uid

    return {
        "organization_id": org_id,
        "class_uid": class_uid,
        "status": "success",
        "normalized_data": normalized_data,
        "unmapped_data": unmapped_data
    }