import logging
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from app.cache import get_cached_schema, set_cached_schema
from app.models.custom_ocsf_class import CustomOcsfClass

logger = logging.getLogger(__name__)

def fetch_schema(db: Session, org_id: str, class_uid: int) -> Optional[Dict[str, Any]]:
    """
    Retrieves OCSF class schema from Redis cache.
    Falls back to PostgreSQL if cache miss occurs and updates cache.
    """
    schema = get_cached_schema(org_id, class_uid)
    if schema:
        return schema

    logger.info(f"Cache miss for org_id={org_id}, class_uid={class_uid}. Querying DB...")
    db_obj = db.query(CustomOcsfClass).filter(
        CustomOcsfClass.organization_id == org_id,
        CustomOcsfClass.class_uid == class_uid
    ).first()

    if not db_obj:
        return None

    schema_data = {
        "organization_id": db_obj.organization_id,
        "class_uid": db_obj.class_uid,
        "class_name": db_obj.class_name,
        "category_uid": db_obj.category_uid,
        "attributes": db_obj.attributes,
        "version": db_obj.version
    }
    set_cached_schema(org_id, class_uid, schema_data)
    return schema_data


def normalize_log(db: Session, org_id: str, class_uid: int, raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transforms raw incoming log data into standardized OCSF format based on defined schema attributes.
    """
    schema = fetch_schema(db, org_id, class_uid)
    if not schema:
        raise ValueError(f"Schema not found for org_id '{org_id}' and class_uid {class_uid}")

    expected_attributes = schema.get("attributes", {})
    normalized_attributes = {}

    # Map matching attributes from raw payload to schema
    for key, val in raw_payload.items():
        if key in expected_attributes or key in ["severity", "sender_email", "src_ip", "dst_ip", "user"]:
            normalized_attributes[key] = val
        else:
            # Place unmapped fields under standard OCSF unmapped_data container
            normalized_attributes.setdefault("unmapped_data", {})[key] = val

    normalized_event = {
        "organization_id": org_id,
        "class_uid": schema["class_uid"],
        "class_name": schema["class_name"],
        "category_uid": schema["category_uid"],
        "version": schema.get("version", 1),
        "attributes": normalized_attributes,
        "status": "NORMALIZED"
    }

    return normalized_event