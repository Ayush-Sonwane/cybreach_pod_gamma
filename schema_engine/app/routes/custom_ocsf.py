from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.custom_ocsf_class import CustomOcsfClass
from app.validator import validate_ocsf_class_payload
from app.cache import get_cached_schema, set_cached_schema, invalidate_cached_schema

router = APIRouter(
    prefix="/api/v2/ocsf",
    tags=["Custom OCSF Classes"]
)


@router.post("/classes", status_code=status.HTTP_201_CREATED)
def create_custom_ocsf_class(payload: dict, db: Session = Depends(get_db)):
    is_valid, err_msg = validate_ocsf_class_payload(payload)
    if not is_valid:
        raise HTTPException(status_code=400, detail=err_msg)

    existing_entry = db.query(CustomOcsfClass).filter(
        CustomOcsfClass.organization_id == payload["organization_id"],
        CustomOcsfClass.class_uid == payload["class_uid"]
    ).first()

    if existing_entry:
        raise HTTPException(
            status_code=409,
            detail=f"Class with UID {payload['class_uid']} already exists for organization '{payload['organization_id']}'"
        )

    new_class = CustomOcsfClass(**payload)
    db.add(new_class)
    db.commit()
    db.refresh(new_class)

    # Populate cache immediately upon creation
    schema_dict = {
        "organization_id": new_class.organization_id,
        "class_uid": new_class.class_uid,
        "class_name": new_class.class_name,
        "category_uid": new_class.category_uid,
        "attributes": new_class.attributes,
        "version": new_class.version
    }
    set_cached_schema(new_class.organization_id, new_class.class_uid, schema_dict)

    return new_class


@router.get("/classes")
def list_custom_ocsf_classes(organization_id: str, db: Session = Depends(get_db)):
    return db.query(CustomOcsfClass).filter(
        CustomOcsfClass.organization_id == organization_id
    ).all()


@router.get("/classes/{class_uid}")
def get_custom_ocsf_class(class_uid: int, organization_id: str, db: Session = Depends(get_db)):
    # 1. Attempt fast lookup from Redis
    cached_data = get_cached_schema(organization_id, class_uid)
    if cached_data:
        return {**cached_data, "source": "cache"}

    # 2. Cache miss: Query PostgreSQL database
    ocsf_class = db.query(CustomOcsfClass).filter(
        CustomOcsfClass.organization_id == organization_id,
        CustomOcsfClass.class_uid == class_uid
    ).first()

    if not ocsf_class:
        raise HTTPException(
            status_code=404,
            detail=f"Class UID {class_uid} not found for organization '{organization_id}'"
        )

    # 3. Cache the retrieved result for subsequent requests
    schema_dict = {
        "organization_id": ocsf_class.organization_id,
        "class_uid": ocsf_class.class_uid,
        "class_name": ocsf_class.class_name,
        "category_uid": ocsf_class.category_uid,
        "attributes": ocsf_class.attributes,
        "version": ocsf_class.version
    }
    set_cached_schema(organization_id, class_uid, schema_dict)

    return {**schema_dict, "source": "database"}


@router.put("/classes/{class_uid}")
def update_custom_ocsf_class(class_uid: int, payload: dict, db: Session = Depends(get_db)):
    payload["class_uid"] = class_uid
    is_valid, err_msg = validate_ocsf_class_payload(payload)
    if not is_valid:
        raise HTTPException(status_code=400, detail=err_msg)

    ocsf_class = db.query(CustomOcsfClass).filter(
        CustomOcsfClass.organization_id == payload["organization_id"],
        CustomOcsfClass.class_uid == class_uid
    ).first()

    if not ocsf_class:
        raise HTTPException(
            status_code=404,
            detail=f"Class UID {class_uid} not found for organization '{payload['organization_id']}'"
        )

    for key, value in payload.items():
        setattr(ocsf_class, key, value)

    ocsf_class.version += 1
    db.commit()
    db.refresh(ocsf_class)

    # Update cache with new schema version
    schema_dict = {
        "organization_id": ocsf_class.organization_id,
        "class_uid": ocsf_class.class_uid,
        "class_name": ocsf_class.class_name,
        "category_uid": ocsf_class.category_uid,
        "attributes": ocsf_class.attributes,
        "version": ocsf_class.version
    }
    set_cached_schema(ocsf_class.organization_id, ocsf_class.class_uid, schema_dict)

    return ocsf_class


@router.delete("/classes/{class_uid}", status_code=status.HTTP_204_NO_CONTENT)
def delete_custom_ocsf_class(class_uid: int, organization_id: str, db: Session = Depends(get_db)):
    ocsf_class = db.query(CustomOcsfClass).filter(
        CustomOcsfClass.organization_id == organization_id,
        CustomOcsfClass.class_uid == class_uid
    ).first()

    if not ocsf_class:
        raise HTTPException(
            status_code=404,
            detail=f"Class UID {class_uid} not found for organization '{organization_id}'"
        )

    db.delete(ocsf_class)
    db.commit()

    # Evict deleted schema from Redis cache
    invalidate_cached_schema(organization_id, class_uid)
    return None