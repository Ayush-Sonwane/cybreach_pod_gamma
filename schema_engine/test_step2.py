import uuid
import random
from app.database import SessionLocal
from app.models.custom_ocsf_class import CustomOcsfClass
from app.validator import validate_ocsf_class_payload

# Generate a random class_uid to avoid unique constraint collisions
random_class_uid = random.randint(1002, 9999)

sample_payload = {
    "organization_id": "org_sec_ops_01",
    "class_uid": random_class_uid,
    "class_name": f"Custom Threat Detection {random_class_uid}",
    "category_uid": 1,
    "attributes": {
        "severity": "HIGH",
        "detector": "custom_agent_v1",
        "tags": ["threat_intel", "edr"]
    }
}

# 1. Run Payload Validation
is_valid, err_msg = validate_ocsf_class_payload(sample_payload)
print(f"Validation Result: {is_valid}")

if is_valid:
    db = SessionLocal()
    try:
        # 2. Save Record to PostgreSQL
        new_entry = CustomOcsfClass(**sample_payload)
        db.add(new_entry)
        db.commit()
        db.refresh(new_entry)
        print(f"Successfully inserted record with ID: {new_entry.id}")
        print(f"Stored class_uid: {new_entry.class_uid}")
    except Exception as e:
        db.rollback()
        print(f"Database insertion failed: {e}")
    finally:
        db.close()
else:
    print(f"Validation Error: {err_msg}")
