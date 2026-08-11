import sys
import os

# Set up module import paths
base_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(base_dir, "ocsf_normalizer", "src"))
sys.path.append(os.path.join(base_dir, "revalidation_service", "src"))

from models import OCSFAuthenticationModel

# Sample payload following the windows_auth schema mapping
test_payload = {
    "activity_id": 1,
    "category_uid": 1,
    "class_uid": 1001,
    "severity_id": 1,
    "status_id": 1,
    "time": 1711920000000,
    "user": {
        "name": "Administrator",
        "uid": "S-1-5-21-1234",
        "domain": "CYBREACH.LOCAL"
    },
    "device": {
        "ip": "192.168.1.50",
        "port": 443
    },
    "actor": {
        "user": {
            "name": "SYSTEM"
        }
    }
}

if __name__ == "__main__":
    try:
        validated_log = OCSFAuthenticationModel(**test_payload)
        print("SUCCESS: Model parsed and validated the payload successfully!")
        print(f"Validated User: {validated_log.user.name}")
        print(f"Validated Device IP: {validated_log.device.ip}")
    except Exception as err:
        print(f"ERROR: Schema validation failed: {err}")
