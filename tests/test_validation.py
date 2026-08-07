import json
from src.detector import SchemaDetector
from src.validator import OCSFValidator

if __name__ == "__main__":
    detector = SchemaDetector()

    print("=== 1. Testing Pipeline Auto-Validation ===")
    valid_raw_log = {
        "TimeGenerated": "2026-08-06T10:30:00Z",
        "SrcIpAddr": "10.0.0.5",
        "DstIpAddr": "172.16.0.1",
        "DstPortNumber": 80,
        "EventVendor": "Microsoft",
        "EventProduct": "Defender"
    }

    vendor = detector.detect_vendor(valid_raw_log)
    is_valid, errors = OCSFValidator.validate_event(valid_raw_log)

    print(f"Detected Vendor: {vendor}")
    print(f"Pipeline Process Output -> Valid: {is_valid} | Errors: {errors}")

    print("\n=== 2. Testing Direct Validator with Malformed Payload ===")
    malformed_event = {
        "class_uid": 4001,
        "category_uid": 4,
    }

    is_valid, errors = OCSFValidator.validate_event(malformed_event)
    print(f"Malformed Event Valid: {is_valid}")
    print(f"Validation Errors Detected: {errors}")