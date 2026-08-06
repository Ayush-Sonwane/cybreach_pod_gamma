import json
from src.detector import OCSFNormalizerPipeline
from src.validator import OCSFValidator

if __name__ == "__main__":
    pipeline = OCSFNormalizerPipeline()

    print("=== 1. Testing Pipeline Auto-Validation ===")
    valid_raw_log = {
        "TimeGenerated": "2026-08-06T10:30:00Z",
        "SrcIpAddr": "10.0.0.5",
        "DstIpAddr": "172.16.0.1",
        "DstPortNumber": 80,
        "EventVendor": "Microsoft",
        "EventProduct": "Defender"
    }

    event, is_valid, errors = pipeline.process(valid_raw_log)
    print(f"Pipeline Process Output -> Valid: {is_valid} | Errors: {errors}")

    print("\n=== 2. Testing Direct Validator with Malformed Payload ===")
    # Intentionally malformed payload (missing time & endpoints)
    malformed_event = {
        "class_uid": 4001,
        "category_uid": 4,
        # Missing 'time'
        # Missing 'src_endpoint' and 'dst_endpoint'
    }

    is_valid, errors = OCSFValidator.validate_event(malformed_event)
    print(f"Malformed Event Valid: {is_valid}")
    print(f"Validation Errors Detected: {errors}")