import json
from src.detector import OCSFNormalizerPipeline

if __name__ == "__main__":
    pipeline = OCSFNormalizerPipeline()

    # Stream simulating good logs, unknown format logs, and unparseable logs
    test_stream = [
        # 1. Valid ASIM Log
        {
            "TimeGenerated": "2026-08-06T10:30:00Z",
            "SrcIpAddr": "10.0.0.5",
            "DstIpAddr": "172.16.0.1",
            "DstPortNumber": 80,
            "EventVendor": "Microsoft",
            "EventProduct": "Defender"
        },
        # 2. Unknown Vendor Schema
        {
            "some_random_key": "custom_value",
            "device_name": "unknown_firewall"
        },
        # 3. Valid Splunk CIM Log
        {
            "_time": 1785983400,
            "action": "success",
            "user": "jdoe",
            "src_ip": "10.0.0.25",
            "sourcetype": "linux_secure"
        }
    ]

    print("=== Testing Complete Pipeline with DLQ Routing ===\n")

    for idx, log in enumerate(test_stream, start=1):
        status, result = pipeline.process_event(log)
        print(f"--- Event #{idx} Result: [{status}] ---")
        print(json.dumps(result, indent=2))
        print("\n" + "="*50 + "\n")