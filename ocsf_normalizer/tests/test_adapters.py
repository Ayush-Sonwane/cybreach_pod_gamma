# tests/test_adapters.py
import json
from src.normalizer.base import BaseNormalizer as OCSFNormalizer

def run_tests():
    normalizer = OCSFNormalizer()

    # 1. IBM QRadar (AQL Schema) Payload
    qradar_payload = {
        "starttime": 1711920000000,
        "sourceip": "10.0.0.15",
        "destinationip": "192.168.1.1",
        "sourceport": 61234,
        "username": "qradar_admin",
        "action": "login",
        "status": "failure",
        "magnitude": 8
    }

    # 2. CrowdStrike LogScale (LQL Schema) Payload
    logscale_payload = {
        "@timestamp": "2026-08-07T08:00:00.000Z",
        "aip": "172.16.10.5",
        "endpoint_ip": "10.0.0.1",
        "user": "logscale_user",
        "event_type": "user_login",
        "status": "success",
        "loglevel": "info"
    }

    # 3. Splunk (CIM Schema) Payload
    splunk_payload = {
        "_time": 1711920000,
        "src_ip": "192.168.1.50",
        "dest_ip": "10.0.0.1",
        "user": "splunk_user",
        "action": "login",
        "status": "success",
        "vendor_severity": "informational"
    }

    # 4. Microsoft Sentinel (ASIM Schema) Payload
    sentinel_payload = {
        "TimeGenerated": "2026-08-07T08:00:00.000Z",
        "SrcIpAddr": "10.1.1.20",
        "TargetIpAddr": "10.0.0.1",
        "TargetUsername": "sentinel_admin",
        "EventResult": "Success",
        "SeverityLevel": "Low"
    }

    # 5. Elastic (ECS Schema) Payload
    ecs_payload = {
        "@timestamp": "2026-08-07T08:00:00.000Z",
        "source.ip": "192.168.10.12",
        "destination.ip": "10.0.0.1",
        "user.name": "ecs_user",
        "event.outcome": "success",
        "event.severity": 2
    }

    test_cases = [
        ("IBM QRadar", qradar_payload),
        ("CrowdStrike LogScale", logscale_payload),
        ("Splunk CIM", splunk_payload),
        ("MS Sentinel ASIM", sentinel_payload),
        ("Elastic ECS", ecs_payload)
    ]

    print("==================================================")
    print("      RUNNING POD GAMMA ALL-ADAPTER TESTS         ")
    print("==================================================\n")

    for vendor_name, payload in test_cases:
        print(f"=== Testing {vendor_name} Normalization ===")
        try:
            ocsf_event = normalizer.process_log(payload)  # Use process_log or process_raw_log depending on method name in base.py
            print(json.dumps(ocsf_event.model_dump(), indent=2))
            print("✅ Status: SUCCESS\n")
        except Exception as e:
            print(f"❌ Status: FAILED - {str(e)}\n")

if __name__ == "__main__":
    run_tests()