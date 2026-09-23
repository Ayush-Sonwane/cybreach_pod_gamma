# src/detector.py
from typing import Dict, Any

class SchemaDetector:
    """Stage 1: Identifies the incoming vendor log schema based on signature keys."""

    @staticmethod
    def detect_vendor(raw_event: Dict[str, Any]) -> str:
        keys = set(raw_event.keys())

        # 1. QRadar Detection Rules
        if {"magnitude", "sourceip"}.issubset(keys) or "starttime" in keys:
            return "qradar"

        # 2. LogScale Detection Rules
        if "@timestamp" in keys and ("aip" in keys or "loglevel" in keys):
            return "logscale"

        # 3. Splunk CIM Rules
        if "vendor_severity" in keys or "src_ip" in keys:
            return "splunk"

        # 4. MS Sentinel ASIM Rules
        if "SrcIpAddr" in keys or "TargetUsername" in keys or "TimeGenerated" in keys:
            return "sentinel"

        # 5. Elastic ECS Rules (Supports both flat keys 'source.ip' and nested dicts 'source': {})
        ecs_signature_keys = {"source", "destination", "observer", "network", "event"}
        if any(k.startswith("source.") or k.startswith("event.") for k in keys) or ("@timestamp" in keys and ecs_signature_keys.intersection(keys)):
            return "ecs"

        return "unknown"


if __name__ == "__main__":
    detector = SchemaDetector()
    
    # Quick Test 1: Splunk Log
    sample_splunk = {"_time": 1785983400, "src_ip": "10.0.0.25"}
    result_splunk = detector.detect_vendor(sample_splunk)
    print(f"Vendor Detection Test (Splunk)  -> Detected: {result_splunk}")

    # Quick Test 2: Nested ECS Log (Resolves Issue #6)
    sample_ecs = {
        "@timestamp": "2026-08-06T10:30:00Z",
        "source": {"ip": "192.168.1.50"},
        "observer": {"vendor": "Elastic"}
    }
    result_ecs = detector.detect_vendor(sample_ecs)
    print(f"Vendor Detection Test (Elastic) -> Detected: {result_ecs}")