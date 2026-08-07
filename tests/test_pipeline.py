import json
from src.detector import SchemaDetector

if __name__ == "__main__":
    detector = SchemaDetector()

    # Mixed array simulating an un-tagged real-time log stream
    incoming_log_stream = [
        # Raw ASIM log
        {
            "TimeGenerated": "2026-08-06T10:30:00Z",
            "SrcIpAddr": "10.0.0.5",
            "DstIpAddr": "172.16.0.1",
            "DstPortNumber": 80,
            "EventVendor": "Microsoft",
            "EventProduct": "Defender"
        },
        # Raw Splunk CIM log
        {
            "_time": 1785983400,
            "action": "success",
            "user": "jdoe",
            "src_ip": "10.0.0.25",
            "sourcetype": "linux_secure"
        },
        # Raw ECS log
        {
            "@timestamp": "2026-08-06T10:30:00Z",
            "source": {"ip": "192.168.1.50", "port": 12345},
            "destination": {"ip": "8.8.8.8", "port": 53},
            "network": {"transport": "udp"},
            "observer": {"vendor": "Elastic", "product": "Packetbeat"}
        }
    ]

    print("=== Processing Live Stream via Auto-Detection Pipeline ===\n")
    for index, raw_log in enumerate(incoming_log_stream, start=1):
        detected_vendor = detector.detect_vendor(raw_log)
        print(f"--- Processed Event #{index} (Detected Vendor: {detected_vendor}) ---")
        print(json.dumps(raw_log, indent=2))
        print("\n" + "="*50 + "\n")