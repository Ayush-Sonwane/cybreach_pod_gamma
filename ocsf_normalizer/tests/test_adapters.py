import json
from src.adapters.asim_adapter import AsimAdapter
from src.adapters.ecs_adapter import EcsAdapter
from src.adapters.splunk_adapter import SplunkOCSFAdapter

if __name__ == "__main__":
    asim = AsimAdapter()
    ecs = EcsAdapter()
    splunk = SplunkOCSFAdapter()

    # 1. Sample ASIM Network Event
    asim_raw = {
        "TimeGenerated": "2026-08-06T10:30:00Z",
        "SrcIpAddr": "192.168.1.100",
        "SrcPortNumber": 54321,
        "DstIpAddr": "10.0.0.1",
        "DstPortNumber": 443,
        "NetworkProtocol": "tcp",
        "EventResult": "Success",
        "EventVendor": "PaloAlto",
        "EventProduct": "PAN-OS"
    }

    # 2. Sample ECS Network Event
    ecs_raw = {
        "@timestamp": "2026-08-06T10:30:00Z",
        "source": {"ip": "192.168.1.100", "port": 54321},
        "destination": {"ip": "10.0.0.1", "port": 443},
        "network": {"transport": "tcp"},
        "event": {"outcome": "success"},
        "observer": {"vendor": "Elastic", "product": "Fleet"}
    }

    # 3. Sample Splunk CIM Authentication Event
    splunk_raw = {
        "_time": 1785983400,
        "action": "success",
        "user": "admin_user",
        "src_ip": "192.168.1.100",
        "sourcetype": "winlogevent"
    }

    print("--- ASIM -> OCSF Output ---")
    print(json.dumps(asim.transform_network_session(asim_raw), indent=2))

    print("\n--- ECS -> OCSF Output ---")
    print(json.dumps(ecs.transform_network_session(ecs_raw), indent=2))

    print("\n--- SPLUNK -> OCSF Output ---")
    # Using map_to_ocsf and converting Pydantic model to dict for JSON serialization
    splunk_ocsf_model = splunk.map_to_ocsf(splunk_raw)
    print(json.dumps(splunk_ocsf_model.model_dump(), indent=2))