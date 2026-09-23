import sys
import os

# Add src to python path so it can find models.py and adapters
sys.path.append(os.path.abspath("ocsf_normalizer/src"))

from adapters.splunk_adapter import SplunkOCSFAdapter

# Mock Splunk CIM Authentication Event
mock_splunk_event = {
    "_time": 1713600000,
    "sourcetype": "WinEventLog:Security",
    "action": "success",
    "user": "jdoe",
    "src": "10.0.0.15",
    "dest": "10.0.0.1",
    "app": "win:local"
}

print("--- Testing Splunk Schema Detection ---")
is_splunk = SplunkOCSFAdapter.is_splunk_payload(mock_splunk_event)
print(f"Is Splunk Payload? -> {is_splunk}")

if is_splunk:
    print("\n--- Normalizing Splunk Payload to OCSF ---")
    ocsf_event = SplunkOCSFAdapter.map_to_ocsf(mock_splunk_event)
    print("🟢 Normalization Successful!")
    print(f"Target User Name: {ocsf_event.user.name}")
    print(f"Actor Name: {ocsf_event.actor.user.name}")
    print(f"Device IP: {ocsf_event.device.ip}")
    print(f"Status ID: {ocsf_event.status_id}")
    print(f"OCSF Class UID: {ocsf_event.class_uid}")