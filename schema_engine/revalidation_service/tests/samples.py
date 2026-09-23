"""Shared sample events for Re-Validation Service tests."""
from src.core.contracts import EventSnapshot
from src.service.scoring import build_snapshot

EVENT_ID = "auth-0001"
VENDOR = "splunk"

FLAWED_EVENT = {
    "class_uid": 3002,
    "category_uid": 3,
    "activity_id": 1,
    "time": 1700000000000,
    "severity_id": 1,
    "status_id": 99,
    "actor": {"user": {"name": "alice"}},
    "metadata": {
        "version": "1.0.0",
        "product": {"name": "Splunk Enterprise", "vendor_name": "Splunk"},
        "provenance": [],
    },
}

FIXED_EVENT = {
    "class_uid": 3002,
    "category_uid": 3,
    "activity_id": 1,
    "time": 1700000000000,
    "severity_id": 4,
    "status_id": 1,
    "actor": {"user": {"name": "alice"}},
    "src_endpoint": {"ip": "10.0.0.1"},
    "dst_endpoint": {"ip": "10.0.0.2"},
    "metadata": {
        "version": "1.1.0",
        "product": {"name": "Splunk Enterprise", "vendor_name": "Splunk"},
        "provenance": [
            {"ocsf_field": "time", "raw_field": "_time"},
            {"ocsf_field": "severity_id", "raw_field": "vendor_severity"},
            {"ocsf_field": "status_id", "raw_field": "action"},
            {"ocsf_field": "actor.user.name", "raw_field": "user"},
            {"ocsf_field": "src_endpoint.ip", "raw_field": "src_ip"},
            {"ocsf_field": "dst_endpoint.ip", "raw_field": "dest_ip"},
        ],
    },
}

INVALID_EVENT = {
    "category_uid": 3,
    "time": "not-a-timestamp",
    "severity_id": "high",
}


def flawed_snapshot() -> EventSnapshot:
    return build_snapshot(EVENT_ID, VENDOR, FLAWED_EVENT)


def fixed_snapshot() -> EventSnapshot:
    return build_snapshot(EVENT_ID, VENDOR, FIXED_EVENT)