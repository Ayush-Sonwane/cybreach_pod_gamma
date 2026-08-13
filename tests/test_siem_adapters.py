# tests/test_siem_adapters.py
import pytest
from datetime import datetime
from dataclasses import is_dataclass, asdict

# Import detector and adapter classes from src
from src.detector import SchemaDetector
from src.adapters.splunk_adapter import SplunkAdapter
from src.adapters.qradar_adapter import QRadarAdapter
from src.adapters.asim_adapter import ASIMAdapter
from src.adapters.ecs_adapter import ECSAdapter
from src.adapters.logscale_adapter import LogScaleAdapter


# Helper function to invoke normalize across static methods, class methods, or instance methods
def call_normalize(adapter_cls, log):
    # 1. Try direct static/classmethod calls
    for func in [
        lambda: adapter_cls.normalize(log),
        lambda: adapter_cls.normalize(payload=log),
        lambda: adapter_cls.normalize(raw_event=log),
    ]:
        try:
            res = func()
            if res is not None:
                return res
        except TypeError:
            pass

    # 2. Try instantiating the class first if methods require 'self'
    try:
        instance = adapter_cls()
        for func in [
            lambda: instance.normalize(log),
            lambda: instance.normalize(payload=log),
            lambda: instance.normalize(raw_event=log),
        ]:
            try:
                res = func()
                if res is not None:
                    return res
            except TypeError:
                pass
    except Exception:
        pass

    raise RuntimeError(f"Could not invoke normalize on {adapter_cls}")


# Helper function to convert OCSF objects/dataclasses safely to dict or inspect properties
def get_class_uid(norm_obj):
    # If it's already a dictionary
    if isinstance(norm_obj, dict):
        return norm_obj.get("class_uid") or norm_obj.get("class_id")
    
    # If it's a Dataclass (like OCSFAuthenticationEvent)
    if is_dataclass(norm_obj):
        data = asdict(norm_obj)
        return data.get("class_uid") or data.get("class_id")

    # If it has custom dictionary export methods
    if hasattr(norm_obj, "to_dict"):
        data = norm_obj.to_dict()
        return data.get("class_uid") or data.get("class_id")
    if hasattr(norm_obj, "dict"):
        data = norm_obj.dict()
        return data.get("class_uid") or data.get("class_id")

    # If attributes are directly accessible on the object instance
    if hasattr(norm_obj, "class_uid"):
        return norm_obj.class_uid
    if hasattr(norm_obj, "class_id"):
        return norm_obj.class_id

    raise TypeError(f"Cannot extract class_uid from object type {type(norm_obj)}")


# ============================================================================
# SAMPLE LOG DATASETS (20 LOGS PER SIEM)
# ============================================================================

SPLUNK_LOGS = [
    {"_time": 1785983400 + i, "src_ip": f"10.0.0.{i}", "dest_ip": f"192.168.1.{i}", "vendor_severity": "high" if i % 2 == 0 else "low", "action": "success", "user": f"user_{i}"}
    for i in range(1, 21)
]

QRADAR_LOGS = [
    {"starttime": 1785983400000 + (i * 1000), "sourceip": f"10.0.1.{i}", "destinationip": f"192.168.2.{i}", "magnitude": 8 if i % 2 == 0 else 3, "username": f"admin_{i}", "eventname": "User Login"}
    for i in range(1, 21)
]

SENTINEL_LOGS = [
    {"TimeGenerated": f"2026-08-07T12:{i:02d}:00Z", "SrcIpAddr": f"10.0.2.{i}", "DstIpAddr": f"192.168.3.{i}", "SeverityLevel": "High" if i % 2 == 0 else "Informational", "TargetUsername": f"sentinel_user_{i}"}
    for i in range(1, 21)
]

ECS_LOGS = [
    {
        "@timestamp": f"2026-08-07T14:{i:02d}:00Z",
        "source": {"ip": f"10.0.3.{i}"},
        "destination": {"ip": f"192.168.4.{i}"},
        "event": {"severity": 3 if i % 2 == 0 else 1, "category": ["authentication"]},
        "user": {"name": f"ecs_user_{i}"}
    }
    for i in range(1, 21)
]

LOGSCALE_LOGS = [
    {"@timestamp": 1785983400000 + (i * 1000), "aip": f"10.0.4.{i}", "endpoint": f"192.168.5.{i}", "loglevel": "ERROR" if i % 2 == 0 else "INFO", "user": f"logscale_user_{i}"}
    for i in range(1, 21)
]


# ============================================================================
# 1. SCHEMA DETECTOR TESTS
# ============================================================================

@pytest.mark.parametrize("log", SPLUNK_LOGS)
def test_detect_splunk(log):
    assert SchemaDetector.detect_vendor(log) == "splunk"

@pytest.mark.parametrize("log", QRADAR_LOGS)
def test_detect_qradar(log):
    assert SchemaDetector.detect_vendor(log) == "qradar"

@pytest.mark.parametrize("log", SENTINEL_LOGS)
def test_detect_sentinel(log):
    assert SchemaDetector.detect_vendor(log) == "sentinel"

@pytest.mark.parametrize("log", ECS_LOGS)
def test_detect_ecs(log):
    assert SchemaDetector.detect_vendor(log) == "ecs"

@pytest.mark.parametrize("log", LOGSCALE_LOGS)
def test_detect_logscale(log):
    assert SchemaDetector.detect_vendor(log) == "logscale"


# ============================================================================
# 2. ADAPTER NORMALIZATION TESTS
# ============================================================================

@pytest.mark.parametrize("log", SPLUNK_LOGS)
def test_splunk_normalization(log):
    norm = call_normalize(SplunkAdapter, log)
    assert get_class_uid(norm) in [3001, 3002]

@pytest.mark.parametrize("log", QRADAR_LOGS)
def test_qradar_normalization(log):
    norm = call_normalize(QRadarAdapter, log)
    assert get_class_uid(norm) in [3001, 3002]

@pytest.mark.parametrize("log", SENTINEL_LOGS)
def test_sentinel_normalization(log):
    norm = call_normalize(ASIMAdapter, log)
    assert get_class_uid(norm) in [3001, 3002]

@pytest.mark.parametrize("log", ECS_LOGS)
def test_ecs_normalization(log):
    norm = call_normalize(ECSAdapter, log)
    assert get_class_uid(norm) in [3001, 3002]

@pytest.mark.parametrize("log", LOGSCALE_LOGS)
def test_logscale_normalization(log):
    norm = call_normalize(LogScaleAdapter, log)
    assert get_class_uid(norm) in [3001, 3002]