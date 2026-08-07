# tests/test_adapters.py
import json
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from src.normalizer.base import BaseNormalizer as OCSFNormalizer
from src.models.ocsf_objects import User, Endpoint


class TestAdapters(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.normalizer = OCSFNormalizer()

    def normalize(self, payload):
        return self.normalizer.process_log(payload)

    def test_qradar(self):
        payload = {
            "starttime": 1711920000000,
            "sourceip": "10.0.0.15",
            "destinationip": "192.168.1.1",
            "sourceport": 61234,
            "username": "qradar_admin",
            "action": "login",
            "status": "failure",
            "magnitude": 8,
        }
        event = self.normalize(payload)
        self.assertEqual(event.class_uid, 3001)
        self.assertEqual(event.status_id, 2)
        self.assertIsInstance(event.user, User)
        self.assertEqual(event.user.name, "qradar_admin")
        self.assertIsInstance(event.src_endpoint, Endpoint)
        self.assertEqual(event.src_endpoint.ip, "10.0.0.15")
        self.assertEqual(event.src_endpoint.port, 61234)
        self.assertEqual(event.dst_endpoint.ip, "192.168.1.1")

    def test_logscale(self):
        payload = {
            "@timestamp": "2026-08-07T08:00:00.000Z",
            "aip": "172.16.10.5",
            "endpoint_ip": "10.0.0.1",
            "user": "logscale_user",
            "event_type": "user_login",
            "status": "success",
            "loglevel": "info",
        }
        event = self.normalize(payload)
        self.assertEqual(event.class_uid, 3001)
        self.assertEqual(event.status_id, 1)
        self.assertIsInstance(event.user, User)
        self.assertEqual(event.user.name, "logscale_user")
        self.assertEqual(event.src_endpoint.ip, "172.16.10.5")
        self.assertEqual(event.dst_endpoint.ip, "10.0.0.1")

    def test_splunk(self):
        payload = {
            "_time": 1711920000,
            "src_ip": "192.168.1.50",
            "dest_ip": "10.0.0.1",
            "user": "splunk_user",
            "action": "login",
            "status": "success",
            "vendor_severity": "informational",
        }
        event = self.normalize(payload)
        self.assertEqual(event.class_uid, 3002)
        self.assertEqual(event.status_id, 1)
        self.assertIsInstance(event.user, User)
        self.assertEqual(event.user.name, "splunk_user")
        self.assertEqual(event.src_endpoint.ip, "192.168.1.50")
        self.assertEqual(event.dst_endpoint.ip, "10.0.0.1")

    def test_sentinel_asim(self):
        payload = {
            "TimeGenerated": "2026-08-07T08:00:00.000Z",
            "SrcIpAddr": "10.1.1.20",
            "TargetIpAddr": "10.0.0.1",
            "TargetUsername": "sentinel_admin",
            "EventResult": "Success",
            "SeverityLevel": "Low",
        }
        event = self.normalize(payload)
        self.assertEqual(event.class_uid, 3002)
        self.assertEqual(event.status_id, 1)
        self.assertIsInstance(event.user, User)
        self.assertEqual(event.user.name, "sentinel_admin")
        self.assertEqual(event.src_endpoint.ip, "10.1.1.20")
        self.assertEqual(event.dst_endpoint.ip, "10.0.0.1")

    def test_ecs(self):
        payload = {
            "@timestamp": "2026-08-07T08:00:00.000Z",
            "source": {"ip": "192.168.10.12", "port": 61234},
            "destination": {"ip": "10.0.0.1", "port": 443},
            "user": {"name": "ecs_user", "id": "U-1001"},
            "event": {"outcome": "success", "severity": 2},
            "process": {"pid": 4242, "name": "sshd", "executable": "/usr/sbin/sshd"},
            "file": {"name": "auth.log", "path": "/var/log/auth.log", "size": 8192, "hash": "abc123"},
            "host": {"name": "ecs-host", "hostname": "ecs-host.corp", "ip": ["10.0.0.2"]},
        }
        event = self.normalize(payload)
        self.assertEqual(event.class_uid, 3002)
        self.assertEqual(event.status_id, 1)
        self.assertIsInstance(event.user, User)
        self.assertEqual(event.user.name, "ecs_user")
        self.assertEqual(event.user.uid, "U-1001")
        self.assertEqual(event.src_endpoint.ip, "192.168.10.12")
        self.assertEqual(event.src_endpoint.port, 61234)
        self.assertEqual(event.dst_endpoint.ip, "10.0.0.1")
        self.assertEqual(event.dst_endpoint.port, 443)
        self.assertIsNotNone(event.process)
        self.assertEqual(event.process.pid, 4242)
        self.assertEqual(event.process.name, "sshd")
        self.assertIsNotNone(event.file)
        self.assertEqual(event.file.name, "auth.log")
        self.assertEqual(event.file.hashes.sha256, "abc123")
        self.assertIsNotNone(event.device)
        self.assertEqual(event.device.name, "ecs-host")


def run_tests():
    """Manual runner (prints each vendor normalization for visual inspection)."""
    normalizer = OCSFNormalizer()

    qradar_payload = {
        "starttime": 1711920000000,
        "sourceip": "10.0.0.15",
        "destinationip": "192.168.1.1",
        "sourceport": 61234,
        "username": "qradar_admin",
        "action": "login",
        "status": "failure",
        "magnitude": 8,
    }

    logscale_payload = {
        "@timestamp": "2026-08-07T08:00:00.000Z",
        "aip": "172.16.10.5",
        "endpoint_ip": "10.0.0.1",
        "user": "logscale_user",
        "event_type": "user_login",
        "status": "success",
        "loglevel": "info",
    }

    splunk_payload = {
        "_time": 1711920000,
        "src_ip": "192.168.1.50",
        "dest_ip": "10.0.0.1",
        "user": "splunk_user",
        "action": "login",
        "status": "success",
        "vendor_severity": "informational",
    }

    sentinel_payload = {
        "TimeGenerated": "2026-08-07T08:00:00.000Z",
        "SrcIpAddr": "10.1.1.20",
        "TargetIpAddr": "10.0.0.1",
        "TargetUsername": "sentinel_admin",
        "EventResult": "Success",
        "SeverityLevel": "Low",
    }

    ecs_payload = {
        "@timestamp": "2026-08-07T08:00:00.000Z",
        "source": {"ip": "192.168.10.12", "port": 61234},
        "destination": {"ip": "10.0.0.1", "port": 443},
        "user": {"name": "ecs_user", "id": "U-1001"},
        "event": {"outcome": "success", "severity": 2},
        "process": {"pid": 4242, "name": "sshd", "executable": "/usr/sbin/sshd"},
        "file": {"name": "auth.log", "path": "/var/log/auth.log", "size": 8192, "hash": "abc123"},
        "host": {"name": "ecs-host", "hostname": "ecs-host.corp", "ip": ["10.0.0.2"]},
    }

    test_cases = [
        ("IBM QRadar", qradar_payload),
        ("CrowdStrike LogScale", logscale_payload),
        ("Splunk CIM", splunk_payload),
        ("MS Sentinel ASIM", sentinel_payload),
        ("Elastic ECS", ecs_payload),
    ]

    print("==================================================")
    print("      RUNNING POD GAMMA ALL-ADAPTER TESTS         ")
    print("==================================================\n")

    for vendor_name, payload in test_cases:
        print(f"=== Testing {vendor_name} Normalization ===")
        try:
            ocsf_event = normalizer.process_log(payload)
            print(json.dumps(ocsf_event.model_dump(), indent=2))
            print("✅ Status: SUCCESS\n")
        except Exception as e:
            print(f"❌ Status: FAILED - {str(e)}\n")


if __name__ == "__main__":
    run_tests()

