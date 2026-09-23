"""Unit tests for complex OCSF object builders and typed models."""

import sys
import os
import unittest

# Ensure src is importable when running from repo root or tests/ dir
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from src.models.ocsf_objects import Endpoint, File, Process, User, Device, Actor
from src.normalizer.complex_objects import (
    build_user,
    build_endpoint,
    build_file,
    build_process,
    build_device,
    build_actor,
)


class TestBuildUser(unittest.TestCase):
    def test_basic_user(self):
        raw = {"user_name": "jdoe", "user_sid": "S-1-5-21-123", "user_domain": "CORP"}
        user = build_user(raw, {"name": "user_name", "uid": "user_sid", "domain": "user_domain"})
        self.assertIsInstance(user, User)
        self.assertEqual(user.name, "jdoe")
        self.assertEqual(user.uid, "S-1-5-21-123")
        self.assertEqual(user.domain, "CORP")

    def test_fallback_keys(self):
        raw = {"username": "admin"}
        user = build_user(raw, {"name": ["user", "username"]})
        self.assertIsInstance(user, User)
        self.assertEqual(user.name, "admin")

    def test_none_when_no_user(self):
        raw = {"src_ip": "10.0.0.1"}
        user = build_user(raw, {"name": "user_name"})
        self.assertIsNone(user)

    def test_provenance_recorded(self):
        raw = {"user_name": "jdoe"}
        prov = {}
        build_user(raw, {"name": "user_name"}, prov)
        self.assertIn("mapped.user.name", prov)
        self.assertEqual(prov["mapped.user.name"].original_value, "jdoe")


class TestBuildEndpoint(unittest.TestCase):
    def test_full_endpoint(self):
        raw = {"ip": "10.0.0.1", "port": 443, "hostname": "srv01"}
        ep = build_endpoint(raw, {"ip": "ip", "port": "port", "hostname": "hostname"})
        self.assertIsInstance(ep, Endpoint)
        self.assertEqual(ep.ip, "10.0.0.1")
        self.assertEqual(ep.port, 443)
        self.assertEqual(ep.hostname, "srv01")

    def test_port_coercion(self):
        raw = {"ip": "10.0.0.1", "port": "8080"}
        ep = build_endpoint(raw, {"ip": "ip", "port": "port"})
        self.assertEqual(ep.port, 8080)
        self.assertIsInstance(ep.port, int)

    def test_none_when_empty(self):
        raw = {"src_ip": "x"}
        ep = build_endpoint(raw, {"ip": "ip"})
        self.assertIsNone(ep)


class TestBuildFile(unittest.TestCase):
    def test_basic_file(self):
        raw = {"file_name": "evil.exe", "file_path": "/tmp/evil.exe", "file_size": 1024}
        file = build_file(raw, {"name": "file_name", "path": "file_path", "size": "file_size"})
        self.assertIsInstance(file, File)
        self.assertEqual(file.name, "evil.exe")
        self.assertEqual(file.path, "/tmp/evil.exe")
        self.assertEqual(file.size, 1024)

    def test_file_with_hashes(self):
        raw = {"file_name": "a.exe", "file_sha256": "abc123"}
        file = build_file(
            raw,
            {"name": "file_name", "hashes": {"sha256": "file_sha256"}},
        )
        self.assertIsNotNone(file.hashes)
        self.assertEqual(file.hashes.sha256, "abc123")

    def test_none_when_empty(self):
        raw = {"event": "login"}
        file = build_file(raw, {"name": "file_name"})
        self.assertIsNone(file)


class TestBuildProcess(unittest.TestCase):
    def test_basic_process(self):
        raw = {"pid": 1234, "process_name": "powershell.exe", "process_path": "C:/Windows"}
        proc = build_process(
            raw, {"pid": "pid", "name": "process_name", "path": "process_path"}
        )
        self.assertIsInstance(proc, Process)
        self.assertEqual(proc.pid, 1234)
        self.assertEqual(proc.name, "powershell.exe")
        self.assertEqual(proc.path, "C:/Windows")

    def test_none_when_empty(self):
        raw = {"user": "jdoe"}
        proc = build_process(raw, {"pid": "pid"})
        self.assertIsNone(proc)


class TestBuildDevice(unittest.TestCase):
    def test_basic_device(self):
        raw = {"device_ip": "192.168.1.1", "device_name": "fw01", "device_hostname": "fw01.corp"}
        device = build_device(
            raw, {"ip": "device_ip", "name": "device_name", "hostname": "device_hostname"}
        )
        self.assertIsInstance(device, Device)
        self.assertEqual(device.ip, "192.168.1.1")
        self.assertEqual(device.name, "fw01")
        self.assertEqual(device.hostname, "fw01.corp")

    def test_none_when_empty(self):
        raw = {"event": "login"}
        device = build_device(raw, {"ip": "device_ip"})
        self.assertIsNone(device)


class TestBuildActor(unittest.TestCase):
    def test_basic_actor(self):
        raw = {"actor_username": "system"}
        actor = build_actor(raw, {"user": {"name": "actor_username"}})
        self.assertIsInstance(actor, Actor)
        self.assertIsNotNone(actor.user)
        self.assertEqual(actor.user.name, "system")

    def test_none_when_empty(self):
        raw = {"event": "login"}
        actor = build_actor(raw, {"user": {"name": "actor_username"}})
        self.assertIsNone(actor)


if __name__ == "__main__":
    unittest.main()

