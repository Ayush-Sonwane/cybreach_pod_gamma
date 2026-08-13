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

        # 3. Generic Webhook Rules (custom SIEM solutions)
        #    Requires an event descriptor plus a timestamp key. Placed after
        #    the vendor-specific rules so it does not shadow them, but before
        #    the Splunk rule (webhook payloads may also carry src_ip/dest_ip).
        if (("event_type" in keys or "event_name" in keys or "event_id" in keys)
                and any(k in keys for k in ("timestamp", "event_time", "occurred_at", "@timestamp", "datetime"))):
            return "webhook"

        # 4. Splunk CIM Rules
        if "vendor_severity" in keys or "src_ip" in keys or "dest_ip" in keys:
            return "splunk"

        # 4. MS Sentinel ASIM Rules
        if "SrcIpAddr" in keys or "TargetUsername" in keys or "TimeGenerated" in keys:
            return "sentinel"

        # 5. Elastic ECS Rules
        #    5a. Dotted-prefix keys (e.g. "source.ip", "event.outcome")
        if any(k.startswith("source.") or k.startswith("event.") for k in keys):
            return "ecs"
        #    5b. Nested ECS object keys (e.g. {"source": {...}, "event": {...}})
        ecs_nested_indicators = {"source", "destination", "event", "process", "host", "observer"}
        if keys.intersection(ecs_nested_indicators) and ("@timestamp" in keys or "timestamp" in keys):
            return "ecs"

        return "unknown"


class OCSFNormalizerPipeline:
    """Compatibility wrapper around the package normalizer pipeline."""

    def __init__(self):
        from src.normalizer.base import BaseNormalizer

        self.normalizer = BaseNormalizer()

    def process_log(self, raw_payload: Dict[str, Any]) -> Dict[str, Any]:
        return self.normalizer.process_log(raw_payload)

    def normalize(self, raw_payload: Dict[str, Any]) -> Dict[str, Any]:
        return self.process_log(raw_payload)

