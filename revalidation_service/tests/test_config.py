# revalidation_service/tests/test_config.py
"""Contract tests for the canonical message-bus names (plan Section 5, P5).

Pod Gamma declares the topic names so all four pods read them from one place,
and so the broker is injected rather than hardcoded to `localhost:9092`.
"""
import importlib
import os
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SERVICE_ROOT))

from src.core import config as config_module  # noqa: E402


def _reload_with_env(monkeypatch, **env):
    for key in (
        "KAFKA_TOPIC_EVIDENCE",
        "KAFKA_TOPIC_VERDICTS",
        "KAFKA_TOPIC_GAP_CLOSED",
        "KAFKA_TOPIC_REVALIDATION",
        "KAFKA_TOPIC_CONNECTOR_HEALTH",
        "KAFKA_BOOTSTRAP_SERVERS",
    ):
        monkeypatch.delenv(key, raising=False)

    for key, value in env.items():
        monkeypatch.setenv(key, value)

    return importlib.reload(config_module)


class TestCanonicalTopics:
    def test_default_topics_match_the_plan(self, monkeypatch):
        config = _reload_with_env(monkeypatch)

        assert config.TOPIC_EVIDENCE == "cybreach.evidence.v1"
        assert config.TOPIC_VERDICTS == "cybreach.verdicts.v2"
        assert config.TOPIC_GAP_CLOSED == "cybreach.gap_closed.v2"
        assert config.TOPIC_REVALIDATION == "cybreach.revalidation.v1"
        assert config.TOPIC_CONNECTOR_HEALTH == "cybreach.connector.health.v1"

    def test_all_five_plan_topics_are_declared(self, monkeypatch):
        config = _reload_with_env(monkeypatch)

        assert len(config.PLAN_TOPICS) == 5
        assert len(set(config.PLAN_TOPICS)) == 5

    def test_no_topic_uses_the_retired_legacy_name(self, monkeypatch):
        config = _reload_with_env(monkeypatch)

        for topic in config.PLAN_TOPICS:
            assert "verdict-events" not in topic
            assert topic.startswith("cybreach.")

    def test_topics_are_overridable(self, monkeypatch):
        config = _reload_with_env(
            monkeypatch, KAFKA_TOPIC_VERDICTS="custom.verdicts.v2"
        )

        assert config.TOPIC_VERDICTS == "custom.verdicts.v2"


class TestInjectedBroker:
    def test_broker_is_not_hardcoded(self, monkeypatch):
        config = _reload_with_env(monkeypatch)

        # No default: a hardcoded `localhost:9092` silently points at whatever
        # broker happens to be on the developer's own machine.
        assert config.get_settings().kafka_bootstrap_servers == ""

    def test_broker_comes_from_the_environment(self, monkeypatch):
        config = _reload_with_env(
            monkeypatch, KAFKA_BOOTSTRAP_SERVERS="broker:9092"
        )

        assert config.get_settings().kafka_bootstrap_servers == "broker:9092"
