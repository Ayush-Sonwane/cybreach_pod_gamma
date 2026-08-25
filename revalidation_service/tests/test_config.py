import pytest

from src.core.config import (
    ENV_ENABLED,
    ENV_INTERVAL_SECONDS,
    DEFAULT_INTERVAL_SECONDS,
    SchedulerSettings,
    load_scheduler_settings,
)


class TestDefaults:
    def test_missing_env_vars_use_documented_defaults(self):
        settings = load_scheduler_settings({})
        assert settings.enabled is False
        assert settings.interval_seconds == DEFAULT_INTERVAL_SECONDS

    def test_settings_are_immutable(self):
        settings = load_scheduler_settings({})
        with pytest.raises(AttributeError):
            settings.enabled = True


class TestValidValues:
    @pytest.mark.parametrize("raw", ["true", "TRUE", "True", "1", " true "])
    def test_enabled_true_variants(self, raw):
        assert load_scheduler_settings({ENV_ENABLED: raw}).enabled is True

    @pytest.mark.parametrize("raw", ["false", "FALSE", "0", " false "])
    def test_enabled_false_variants(self, raw):
        assert load_scheduler_settings({ENV_ENABLED: raw}).enabled is False

    def test_interval_parsed_as_integer(self):
        settings = load_scheduler_settings({ENV_INTERVAL_SECONDS: "45"})
        assert settings.interval_seconds == 45

    def test_interval_whitespace_trimmed(self):
        assert load_scheduler_settings({ENV_INTERVAL_SECONDS: "  60  "}).interval_seconds == 60


class TestFailFast:
    @pytest.mark.parametrize("raw", ["yes", "on", "", "enabled"])
    def test_invalid_boolean_fails_startup(self, raw):
        with pytest.raises(ValueError, match=ENV_ENABLED):
            load_scheduler_settings({ENV_ENABLED: raw})

    @pytest.mark.parametrize("raw", ["abc", "", "3.5"])
    def test_invalid_interval_fails_startup(self, raw):
        with pytest.raises(ValueError, match=ENV_INTERVAL_SECONDS):
            load_scheduler_settings({ENV_INTERVAL_SECONDS: raw})

    @pytest.mark.parametrize("raw", ["0", "-5"])
    def test_non_positive_interval_rejected(self, raw):
        with pytest.raises(ValueError, match=ENV_INTERVAL_SECONDS):
            load_scheduler_settings({ENV_INTERVAL_SECONDS: raw})

    def test_invalid_boolean_message_lists_accepted_values(self):
        with pytest.raises(ValueError, match="true/false/1/0"):
            load_scheduler_settings({ENV_ENABLED: "maybe"})
