"""Tests for interval parsing, formatting and bounds enforcement."""

import pytest

from src.scheduling.interval import (
    MAX_INTERVAL_SECONDS,
    MIN_INTERVAL_SECONDS,
    format_interval,
    parse_interval,
)


class TestParseInterval:

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("90s", 90),
            ("15m", 900),
            ("24h", 86400),
            ("7d", 604800),
            ("1h30m", 5400),
            ("2d12h", 216000),
            ("1d", 86400),
            ("24H", 86400),
            (" 15m ", 900),
        ],
    )
    def test_valid_durations(self, value, expected):
        assert parse_interval(value) == expected

    def test_integer_seconds_passthrough(self):
        assert parse_interval(3600) == 3600

    def test_bounds(self):
        assert parse_interval(MIN_INTERVAL_SECONDS) == MIN_INTERVAL_SECONDS
        assert parse_interval(MAX_INTERVAL_SECONDS) == MAX_INTERVAL_SECONDS

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "   ",
            "abc",
            "5x",
            "-5m",
            "m",
            "1h-30m",
            None,
            [],
            {},
            True,
            3.5,
        ],
    )
    def test_invalid_values_raise(self, value):
        with pytest.raises(ValueError):
            parse_interval(value)

    def test_below_minimum_rejected(self):
        with pytest.raises(ValueError, match="at least"):
            parse_interval("30s")
            parse_interval(MIN_INTERVAL_SECONDS - 1)

    def test_above_maximum_rejected(self):
        with pytest.raises(ValueError, match="not exceed"):
            parse_interval("31d")

    def test_zero_duration_rejected(self):
        with pytest.raises(ValueError, match="at least"):
            parse_interval("0s")


class TestFormatInterval:

    @pytest.mark.parametrize(
        "seconds, expected",
        [
            (59, "59s"),
            (60, "1m"),
            (3600, "1h"),
            (5400, "1h30m"),
            (90000, "1d1h"),
        ],
    )
    def test_formatting(self, seconds, expected):
        assert format_interval(seconds) == expected

    def test_round_trip(self):
        for seconds in (
            MIN_INTERVAL_SECONDS,
            61,
            3601,
            86761,
            MAX_INTERVAL_SECONDS,
        ):
            assert parse_interval(format_interval(seconds)) == seconds
