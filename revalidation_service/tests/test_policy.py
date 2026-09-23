"""Tests for run-timing policy helpers and idempotency key generation."""

import pytest

from src.scheduling.policy import (
    apply_missed_run_policy,
    build_scheduled_idempotency_key,
    is_due,
)


HOUR = 3600


class TestIsDue:

    def test_never_run_schedule_is_due(self):
        assert is_due(next_run_at=None, now=1000.0) is True

    def test_future_next_run_is_not_due(self):
        assert is_due(next_run_at=2000.0, now=1999.9) is False

    def test_reached_next_run_is_due(self):
        assert is_due(next_run_at=2000.0, now=2000.0) is True

    def test_disabled_or_running_is_never_due(self):
        assert is_due(None, 1000.0, enabled=False) is False
        assert is_due(None, 1000.0, is_running=True) is False


class TestMissedRunPolicy:

    def test_invalid_policy_raises(self):
        with pytest.raises(ValueError, match="Unknown missed-run policy"):
            apply_missed_run_policy("explode", 0.0, HOUR, HOUR * 5)

    def test_skip_drops_missed_ticks_and_reanchors_to_now(self):
        last_run = 0.0
        now = HOUR * 10

        should_run, next_run = apply_missed_run_policy(
            "skip", last_run, HOUR, now
        )

        assert should_run is True
        assert next_run == now + HOUR

    def test_run_once_keeps_cadence_anchor(self):
        last_run = 0.0
        now = HOUR * 10 + 60

        should_run, next_run = apply_missed_run_policy(
            "run_once", last_run, HOUR, now
        )

        assert should_run is True
        # one catch-up run, then continue on the original hourly phase
        assert next_run == HOUR * 11

    def test_small_lag_behaves_identically(self):
        last_run = 1000.0
        now = last_run + HOUR + 30

        skip_result = apply_missed_run_policy("skip", last_run, HOUR, now)
        once_result = apply_missed_run_policy(
            "run_once", last_run, HOUR, now
        )

        assert skip_result[0] is True
        assert once_result[0] is True
        assert once_result[1] == last_run + HOUR * 2

    def test_only_one_catch_up_regardless_of_gap_size(self):
        last_run = 0.0
        far_future = HOUR * 1000

        should_run, _ = apply_missed_run_policy(
            "run_once", last_run, HOUR, far_future
        )

        assert should_run is True


class TestScheduledIdempotencyKey:

    def test_key_is_deterministic_per_tick(self):
        first = build_scheduled_idempotency_key("sched-abc", 1700000000)
        second = build_scheduled_idempotency_key("sched-abc", 1700000000)

        assert first == second

    def test_keys_differ_across_ticks_and_schedules(self):
        base = build_scheduled_idempotency_key("sched-abc", 1700000000)

        assert base != build_scheduled_idempotency_key(
            "sched-abc", 1700036000
        )
        assert base != build_scheduled_idempotency_key(
            "sched-def", 1700000000
        )

    def test_key_format_and_length(self):
        key = build_scheduled_idempotency_key("sched-abc", 1700000000)

        assert key.startswith("auto-sched-abc-")
        assert len(key) <= 255
