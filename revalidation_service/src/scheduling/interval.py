"""Interval parsing and validation for re-validation schedules.

Accepts human-friendly duration strings such as "90s", "15m", "24h",
"7d" or combined forms like "1h30m" / "2d12h", and converts them to
a total number of seconds. Bounds are enforced so that automated
re-validation can neither hammer the service nor go stale.
"""

import os
import re

MIN_INTERVAL_SECONDS = int(
    os.environ.get("REVALIDATION_MIN_INTERVAL_SECONDS", "60")
)
MAX_INTERVAL_SECONDS = int(
    os.environ.get("REVALIDATION_MAX_INTERVAL_SECONDS", "2592000")
)

DEFAULT_INTERVAL = "24h"

_INTERVAL_PATTERN = re.compile(
    r"^(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$"
)

_UNIT_SECONDS = {
    "d": 86400,
    "h": 3600,
    "m": 60,
    "s": 1,
}


def parse_interval(value) -> int:
    """Parse an interval value into total seconds.

    Accepts an integer number of seconds or a duration string.
    Raises ValueError when the value is malformed or outside the
    configured [MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS] range.
    """

    if isinstance(value, bool):
        raise ValueError("Interval must be a duration string or seconds")

    if isinstance(value, (int, float)):
        if float(value).is_integer():
            total = int(value)
        else:
            raise ValueError("Interval seconds must be a whole number")
    elif isinstance(value, str):
        text = value.strip().lower()
        if not text:
            raise ValueError("Interval cannot be empty")

        if text.isdigit():
            total = int(text)
        else:
            match = _INTERVAL_PATTERN.match(text)
            if match is None:
                raise ValueError(
                    "Invalid interval format: "
                    f"'{value}'. "
                    "Expected forms like '30s', '15m', '24h', "
                    "'7d' or combinations like '1h30m'"
                )

            total = 0
            matched_any = False
            for unit, group in zip(
                ("d", "h", "m", "s"),
                match.groups(),
            ):
                if group is not None:
                    matched_any = True
                    total += int(group) * _UNIT_SECONDS[unit]

            if not matched_any:
                raise ValueError(
                    f"Interval '{value}' does not contain any duration"
                )
    else:
        raise ValueError(
            "Interval must be a duration string or number of seconds"
        )

    if total < MIN_INTERVAL_SECONDS:
        raise ValueError(
            f"Interval must be at least {MIN_INTERVAL_SECONDS} seconds"
        )

    if total > MAX_INTERVAL_SECONDS:
        raise ValueError(
            f"Interval must not exceed {MAX_INTERVAL_SECONDS} seconds"
        )

    return total


def format_interval(seconds: int) -> str:
    """Render a number of seconds as a compact duration string."""

    remaining = int(seconds)
    parts = []

    for unit in ("d", "h", "m", "s"):
        unit_size = _UNIT_SECONDS[unit]
        if remaining >= unit_size and unit != "s":
            amount, remaining = divmod(remaining, unit_size)
            parts.append(f"{amount}{unit}")
        elif unit == "s" and (remaining > 0 or not parts):
            parts.append(f"{remaining}s")

    return "".join(parts)
