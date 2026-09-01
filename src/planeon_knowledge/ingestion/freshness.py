"""Source-observation freshness evaluation kept separate from index freshness."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

from .coverage import CoverageFailure, maximum_band


def parse_time(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise CoverageFailure("MEASUREMENT_INVALID") from exc


def freshness_minutes(evaluated_at: str, latest_source_observation_at: str) -> Decimal:
    elapsed = parse_time(evaluated_at) - parse_time(latest_source_observation_at)
    if elapsed.total_seconds() < 0:
        raise CoverageFailure("FUTURE_OBSERVATION")
    return Decimal(int(elapsed.total_seconds())) / Decimal(60)


def freshness_band(
    value: Decimal,
    pass_maximum: Decimal,
    warn_maximum: Decimal,
) -> str:
    return maximum_band(value, pass_maximum, warn_maximum)
