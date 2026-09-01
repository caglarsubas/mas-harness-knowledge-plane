"""Classification-coverage evaluation over metadata-only counts."""

from __future__ import annotations

from decimal import Decimal

from .coverage import minimum_band, ratio


def classification_coverage(classified_count: int, observed_count: int) -> Decimal:
    return ratio(classified_count, observed_count)


def classification_band(value: Decimal, pass_minimum: Decimal, warn_minimum: Decimal) -> str:
    return minimum_band(value, pass_minimum, warn_minimum)
