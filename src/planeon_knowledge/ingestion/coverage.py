"""Decimal-safe bounded ratio evaluation for ingestion readiness."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation


class CoverageFailure(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def decimal_value(value: str, field: str, *, maximum: Decimal) -> Decimal:
    if not isinstance(value, str) or len(value) > 24:
        raise CoverageFailure("THRESHOLD_INVALID")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise CoverageFailure("THRESHOLD_INVALID") from exc
    if not parsed.is_finite() or parsed < 0 or parsed > maximum or parsed.as_tuple().exponent < -6:
        raise CoverageFailure("THRESHOLD_INVALID")
    if format(parsed, "f") != value or canonical_decimal(parsed) != value:
        raise CoverageFailure("THRESHOLD_INVALID")
    return parsed


def ratio(numerator: int, denominator: int) -> Decimal:
    if denominator <= 0 or numerator < 0 or numerator > denominator:
        raise CoverageFailure("MEASUREMENT_INVALID")
    return Decimal(numerator) / Decimal(denominator)


def canonical_decimal(value: Decimal) -> str:
    rendered = format(value.quantize(Decimal("0.000001")), "f").rstrip("0").rstrip(".")
    return rendered or "0"


def minimum_band(value: Decimal, pass_minimum: Decimal, warn_minimum: Decimal) -> str:
    if pass_minimum < warn_minimum:
        raise CoverageFailure("THRESHOLD_ORDER_INVALID")
    if value >= pass_minimum:
        return "PASS"
    if value >= warn_minimum:
        return "WARN"
    return "FAIL"


def maximum_band(value: Decimal, pass_maximum: Decimal, warn_maximum: Decimal) -> str:
    if pass_maximum > warn_maximum:
        raise CoverageFailure("THRESHOLD_ORDER_INVALID")
    if value <= pass_maximum:
        return "PASS"
    if value <= warn_maximum:
        return "WARN"
    return "FAIL"
