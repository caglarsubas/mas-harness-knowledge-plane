"""Closed scalar validation shared by foundation records."""

from __future__ import annotations

import re
from datetime import datetime
from uuid import UUID

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
TOKEN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,127}$")
MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$")
UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def uuid_text(value: str, field: str) -> str:
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a canonical UUID") from exc
    if str(parsed) != value:
        raise ValueError(f"{field} must be a canonical UUID")
    return value


def digest(value: str, field: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase sha256 digest")
    return value


def token(value: str, field: str) -> str:
    if not isinstance(value, str) or TOKEN.fullmatch(value) is None:
        raise ValueError(f"{field} is outside the closed token domain")
    return value


def media_type(value: str) -> str:
    if not isinstance(value, str) or MEDIA_TYPE.fullmatch(value) is None:
        raise ValueError("mediaType is outside the closed media-type domain")
    return value


def utc_seconds(value: str, field: str) -> str:
    if not isinstance(value, str) or UTC_SECONDS.fullmatch(value) is None:
        raise ValueError(f"{field} must be UTC RFC3339 seconds")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError(f"{field} must be a real UTC timestamp") from exc
    return value
