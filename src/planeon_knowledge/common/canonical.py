"""Bounded canonical JSON and digest primitives."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable, Mapping
from typing import Any

MAX_JSON_BYTES = 65_536


class CanonicalJsonError(ValueError):
    """Raised when an input is not in the closed canonical domain."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJsonError("duplicate JSON member")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise CanonicalJsonError(f"non-finite number is forbidden: {value}")


def parse_closed_json(
    raw: bytes | str,
    *,
    allowed_fields: Iterable[str] | None = None,
    require_object: bool = True,
) -> Any:
    try:
        data = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
        if len(data) > MAX_JSON_BYTES:
            raise CanonicalJsonError("JSON exceeds the closed size limit")
        text = data.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_non_finite,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CanonicalJsonError("invalid JSON") from exc
    if require_object and not isinstance(value, dict):
        raise CanonicalJsonError("JSON root must be an object")
    if allowed_fields is not None:
        expected = frozenset(allowed_fields)
        actual = frozenset(value)
        if actual != expected:
            raise CanonicalJsonError("JSON fields are not closed")
    return value


def _validate(value: Any) -> None:
    if value is None or isinstance(value, (bool, str, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalJsonError("non-finite number is forbidden")
        return
    if isinstance(value, list):
        for item in value:
            _validate(item)
        return
    if isinstance(value, Mapping) and all(isinstance(key, str) for key in value):
        for item in value.values():
            _validate(item)
        return
    raise CanonicalJsonError("value is outside the canonical JSON domain")


def canonical_json(value: Any) -> bytes:
    _validate(value)
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > MAX_JSON_BYTES:
        raise CanonicalJsonError("canonical JSON exceeds the closed size limit")
    return encoded


def canonical_digest(value: Any) -> str:
    return f"sha256:{hashlib.sha256(canonical_json(value)).hexdigest()}"
