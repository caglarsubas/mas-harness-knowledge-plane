"""Strict bounded local decoders with digest-only record metadata."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
from dataclasses import dataclass, field
from typing import Any

from planeon_knowledge.common.canonical import canonical_digest

from .contracts import DecodedRecord

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_RECORD_BYTES = 65_536
MAX_STRING_BYTES = 16_384
MAX_FIELDS = 256
MAX_DEPTH = 16
MAX_LIST_ITEMS = 10_000
MEDIA_TYPES = frozenset({"application/json", "application/x-ndjson", "text/csv", "text/plain", "text/markdown"})


class DecoderFailure(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class DecodedEnvelope:
    record: DecodedRecord
    canonical_bytes: bytes = field(repr=False, compare=False)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DecoderFailure("JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _non_finite(value: str) -> None:
    raise DecoderFailure("JSON_NON_FINITE_NUMBER")


def _json_value(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_non_finite)
    except DecoderFailure:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise DecoderFailure("JSON_INVALID") from exc


def _validate(value: Any, *, depth: int, field_counter: list[int]) -> None:
    if depth > MAX_DEPTH:
        raise DecoderFailure("VALUE_DEPTH_EXCEEDED")
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise DecoderFailure("JSON_NON_FINITE_NUMBER")
        return
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_STRING_BYTES or any(character in value for character in "\x00"):
            raise DecoderFailure("STRING_LIMIT_EXCEEDED")
        return
    if isinstance(value, list):
        if len(value) > MAX_LIST_ITEMS:
            raise DecoderFailure("LIST_LIMIT_EXCEEDED")
        for item in value:
            _validate(item, depth=depth + 1, field_counter=field_counter)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        field_counter[0] += len(value)
        if field_counter[0] > MAX_FIELDS:
            raise DecoderFailure("FIELD_LIMIT_EXCEEDED")
        for key, item in value.items():
            if not key or len(key.encode("utf-8")) > 256 or any(character in key for character in "\r\n\x00"):
                raise DecoderFailure("FIELD_NAME_INVALID")
            _validate(item, depth=depth + 1, field_counter=field_counter)
        return
    raise DecoderFailure("VALUE_TYPE_FORBIDDEN")


def _schema(value: Any) -> Any:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        variants = sorted({json.dumps(_schema(item), sort_keys=True, separators=(",", ":")) for item in value})
        return {"type": "array", "items": [json.loads(item) for item in variants]}
    if isinstance(value, dict):
        return {"type": "object", "fields": {key: _schema(value[key]) for key in sorted(value)}}
    raise DecoderFailure("VALUE_TYPE_FORBIDDEN")


def _encode(value: Any) -> bytes:
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise DecoderFailure("VALUE_ENCODING_FAILED") from exc
    if not 1 <= len(encoded) <= MAX_RECORD_BYTES:
        raise DecoderFailure("RECORD_SIZE_EXCEEDED")
    return encoded


def _records_for_json(value: Any) -> list[dict[str, Any]]:
    records = value if isinstance(value, list) else [value]
    if not records or not all(isinstance(item, dict) for item in records):
        raise DecoderFailure("JSON_RECORD_OBJECT_REQUIRED")
    return records


def _decode_json(text: str) -> list[dict[str, Any]]:
    return _records_for_json(_json_value(text))


def _decode_ndjson(text: str) -> list[dict[str, Any]]:
    lines = text.splitlines()
    if not lines or any(not line.strip() for line in lines):
        raise DecoderFailure("NDJSON_LINE_INVALID")
    records: list[dict[str, Any]] = []
    for line in lines:
        if len(line.encode("utf-8")) > MAX_RECORD_BYTES:
            raise DecoderFailure("RECORD_SIZE_EXCEEDED")
        value = _json_value(line)
        if not isinstance(value, dict):
            raise DecoderFailure("JSON_RECORD_OBJECT_REQUIRED")
        records.append(value)
    return records


def _decode_csv(text: str) -> list[dict[str, Any]]:
    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except csv.Error as exc:
        raise DecoderFailure("CSV_INVALID") from exc
    if len(rows) < 2:
        raise DecoderFailure("CSV_RECORD_REQUIRED")
    header = rows[0]
    if not 1 <= len(header) <= MAX_FIELDS or len(set(header)) != len(header):
        raise DecoderFailure("CSV_HEADER_INVALID")
    for name in header:
        if not name or len(name.encode("utf-8")) > 256 or any(character in name for character in "\r\n\x00"):
            raise DecoderFailure("CSV_HEADER_INVALID")
    records: list[dict[str, Any]] = []
    for row in rows[1:]:
        if len(row) != len(header):
            raise DecoderFailure("CSV_COLUMN_MISMATCH")
        if any(len(cell.encode("utf-8")) > MAX_STRING_BYTES or "\x00" in cell for cell in row):
            raise DecoderFailure("STRING_LIMIT_EXCEEDED")
        records.append(dict(zip(header, row, strict=True)))
    return records


def decode(payload: bytes, media_type: str, *, max_records: int) -> tuple[DecodedEnvelope, ...]:
    if media_type not in MEDIA_TYPES:
        raise DecoderFailure("MEDIA_TYPE_UNSUPPORTED")
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_RESPONSE_BYTES:
        raise DecoderFailure("RESPONSE_SIZE_EXCEEDED")
    if not isinstance(max_records, int) or isinstance(max_records, bool) or not 1 <= max_records <= 10_000:
        raise DecoderFailure("RECORD_LIMIT_INVALID")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise DecoderFailure("UTF8_REQUIRED") from exc

    if media_type == "application/json":
        values: list[Any] = _decode_json(text)
    elif media_type == "application/x-ndjson":
        values = _decode_ndjson(text)
    elif media_type == "text/csv":
        values = _decode_csv(text)
    else:
        if not text or "\x00" in text:
            raise DecoderFailure("TEXT_INVALID")
        values = [{"document": text}]
    if len(values) > max_records:
        raise DecoderFailure("RECORD_LIMIT_EXCEEDED")

    result: list[DecodedEnvelope] = []
    for ordinal, value in enumerate(values):
        _validate(value, depth=0, field_counter=[0])
        encoded = _encode(value)
        record_digest = f"sha256:{hashlib.sha256(encoded).hexdigest()}"
        schema_digest = canonical_digest(_schema(value))
        result.append(DecodedEnvelope(DecodedRecord(ordinal, record_digest, schema_digest, len(encoded)), encoded))
    return tuple(result)
