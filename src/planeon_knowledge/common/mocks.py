"""Closed loader for local synthetic contract mocks."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, Iterable

from .canonical import MAX_JSON_BYTES, parse_closed_json

FORBIDDEN_KEYS = {
    "authorization",
    "authorizationHeader",
    "apiKey",
    "bucket",
    "content",
    "credential",
    "embedding",
    "filePath",
    "locator",
    "modelOutput",
    "password",
    "payload",
    "prompt",
    "query",
    "secret",
    "sourceContent",
    "token",
    "uri",
    "url",
}


def _reject_content(value: Any) -> None:
    if isinstance(value, dict):
        if FORBIDDEN_KEYS.intersection(value):
            raise ValueError("mock contains a content-bearing or credential field")
        for item in value.values():
            _reject_content(item)
    elif isinstance(value, list):
        for item in value:
            _reject_content(item)


def load_mock(path: Path, *, allowed_fields: Iterable[str] | None = None) -> dict[str, Any]:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JSON_BYTES:
            raise ValueError("mock must be a bounded regular file")
        data = bytearray()
        while chunk := os.read(descriptor, 16_384):
            data.extend(chunk)
    finally:
        os.close(descriptor)
    value = parse_closed_json(bytes(data), allowed_fields=allowed_fields)
    _reject_content(value)
    return value
