"""Closed HTTP GET pagination plans with no socket or DNS operation."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from planeon_knowledge.common.canonical import canonical_digest

from ..contracts import ReadPlan
from .base import ConnectorFailure, ConnectorPage, ConnectorPort, enforce_page, require_attestations

HOST = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$")
BLOCKED_HOSTS = frozenset({"localhost", "metadata.google.internal", "metadata.internal", "instance-data"})


def _safe_host(value: str) -> str:
    if (
        not isinstance(value, str)
        or value.casefold() != value
        or HOST.fullmatch(value) is None
        or value in BLOCKED_HOSTS
        or value.endswith((".localhost", ".local", ".internal"))
    ):
        raise ValueError("HTTP host is outside the closed domain")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    if not address.is_global:
        raise ValueError("HTTP non-global target is forbidden")
    return value


def _path_prefix(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 512 or not value.startswith("/"):
        raise ValueError("HTTP path prefix is invalid")
    if "?" in value or "#" in value or "\\" in value or "//" in value or any(ord(character) < 32 for character in value):
        raise ValueError("HTTP path prefix is invalid")
    if any(piece in {".", ".."} for piece in value.split("/")):
        raise ValueError("HTTP path traversal is forbidden")
    return value


@dataclass(frozen=True, slots=True)
class HttpBinding:
    scheme: str
    host: str
    port: int
    path_prefix: str
    pagination_mode: str

    def __post_init__(self) -> None:
        if self.scheme not in {"http", "https"}:
            raise ValueError("HTTP scheme is invalid")
        _safe_host(self.host)
        if not isinstance(self.port, int) or isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            raise ValueError("HTTP port is invalid")
        _path_prefix(self.path_prefix)
        if self.pagination_mode not in {"NONE", "OPAQUE_TOKEN"}:
            raise ValueError("HTTP pagination mode is invalid")

    @property
    def binding_digest(self) -> str:
        return canonical_digest({"scheme": self.scheme, "host": self.host, "port": self.port, "pathPrefix": self.path_prefix, "paginationMode": self.pagination_mode})


def read_http(plan: ReadPlan, binding: HttpBinding, port: ConnectorPort) -> tuple[ConnectorPage, ...]:
    if binding.binding_digest != plan.binding_digest:
        raise ConnectorFailure("HTTP_BINDING_DENIED")
    pages: list[ConnectorPage] = []
    cursor: str | None = None
    total_bytes = 0
    total_hint = 0
    seen: set[str] = set()
    for _ in range(plan.max_pages):
        page = port(plan, binding, cursor, None)
        enforce_page(plan, page)
        require_attestations(page, frozenset({"AUTHORITY_MATCH", "DEADLINE_BOUND", "GET_ONLY", "NO_REDIRECT", "READ_ONLY"}))
        total_bytes += len(page.payload)
        total_hint += page.record_hint
        if total_bytes > plan.max_bytes or total_hint > plan.max_records:
            raise ConnectorFailure("HTTP_AGGREGATE_LIMIT_EXCEEDED")
        pages.append(page)
        if page.next_token is None:
            return tuple(pages)
        if binding.pagination_mode != "OPAQUE_TOKEN" or page.next_token in seen:
            raise ConnectorFailure("HTTP_PAGINATION_DENIED")
        seen.add(page.next_token)
        cursor = page.next_token
    raise ConnectorFailure("HTTP_PAGE_LIMIT_EXCEEDED")
