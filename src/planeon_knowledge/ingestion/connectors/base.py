"""Injected connector-port primitives; this module performs no external I/O."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Protocol

from planeon_knowledge.common.validation import digest, media_type, utc_seconds

from ..contracts import ReadPlan

OPAQUE = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")


class ConnectorFailure(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class ConnectorPage:
    payload: bytes
    media_type: str
    payload_digest: str
    observed_at: str
    attestations: frozenset[str]
    next_token: str | None = None
    checkpoint_token: str | None = None
    record_hint: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.payload, bytes) or not 1 <= len(self.payload) <= 2 * 1024 * 1024:
            raise ValueError("connector payload is outside the closed range")
        media_type(self.media_type)
        digest(self.payload_digest, "payloadDigest")
        if self.payload_digest != f"sha256:{hashlib.sha256(self.payload).hexdigest()}":
            raise ValueError("connector payload digest mismatch")
        utc_seconds(self.observed_at, "observedAt")
        if not isinstance(self.attestations, frozenset) or not all(isinstance(item, str) and OPAQUE.fullmatch(item) for item in self.attestations):
            raise ValueError("connector attestations are invalid")
        for value in (self.next_token, self.checkpoint_token):
            if value is not None and (not isinstance(value, str) or OPAQUE.fullmatch(value) is None):
                raise ValueError("connector opaque token is invalid")
        if not isinstance(self.record_hint, int) or isinstance(self.record_hint, bool) or not 0 <= self.record_hint <= 10_000:
            raise ValueError("recordHint is outside the closed range")


class ConnectorPort(Protocol):
    def __call__(self, plan: ReadPlan, binding: object, cursor: str | None, parameters: object | None) -> ConnectorPage:
        """Return one already bounded observation without mutating a source."""


def require_attestations(page: ConnectorPage, required: frozenset[str]) -> None:
    if not required <= page.attestations:
        raise ConnectorFailure("CONNECTOR_ATTESTATION_MISSING")


def enforce_page(plan: ReadPlan, page: ConnectorPage) -> None:
    if len(page.payload) > min(plan.max_bytes, 2 * 1024 * 1024):
        raise ConnectorFailure("RESPONSE_SIZE_EXCEEDED")
    if page.record_hint > plan.max_records:
        raise ConnectorFailure("RECORD_LIMIT_EXCEEDED")
