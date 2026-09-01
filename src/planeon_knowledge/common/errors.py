"""Stable privacy-preserving error envelope."""

from __future__ import annotations

from dataclasses import dataclass

from .validation import token, uuid_text

SCHEMA_VERSION = "planeon.knowledge.error/v1"


@dataclass(frozen=True, slots=True)
class KnowledgeError(Exception):
    code: str
    correlation_id: str
    message: str = "Request could not be processed."

    def __post_init__(self) -> None:
        token(self.code, "code")
        uuid_text(self.correlation_id, "correlationId")
        if not isinstance(self.message, str) or not 1 <= len(self.message) <= 160:
            raise ValueError("message must be bounded")

    def as_dict(self) -> dict[str, str]:
        return {
            "schemaVersion": SCHEMA_VERSION,
            "code": self.code,
            "correlationId": self.correlation_id,
            "message": self.message,
        }
