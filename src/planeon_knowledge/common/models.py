"""Immutable metadata-only foundation records."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .validation import digest, media_type, token, utc_seconds, uuid_text

SCHEMA_VERSION = "planeon.knowledge.foundation/v1"


class IdempotencyState(StrEnum):
    NEW = "NEW"
    DUPLICATE = "DUPLICATE"
    CONFLICT = "CONFLICT"


def classify_idempotency(existing_digest: str | None, candidate_digest: str) -> IdempotencyState:
    digest(candidate_digest, "candidateDigest")
    if existing_digest is None:
        return IdempotencyState.NEW
    digest(existing_digest, "existingDigest")
    return IdempotencyState.DUPLICATE if existing_digest == candidate_digest else IdempotencyState.CONFLICT


@dataclass(frozen=True, slots=True)
class TenantIdentity:
    organization_id: str
    subject_id: str
    admission_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        token(self.subject_id, "subjectId")
        digest(self.admission_digest, "admissionDigest")

    def as_dict(self) -> dict[str, str]:
        return {
            "schemaVersion": SCHEMA_VERSION,
            "organizationId": self.organization_id,
            "subjectId": self.subject_id,
            "admissionDigest": self.admission_digest,
        }


@dataclass(frozen=True, slots=True)
class SourceReference:
    organization_id: str
    source_id: str
    source_version_digest: str
    locator_digest: str
    content_digest: str
    media_type: str
    content_bytes: int
    observed_at: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.source_id, "sourceId")
        digest(self.source_version_digest, "sourceVersionDigest")
        digest(self.locator_digest, "locatorDigest")
        digest(self.content_digest, "contentDigest")
        media_type(self.media_type)
        if not isinstance(self.content_bytes, int) or isinstance(self.content_bytes, bool) or not 0 <= self.content_bytes <= 2**63 - 1:
            raise ValueError("contentBytes is outside the closed range")
        utc_seconds(self.observed_at, "observedAt")

    def as_dict(self) -> dict[str, str | int]:
        return {
            "schemaVersion": SCHEMA_VERSION,
            "organizationId": self.organization_id,
            "sourceId": self.source_id,
            "sourceVersionDigest": self.source_version_digest,
            "locatorDigest": self.locator_digest,
            "contentDigest": self.content_digest,
            "mediaType": self.media_type,
            "contentBytes": self.content_bytes,
            "observedAt": self.observed_at,
        }


@dataclass(frozen=True, slots=True)
class InboxRecord:
    organization_id: str
    event_id: str
    event_type: str
    aggregate_id: str
    event_digest: str
    received_at: str
    processed_at: str | None = None

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.event_id, "eventId")
        token(self.event_type, "eventType")
        uuid_text(self.aggregate_id, "aggregateId")
        digest(self.event_digest, "eventDigest")
        utc_seconds(self.received_at, "receivedAt")
        if self.processed_at is not None:
            utc_seconds(self.processed_at, "processedAt")

    @property
    def idempotency_key(self) -> tuple[str, str]:
        return self.organization_id, self.event_id

    def mark_processed(self, timestamp: str) -> "InboxRecord":
        if self.processed_at is not None:
            raise ValueError("inbox record is append-only")
        return InboxRecord(
            self.organization_id,
            self.event_id,
            self.event_type,
            self.aggregate_id,
            self.event_digest,
            self.received_at,
            timestamp,
        )

    def as_dict(self) -> dict[str, str | None]:
        return {
            "schemaVersion": SCHEMA_VERSION,
            "organizationId": self.organization_id,
            "eventId": self.event_id,
            "eventType": self.event_type,
            "aggregateId": self.aggregate_id,
            "eventDigest": self.event_digest,
            "receivedAt": self.received_at,
            "processedAt": self.processed_at,
        }


@dataclass(frozen=True, slots=True)
class OutboxRecord:
    organization_id: str
    event_id: str
    event_type: str
    aggregate_id: str
    payload_digest: str
    occurred_at: str
    published_at: str | None = None

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.event_id, "eventId")
        token(self.event_type, "eventType")
        uuid_text(self.aggregate_id, "aggregateId")
        digest(self.payload_digest, "payloadDigest")
        utc_seconds(self.occurred_at, "occurredAt")
        if self.published_at is not None:
            utc_seconds(self.published_at, "publishedAt")

    @property
    def idempotency_key(self) -> tuple[str, str]:
        return self.organization_id, self.event_id

    def mark_published(self, timestamp: str) -> "OutboxRecord":
        if self.published_at is not None:
            raise ValueError("outbox record is append-only")
        return OutboxRecord(
            self.organization_id,
            self.event_id,
            self.event_type,
            self.aggregate_id,
            self.payload_digest,
            self.occurred_at,
            timestamp,
        )

    def as_dict(self) -> dict[str, str | None]:
        return {
            "schemaVersion": SCHEMA_VERSION,
            "organizationId": self.organization_id,
            "eventId": self.event_id,
            "eventType": self.event_type,
            "aggregateId": self.aggregate_id,
            "payloadDigest": self.payload_digest,
            "occurredAt": self.occurred_at,
            "publishedAt": self.published_at,
        }
