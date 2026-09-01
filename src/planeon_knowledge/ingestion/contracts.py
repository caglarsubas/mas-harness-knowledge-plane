"""Closed immutable connector and staged-ingestion metadata contracts."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.common.validation import digest, media_type, token, utc_seconds, uuid_text

SCHEMA = "planeon.knowledge.ingestion/v1"
STABLE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$")


def stable_id(value: str, field: str) -> str:
    if not isinstance(value, str) or len(value) > 128 or STABLE_ID.fullmatch(value) is None:
        raise ValueError(f"{field} must be a stable id")
    return value


def positive_int(value: int, field: str, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        raise ValueError(f"{field} is outside the closed range")
    return value


def optional_digest(value: str | None, field: str) -> str | None:
    if value is not None:
        digest(value, field)
    return value


def sorted_tokens(values: tuple[str, ...], field: str, *, minimum: int = 1, maximum: int = 32) -> tuple[str, ...]:
    if not isinstance(values, tuple) or not minimum <= len(values) <= maximum:
        raise ValueError(f"{field} cardinality is outside the closed range")
    checked = tuple(token(value, field) for value in values)
    if checked != tuple(sorted(set(checked))):
        raise ValueError(f"{field} must be sorted and unique")
    return checked


class ConnectorKind(StrEnum):
    FILE = "FILE"
    HTTP = "HTTP"
    POSTGRESQL = "POSTGRESQL"
    EVENT = "EVENT"


class Classification(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class SourceState(StrEnum):
    DECLARED = "DECLARED"
    VALIDATING = "VALIDATING"
    VALID = "VALID"
    INVALID = "INVALID"
    SAMPLING = "SAMPLING"
    SAMPLED = "SAMPLED"
    DISABLED = "DISABLED"


class LeaseState(StrEnum):
    ACQUIRED = "ACQUIRED"
    RENEWED = "RENEWED"
    RELEASED = "RELEASED"
    EXPIRED = "EXPIRED"


class BatchState(StrEnum):
    STAGED = "STAGED"


@dataclass(frozen=True, slots=True)
class SourceDefinition:
    organization_id: str
    source_id: str
    connector_kind: ConnectorKind
    profile_digest: str
    endpoint_ref_digest: str
    credential_ref_digest: str | None
    network_policy_digest: str
    expected_schema_digest: str
    active_domain_version_digest: str
    semantic_mapping_digest: str
    owner_digest: str
    classification: Classification
    residency: tuple[str, ...]
    max_records: int
    max_bytes: int
    deadline_ms: int
    created_at: str
    created_by_subject_id: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.source_id, "sourceId")
        if not isinstance(self.connector_kind, ConnectorKind):
            raise ValueError("connectorKind is invalid")
        for field, value in (
            ("profileDigest", self.profile_digest),
            ("endpointRefDigest", self.endpoint_ref_digest),
            ("networkPolicyDigest", self.network_policy_digest),
            ("expectedSchemaDigest", self.expected_schema_digest),
            ("activeDomainVersionDigest", self.active_domain_version_digest),
            ("semanticMappingDigest", self.semantic_mapping_digest),
            ("ownerDigest", self.owner_digest),
        ):
            digest(value, field)
        optional_digest(self.credential_ref_digest, "credentialRefDigest")
        if not isinstance(self.classification, Classification):
            raise ValueError("classification is invalid")
        sorted_tokens(self.residency, "residency")
        positive_int(self.max_records, "maxRecords", 10_000)
        positive_int(self.max_bytes, "maxBytes", 8 * 1024 * 1024)
        positive_int(self.deadline_ms, "deadlineMs", 30_000)
        utc_seconds(self.created_at, "createdAt")
        token(self.created_by_subject_id, "createdBySubjectId")

    @property
    def resource_digest(self) -> str:
        return canonical_digest(public_dict(self))


@dataclass(frozen=True, slots=True)
class SourceRevision:
    organization_id: str
    source_id: str
    source_version_digest: str
    revision: int
    state: SourceState
    reason_code: str
    occurred_at: str
    correlation_id: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.source_id, "sourceId")
        digest(self.source_version_digest, "sourceVersionDigest")
        positive_int(self.revision, "revision", 2**63 - 1)
        if not isinstance(self.state, SourceState):
            raise ValueError("source state is invalid")
        token(self.reason_code, "reasonCode")
        utc_seconds(self.occurred_at, "occurredAt")
        uuid_text(self.correlation_id, "correlationId")


@dataclass(frozen=True, slots=True)
class AccessPermit:
    organization_id: str
    subject_id: str
    action: str
    resource_digest: str
    allowed: bool
    expires_at: str
    decision_id: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        token(self.subject_id, "subjectId")
        token(self.action, "action")
        digest(self.resource_digest, "resourceDigest")
        if type(self.allowed) is not bool:
            raise ValueError("allowed must be boolean")
        utc_seconds(self.expires_at, "expiresAt")
        uuid_text(self.decision_id, "decisionId")


@dataclass(frozen=True, slots=True)
class EndpointGrant:
    grant_id: str
    organization_id: str
    source_id: str
    connector_kind: ConnectorKind
    operation: str
    endpoint_ref_digest: str
    network_policy_digest: str
    binding_digest: str
    allowed: bool
    expires_at: str

    def __post_init__(self) -> None:
        uuid_text(self.grant_id, "grantId")
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.source_id, "sourceId")
        if not isinstance(self.connector_kind, ConnectorKind):
            raise ValueError("connectorKind is invalid")
        token(self.operation, "operation")
        digest(self.endpoint_ref_digest, "endpointRefDigest")
        digest(self.network_policy_digest, "networkPolicyDigest")
        digest(self.binding_digest, "bindingDigest")
        if type(self.allowed) is not bool:
            raise ValueError("allowed must be boolean")
        utc_seconds(self.expires_at, "expiresAt")


@dataclass(frozen=True, slots=True)
class SecretGrant:
    grant_id: str
    organization_id: str
    source_id: str
    operation: str
    credential_ref_digest: str
    allowed: bool
    expires_at: str

    def __post_init__(self) -> None:
        uuid_text(self.grant_id, "grantId")
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.source_id, "sourceId")
        token(self.operation, "operation")
        digest(self.credential_ref_digest, "credentialRefDigest")
        if type(self.allowed) is not bool:
            raise ValueError("allowed must be boolean")
        utc_seconds(self.expires_at, "expiresAt")


@dataclass(frozen=True, slots=True)
class DomainBindingObservation:
    organization_id: str
    source_id: str
    active_domain_version_digest: str
    semantic_mapping_digest: str
    domain_active: bool
    mapping_active: bool
    observed_at: str
    expires_at: str
    observation_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.source_id, "sourceId")
        digest(self.active_domain_version_digest, "activeDomainVersionDigest")
        digest(self.semantic_mapping_digest, "semanticMappingDigest")
        if type(self.domain_active) is not bool or type(self.mapping_active) is not bool:
            raise ValueError("domain binding states must be boolean")
        utc_seconds(self.observed_at, "observedAt")
        utc_seconds(self.expires_at, "expiresAt")
        digest(self.observation_digest, "observationDigest")


@dataclass(frozen=True, slots=True)
class ConnectorProfile:
    connector_kind: ConnectorKind
    profile_digest: str
    runtime_mode: str
    read_only: bool
    max_response_bytes: int = 2 * 1024 * 1024
    max_pages: int = 32

    def __post_init__(self) -> None:
        if not isinstance(self.connector_kind, ConnectorKind):
            raise ValueError("connectorKind is invalid")
        digest(self.profile_digest, "profileDigest")
        if self.runtime_mode != "process" or self.read_only is not True:
            raise ValueError("only the read-only process profile is supported")
        positive_int(self.max_response_bytes, "maxResponseBytes", 2 * 1024 * 1024)
        positive_int(self.max_pages, "maxPages", 32)


@dataclass(frozen=True, slots=True)
class ReadPlan:
    organization_id: str
    source_id: str
    source_version_digest: str
    connector_kind: ConnectorKind
    endpoint_grant_id: str
    binding_digest: str
    lease_id: str
    lease_revision: int
    fencing_token: int
    max_records: int
    max_bytes: int
    max_pages: int
    deadline_ms: int
    request_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.source_id, "sourceId")
        digest(self.source_version_digest, "sourceVersionDigest")
        if not isinstance(self.connector_kind, ConnectorKind):
            raise ValueError("connectorKind is invalid")
        uuid_text(self.endpoint_grant_id, "endpointGrantId")
        digest(self.binding_digest, "bindingDigest")
        uuid_text(self.lease_id, "leaseId")
        positive_int(self.lease_revision, "leaseRevision", 2**63 - 1)
        positive_int(self.fencing_token, "fencingToken", 2**63 - 1)
        positive_int(self.max_records, "maxRecords", 10_000)
        positive_int(self.max_bytes, "maxBytes", 8 * 1024 * 1024)
        positive_int(self.max_pages, "maxPages", 32)
        positive_int(self.deadline_ms, "deadlineMs", 30_000)
        digest(self.request_digest, "requestDigest")


@dataclass(frozen=True, slots=True)
class ConnectorObservation:
    organization_id: str
    source_id: str
    connector_kind: ConnectorKind
    request_digest: str
    response_digest: str
    media_type: str
    byte_count: int
    record_hint: int
    read_only: bool
    reason_codes: tuple[str, ...]
    observed_at: str
    observation_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.source_id, "sourceId")
        if not isinstance(self.connector_kind, ConnectorKind):
            raise ValueError("connectorKind is invalid")
        digest(self.request_digest, "requestDigest")
        digest(self.response_digest, "responseDigest")
        media_type(self.media_type)
        if not isinstance(self.byte_count, int) or isinstance(self.byte_count, bool) or not 0 <= self.byte_count <= 8 * 1024 * 1024:
            raise ValueError("byteCount is outside the closed range")
        if not isinstance(self.record_hint, int) or isinstance(self.record_hint, bool) or not 0 <= self.record_hint <= 10_000:
            raise ValueError("recordHint is outside the closed range")
        if type(self.read_only) is not bool:
            raise ValueError("readOnly must be boolean")
        sorted_tokens(self.reason_codes, "reasonCodes", minimum=0, maximum=32)
        utc_seconds(self.observed_at, "observedAt")
        digest(self.observation_digest, "observationDigest")


@dataclass(frozen=True, slots=True)
class LeaseRevision:
    organization_id: str
    source_id: str
    source_version_digest: str
    partition: str
    lease_id: str
    revision: int
    fencing_token: int
    owner_worker_id: str
    state: LeaseState
    issued_at: str
    expires_at: str
    reason_code: str
    correlation_id: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.source_id, "sourceId")
        digest(self.source_version_digest, "sourceVersionDigest")
        token(self.partition, "partition")
        uuid_text(self.lease_id, "leaseId")
        positive_int(self.revision, "revision", 2**63 - 1)
        positive_int(self.fencing_token, "fencingToken", 2**63 - 1)
        token(self.owner_worker_id, "ownerWorkerId")
        if not isinstance(self.state, LeaseState):
            raise ValueError("lease state is invalid")
        utc_seconds(self.issued_at, "issuedAt")
        utc_seconds(self.expires_at, "expiresAt")
        token(self.reason_code, "reasonCode")
        uuid_text(self.correlation_id, "correlationId")


@dataclass(frozen=True, slots=True)
class CheckpointCandidate:
    organization_id: str
    source_id: str
    source_version_digest: str
    checkpoint_digest: str
    observed_at: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.source_id, "sourceId")
        digest(self.source_version_digest, "sourceVersionDigest")
        digest(self.checkpoint_digest, "checkpointDigest")
        utc_seconds(self.observed_at, "observedAt")


@dataclass(frozen=True, slots=True)
class DecodedRecord:
    ordinal: int
    record_digest: str
    schema_digest: str
    encoded_bytes: int

    def __post_init__(self) -> None:
        if not isinstance(self.ordinal, int) or isinstance(self.ordinal, bool) or self.ordinal < 0:
            raise ValueError("ordinal must be non-negative")
        digest(self.record_digest, "recordDigest")
        digest(self.schema_digest, "schemaDigest")
        positive_int(self.encoded_bytes, "encodedBytes", 65_536)


@dataclass(frozen=True, slots=True)
class StagedRecordDigest:
    organization_id: str
    batch_id: str
    ordinal: int
    record_digest: str
    schema_digest: str
    encoded_bytes: int

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.batch_id, "batchId")
        if not isinstance(self.ordinal, int) or isinstance(self.ordinal, bool) or self.ordinal < 0:
            raise ValueError("ordinal must be non-negative")
        digest(self.record_digest, "recordDigest")
        digest(self.schema_digest, "schemaDigest")
        positive_int(self.encoded_bytes, "encodedBytes", 65_536)


@dataclass(frozen=True, slots=True)
class StagedBatch:
    organization_id: str
    batch_id: str
    source_id: str
    source_version_digest: str
    expected_schema_digest: str
    active_domain_version_digest: str
    semantic_mapping_digest: str
    material_digest: str
    checkpoint_candidate_digest: str
    media_type: str
    connector_kind: ConnectorKind
    state: BatchState
    record_count: int
    byte_count: int
    record_set_digest: str
    fencing_token: int
    staged_at: str
    batch_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.batch_id, "batchId")
        uuid_text(self.source_id, "sourceId")
        for field, value in (
            ("sourceVersionDigest", self.source_version_digest),
            ("expectedSchemaDigest", self.expected_schema_digest),
            ("activeDomainVersionDigest", self.active_domain_version_digest),
            ("semanticMappingDigest", self.semantic_mapping_digest),
            ("materialDigest", self.material_digest),
            ("checkpointCandidateDigest", self.checkpoint_candidate_digest),
            ("recordSetDigest", self.record_set_digest),
            ("batchDigest", self.batch_digest),
        ):
            digest(value, field)
        media_type(self.media_type)
        if not isinstance(self.connector_kind, ConnectorKind) or self.state is not BatchState.STAGED:
            raise ValueError("staged batch kind/state is invalid")
        positive_int(self.record_count, "recordCount", 10_000)
        positive_int(self.byte_count, "byteCount", 8 * 1024 * 1024)
        positive_int(self.fencing_token, "fencingToken", 2**63 - 1)
        utc_seconds(self.staged_at, "stagedAt")


@dataclass(frozen=True, slots=True)
class StagingReceipt:
    receipt_id: str
    organization_id: str
    source_id: str
    batch_id: str
    material_digest: str
    byte_count: int
    record_count: int
    prepared: bool
    receipt_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.receipt_id, "receiptId")
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.source_id, "sourceId")
        uuid_text(self.batch_id, "batchId")
        digest(self.material_digest, "materialDigest")
        positive_int(self.byte_count, "byteCount", 8 * 1024 * 1024)
        positive_int(self.record_count, "recordCount", 10_000)
        if self.prepared is not True:
            raise ValueError("staging receipt must be prepared")
        digest(self.receipt_digest, "receiptDigest")


@dataclass(frozen=True, slots=True)
class IngestionEvidence:
    organization_id: str
    source_id: str
    source_version_digest: str
    source_state: SourceState
    source_revision: int
    batch_digest: str | None
    endpoint_grant_digest: str | None
    domain_observation_digest: str | None
    reason_code: str
    occurred_at: str
    record_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.source_id, "sourceId")
        digest(self.source_version_digest, "sourceVersionDigest")
        if not isinstance(self.source_state, SourceState):
            raise ValueError("sourceState is invalid")
        positive_int(self.source_revision, "sourceRevision", 2**63 - 1)
        optional_digest(self.batch_digest, "batchDigest")
        optional_digest(self.endpoint_grant_digest, "endpointGrantDigest")
        optional_digest(self.domain_observation_digest, "domainObservationDigest")
        token(self.reason_code, "reasonCode")
        utc_seconds(self.occurred_at, "occurredAt")
        digest(self.record_digest, "recordDigest")


@dataclass(frozen=True, slots=True)
class IngestionEvent:
    event_id: str
    organization_id: str
    source_id: str
    aggregate_version: int
    event_type: str
    source_version_digest: str
    evidence_digest: str
    batch_digest: str | None
    reason_code: str
    correlation_id: str
    occurred_at: str
    event_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.event_id, "eventId")
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.source_id, "sourceId")
        positive_int(self.aggregate_version, "aggregateVersion", 2**63 - 1)
        token(self.event_type, "eventType")
        digest(self.source_version_digest, "sourceVersionDigest")
        digest(self.evidence_digest, "evidenceDigest")
        optional_digest(self.batch_digest, "batchDigest")
        token(self.reason_code, "reasonCode")
        uuid_text(self.correlation_id, "correlationId")
        utc_seconds(self.occurred_at, "occurredAt")
        digest(self.event_digest, "eventDigest")


def _camel(name: str) -> str:
    pieces = name.split("_")
    return pieces[0] + "".join(piece.title() for piece in pieces[1:])


def _public_value(value: Any) -> Any:
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, dict):
        return {_camel(str(name)): _public_value(item) for name, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_public_value(item) for item in value]
    return value


def public_dict(value: Any) -> dict[str, Any]:
    if not hasattr(value, "__dataclass_fields__"):
        raise TypeError("public_dict requires an immutable contract record")
    return {"schemaVersion": SCHEMA, **_public_value(asdict(value))}
