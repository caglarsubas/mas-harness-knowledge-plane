"""Deterministic clean-room support for KN-DATA-001 acceptance."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.common.models import TenantIdentity
from planeon_knowledge.ingestion.batch import StagingPort
from planeon_knowledge.ingestion.connectors import (
    Binding,
    EventBinding,
    FileBinding,
    HttpBinding,
    PostgresBinding,
)
from planeon_knowledge.ingestion.connectors.base import ConnectorPage
from planeon_knowledge.ingestion.contracts import (
    AccessPermit,
    Classification,
    ConnectorKind,
    ConnectorProfile,
    DomainBindingObservation,
    EndpointGrant,
    SecretGrant,
    SourceDefinition,
    StagingReceipt,
)
from planeon_knowledge.ingestion.decoder import DecodedEnvelope, decode
from planeon_knowledge.ingestion.service import IngestionService, source_scope_digest
from planeon_knowledge.ingestion.store import InMemoryIngestionStore

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures/connectors/white-goods"
ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111"
OTHER_ORGANIZATION_ID = "22222222-2222-4222-8222-222222222222"
SUBJECT_ID = "data-engineer"
NOW = "2026-01-01T00:00:00Z"
EXPIRES = "2030-01-01T00:00:00Z"

MEDIA_BY_KIND = {
    ConnectorKind.FILE: "text/csv",
    ConnectorKind.HTTP: "application/json",
    ConnectorKind.POSTGRESQL: "application/x-ndjson",
    ConnectorKind.EVENT: "application/x-ndjson",
}
FILE_BY_KIND = {
    ConnectorKind.FILE: "file.csv",
    ConnectorKind.HTTP: "http.json",
    ConnectorKind.POSTGRESQL: "postgresql.ndjson",
    ConnectorKind.EVENT: "event.ndjson",
}
ATTESTATIONS = {
    ConnectorKind.FILE: frozenset({"DEADLINE_BOUND", "MOUNT_GRANT_MATCH", "NO_SYMLINK", "READ_ONLY", "REGULAR_FILE"}),
    ConnectorKind.HTTP: frozenset({"AUTHORITY_MATCH", "DEADLINE_BOUND", "GET_ONLY", "NO_REDIRECT", "READ_ONLY"}),
    ConnectorKind.POSTGRESQL: frozenset({"DEADLINE_BOUND", "PREPARED_EXECUTION", "READ_ONLY_TRANSACTION", "SERVER_LIMIT_BOUND", "STATEMENT_TIMEOUT_BOUND"}),
    ConnectorKind.EVENT: frozenset({"DEADLINE_BOUND", "NO_AUTO_COMMIT", "POLL_ONLY", "READ_ONLY", "TOPIC_PARTITION_MATCH"}),
}


def identifier(label: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"planeon-kn-data-001:{label}"))


def digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def fixture_bytes(kind: ConnectorKind) -> bytes:
    return (FIXTURE / FILE_BY_KIND[kind]).read_bytes()


def identity(*, organization_id: str = ORGANIZATION_ID, subject_id: str = SUBJECT_ID) -> TenantIdentity:
    return TenantIdentity(
        organization_id,
        subject_id,
        canonical_digest({"organizationId": organization_id, "subjectId": subject_id}),
    )


class Clock:
    def __init__(self, value: str = NOW) -> None:
        self.value = value

    def __call__(self) -> str:
        return self.value


class DeterministicIds:
    def __init__(self) -> None:
        self.index = 0

    def __call__(self) -> str:
        self.index += 1
        return identifier(f"generated:{self.index}")


def profiles() -> dict[ConnectorKind, ConnectorProfile]:
    return {
        kind: ConnectorProfile(
            kind,
            canonical_digest({"connectorKind": kind.value, "runtimeMode": "process", "readOnly": True}),
            "process",
            True,
        )
        for kind in ConnectorKind
    }


def service(*, clock: Clock | None = None) -> IngestionService:
    return IngestionService(
        store=InMemoryIngestionStore(),
        profiles=profiles(),
        now=clock or Clock(),
        new_id=DeterministicIds(),
    )


def source(kind: ConnectorKind = ConnectorKind.HTTP, *, caller: TenantIdentity | None = None) -> SourceDefinition:
    admitted = caller or identity()
    payload = fixture_bytes(kind)
    records = decode(payload, MEDIA_BY_KIND[kind], max_records=10)
    schemas = {item.record.schema_digest for item in records}
    if len(schemas) != 1:
        raise AssertionError("parity fixture schema drift")
    return SourceDefinition(
        admitted.organization_id,
        identifier(f"source:{kind.value}:{admitted.organization_id}"),
        kind,
        profiles()[kind].profile_digest,
        canonical_digest({"endpoint": kind.value}),
        None if kind is ConnectorKind.FILE else canonical_digest({"credential": kind.value}),
        canonical_digest({"networkPolicy": kind.value}),
        schemas.pop(),
        canonical_digest({"domainVersion": "white-goods-1"}),
        canonical_digest({"semanticMapping": "white-goods-source-1"}),
        canonical_digest({"owners": ["white-goods-data-owner"]}),
        Classification.INTERNAL,
        ("eu", "tr"),
        100,
        1024 * 1024,
        5_000,
        NOW,
        admitted.subject_id,
    )


def permit(caller: TenantIdentity, action: str, resource_digest: str, *, allowed: bool = True, expires_at: str = EXPIRES) -> AccessPermit:
    return AccessPermit(
        caller.organization_id,
        caller.subject_id,
        action,
        resource_digest,
        allowed,
        expires_at,
        identifier(f"permit:{caller.organization_id}:{caller.subject_id}:{action}:{resource_digest}:{allowed}:{expires_at}"),
    )


def binding(kind: ConnectorKind, payload: bytes | None = None) -> Binding:
    raw = fixture_bytes(kind) if payload is None else payload
    if kind is ConnectorKind.FILE:
        return FileBinding("imports/white-goods/file.csv", canonical_digest({"mount": "white-goods"}), digest_bytes(raw), True, True)
    if kind is ConnectorKind.HTTP:
        return HttpBinding("https", "api.example.com", 443, "/v1/appliances", "OPAQUE_TOKEN")
    if kind is ConnectorKind.POSTGRESQL:
        return PostgresBinding("white-goods-quality", canonical_digest({"statement": "white-goods-quality"}), True, True, 100, 5_000)
    return EventBinding(canonical_digest({"subscription": "white-goods"}), canonical_digest({"topic": "production-events"}), 0, False, "POLL")


def endpoint(source_value: SourceDefinition, operation: str, binding_value: Binding, *, allowed: bool = True, expires_at: str = EXPIRES) -> EndpointGrant:
    return EndpointGrant(
        identifier(f"endpoint:{source_value.source_id}:{operation}"),
        source_value.organization_id,
        source_value.source_id,
        source_value.connector_kind,
        operation,
        source_value.endpoint_ref_digest,
        source_value.network_policy_digest,
        binding_value.binding_digest,
        allowed,
        expires_at,
    )


def secret(source_value: SourceDefinition, operation: str, *, allowed: bool = True, expires_at: str = EXPIRES) -> SecretGrant | None:
    if source_value.credential_ref_digest is None:
        return None
    return SecretGrant(
        identifier(f"secret:{source_value.source_id}:{operation}"),
        source_value.organization_id,
        source_value.source_id,
        operation,
        source_value.credential_ref_digest,
        allowed,
        expires_at,
    )


def domain(source_value: SourceDefinition, *, active: bool = True, expires_at: str = EXPIRES) -> DomainBindingObservation:
    body = {
        "organizationId": source_value.organization_id,
        "sourceId": source_value.source_id,
        "activeDomainVersionDigest": source_value.active_domain_version_digest,
        "semanticMappingDigest": source_value.semantic_mapping_digest,
        "domainActive": active,
        "mappingActive": active,
        "observedAt": NOW,
        "expiresAt": expires_at,
    }
    return DomainBindingObservation(
        source_value.organization_id,
        source_value.source_id,
        source_value.active_domain_version_digest,
        source_value.semantic_mapping_digest,
        active,
        active,
        NOW,
        expires_at,
        canonical_digest(body),
    )


class FixturePort:
    def __init__(
        self,
        kind: ConnectorKind,
        *,
        payload: bytes | None = None,
        media_type: str | None = None,
        attestations: frozenset[str] | None = None,
        next_token: str | None = None,
        checkpoint_token: str | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.kind = kind
        self.payload = fixture_bytes(kind) if payload is None else payload
        self.media_type = media_type or MEDIA_BY_KIND[kind]
        self.attestations = ATTESTATIONS[kind] if attestations is None else attestations
        self.next_token = next_token
        self.checkpoint_token = "position-104" if kind is ConnectorKind.EVENT and checkpoint_token is None else checkpoint_token
        self.failure = failure
        self.calls: list[tuple[object, object, object, object]] = []

    def __call__(self, plan, binding_value, cursor, parameters):
        self.calls.append((plan, binding_value, cursor, parameters))
        if self.failure is not None:
            raise self.failure
        return ConnectorPage(
            self.payload,
            self.media_type,
            digest_bytes(self.payload),
            NOW,
            self.attestations,
            self.next_token,
            self.checkpoint_token,
            4,
        )


class MemoryStagingPort(StagingPort):
    def __init__(self, *, fail: bool = False, mismatch: bool = False) -> None:
        self.fail = fail
        self.mismatch = mismatch
        self.prepared: list[tuple[str, tuple[str, ...]]] = []
        self.aborted: list[StagingReceipt] = []

    def prepare(self, *, organization_id: str, source_id: str, batch_id: str, material_digest: str, pages, records: tuple[DecodedEnvelope, ...]) -> StagingReceipt:
        if self.fail:
            raise RuntimeError("sink detail must not escape")
        byte_count = sum(len(page.payload) for page in pages)
        self.prepared.append((material_digest, tuple(item.record.record_digest for item in records)))
        body = {
            "receiptId": identifier(f"receipt:{batch_id}"),
            "organizationId": organization_id,
            "sourceId": source_id,
            "batchId": batch_id,
            "materialDigest": material_digest,
            "byteCount": byte_count,
            "recordCount": len(records),
            "prepared": True,
        }
        receipt_digest = canonical_digest(body)
        if self.mismatch:
            receipt_digest = "sha256:" + "f" * 64
        return StagingReceipt(
            body["receiptId"], organization_id, source_id, batch_id,
            material_digest, byte_count, len(records), True, receipt_digest,
        )

    def abort(self, receipt: StagingReceipt) -> None:
        self.aborted.append(receipt)


def create_and_validate(target: IngestionService, caller: TenantIdentity, kind: ConnectorKind = ConnectorKind.HTTP):
    candidate = source(kind, caller=caller)
    created = target.create_source(
        caller,
        permit(caller, "knowledge.ingestion.source.create", candidate.resource_digest),
        candidate,
        idempotency_key=f"create-{kind.value.lower()}",
        correlation_id=identifier(f"correlation:create:{kind.value}"),
    )
    binding_value = binding(kind)
    validated = target.validate_source(
        caller,
        permit(caller, "knowledge.ingestion.source.validate", source_scope_digest(caller.organization_id, candidate.source_id)),
        candidate.source_id,
        expected_revision=created.revision,
        endpoint=endpoint(candidate, "VALIDATE", binding_value),
        secret=secret(candidate, "VALIDATE"),
        domain=domain(candidate),
        binding=binding_value,
        idempotency_key=f"validate-{kind.value.lower()}",
        correlation_id=identifier(f"correlation:validate:{kind.value}"),
    )
    return candidate, binding_value, validated


def acquire_sample_lease(target: IngestionService, caller: TenantIdentity, candidate: SourceDefinition):
    binding_value = binding(candidate.connector_kind)
    return target.acquire_lease(
        caller,
        permit(caller, "knowledge.ingestion.lease.acquire", source_scope_digest(caller.organization_id, candidate.source_id)),
        candidate.source_id,
        partition="partition-0",
        owner_worker_id="worker-1",
        ttl_seconds=120,
        endpoint=endpoint(candidate, "LEASE", binding_value),
        secret=secret(candidate, "LEASE"),
        domain=domain(candidate),
        binding=binding_value,
        idempotency_key=f"lease-{candidate.connector_kind.value.lower()}",
        correlation_id=identifier(f"correlation:lease:{candidate.connector_kind.value}"),
    )


def sample(
    target: IngestionService,
    caller: TenantIdentity,
    candidate: SourceDefinition,
    binding_value: Binding,
    expected_revision: int,
    lease,
    *,
    port: FixturePort | None = None,
    staging: MemoryStagingPort | None = None,
    key: str | None = None,
):
    return target.sample_source(
        caller,
        permit(caller, "knowledge.ingestion.source.sample", source_scope_digest(caller.organization_id, candidate.source_id)),
        candidate.source_id,
        expected_revision=expected_revision,
        endpoint=endpoint(candidate, "SAMPLE", binding_value),
        secret=secret(candidate, "SAMPLE"),
        domain=domain(candidate),
        binding=binding_value,
        lease=lease,
        port=port or FixturePort(candidate.connector_kind),
        staging_port=staging or MemoryStagingPort(),
        parameters={"plant": "ankara"} if candidate.connector_kind is ConnectorKind.POSTGRESQL else None,
        checkpoint="position-100" if candidate.connector_kind is ConnectorKind.EVENT else None,
        idempotency_key=key or f"sample-{candidate.connector_kind.value.lower()}",
        correlation_id=identifier(f"correlation:sample:{candidate.connector_kind.value}"),
    )


def load_manifest() -> dict[str, object]:
    return json.loads((FIXTURE / "manifest.json").read_text(encoding="utf-8"))
