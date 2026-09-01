"""Deterministic staged-batch assembly with transient material ports."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

from planeon_knowledge.common.canonical import canonical_digest

from .connectors.base import ConnectorPage
from .contracts import (
    BatchState,
    CheckpointCandidate,
    ConnectorObservation,
    LeaseRevision,
    SourceDefinition,
    StagedBatch,
    StagedRecordDigest,
    StagingReceipt,
)
from .decoder import DecodedEnvelope, DecoderFailure, decode


class BatchFailure(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


class StagingPort(Protocol):
    def prepare(
        self,
        *,
        organization_id: str,
        source_id: str,
        batch_id: str,
        material_digest: str,
        pages: tuple[ConnectorPage, ...],
        records: tuple[DecodedEnvelope, ...],
    ) -> StagingReceipt:
        """Prepare content-addressed material without publishing or committing it."""

    def abort(self, receipt: StagingReceipt) -> None:
        """Discard or quarantine one unadvertised preparation after metadata failure."""


@dataclass(frozen=True, slots=True)
class BatchBuild:
    batch: StagedBatch
    records: tuple[StagedRecordDigest, ...]
    checkpoint: CheckpointCandidate
    observation: ConnectorObservation
    receipt: StagingReceipt


def _sequence_digest(label: str, values: tuple[str, ...]) -> str:
    hasher = hashlib.sha256()
    hasher.update(label.encode("ascii"))
    hasher.update(len(values).to_bytes(8, "big"))
    for value in values:
        encoded = value.encode("ascii")
        hasher.update(len(encoded).to_bytes(4, "big"))
        hasher.update(encoded)
    return f"sha256:{hasher.hexdigest()}"


def _receipt_digest(receipt: StagingReceipt) -> str:
    return canonical_digest({
        "receiptId": receipt.receipt_id,
        "organizationId": receipt.organization_id,
        "sourceId": receipt.source_id,
        "batchId": receipt.batch_id,
        "materialDigest": receipt.material_digest,
        "byteCount": receipt.byte_count,
        "recordCount": receipt.record_count,
        "prepared": receipt.prepared,
    })


def build_staged_batch(
    *,
    source: SourceDefinition,
    lease: LeaseRevision,
    pages: tuple[ConnectorPage, ...],
    batch_id: str,
    staged_at: str,
    request_digest: str,
    staging_port: StagingPort,
) -> BatchBuild:
    if not pages or len(pages) > 32:
        raise BatchFailure("PAGE_COUNT_INVALID")
    media_types = {page.media_type for page in pages}
    if len(media_types) != 1:
        raise BatchFailure("MEDIA_TYPE_DRIFT")
    byte_count = sum(len(page.payload) for page in pages)
    if byte_count > source.max_bytes:
        raise BatchFailure("SAMPLE_SIZE_EXCEEDED")

    decoded: list[DecodedEnvelope] = []
    try:
        for page in pages:
            remaining = source.max_records - len(decoded)
            if remaining <= 0:
                raise BatchFailure("RECORD_LIMIT_EXCEEDED")
            for envelope in decode(page.payload, page.media_type, max_records=remaining):
                record = envelope.record
                if record.schema_digest != source.expected_schema_digest:
                    raise BatchFailure("SCHEMA_DIGEST_MISMATCH")
                global_record = type(record)(len(decoded), record.record_digest, record.schema_digest, record.encoded_bytes)
                decoded.append(DecodedEnvelope(global_record, envelope.canonical_bytes))
    except DecoderFailure as exc:
        raise BatchFailure(exc.reason_code) from exc
    if not decoded:
        raise BatchFailure("RECORDS_MISSING")

    material_digest = _sequence_digest("planeon-staged-material-v1", tuple(page.payload_digest for page in pages))
    record_set_digest = _sequence_digest("planeon-staged-records-v1", tuple(item.record.record_digest for item in decoded))
    last_checkpoint = next((page.checkpoint_token for page in reversed(pages) if page.checkpoint_token is not None), None)
    checkpoint_digest = canonical_digest({
        "organizationId": source.organization_id,
        "sourceId": source.source_id,
        "sourceVersionDigest": source.resource_digest,
        "connectorKind": source.connector_kind.value,
        "opaqueCheckpoint": last_checkpoint,
        "materialDigest": material_digest,
    })
    checkpoint = CheckpointCandidate(source.organization_id, source.source_id, source.resource_digest, checkpoint_digest, staged_at)

    staged_records = tuple(
        StagedRecordDigest(
            source.organization_id,
            batch_id,
            item.record.ordinal,
            item.record.record_digest,
            item.record.schema_digest,
            item.record.encoded_bytes,
        )
        for item in decoded
    )
    try:
        receipt = staging_port.prepare(
            organization_id=source.organization_id,
            source_id=source.source_id,
            batch_id=batch_id,
            material_digest=material_digest,
            pages=pages,
            records=tuple(decoded),
        )
    except Exception as exc:
        raise BatchFailure("STAGING_SINK_UNAVAILABLE") from exc
    if (
        receipt.organization_id != source.organization_id
        or receipt.source_id != source.source_id
        or receipt.batch_id != batch_id
        or receipt.material_digest != material_digest
        or receipt.byte_count != byte_count
        or receipt.record_count != len(decoded)
        or receipt.receipt_digest != _receipt_digest(receipt)
    ):
        try:
            staging_port.abort(receipt)
        finally:
            raise BatchFailure("STAGING_RECEIPT_MISMATCH")

    observation_body = {
        "organizationId": source.organization_id,
        "sourceId": source.source_id,
        "connectorKind": source.connector_kind.value,
        "requestDigest": request_digest,
        "responseDigest": material_digest,
        "mediaType": pages[0].media_type,
        "byteCount": byte_count,
        "recordHint": len(decoded),
        "readOnly": True,
        "reasonCodes": [],
        "observedAt": max(page.observed_at for page in pages),
    }
    observation = ConnectorObservation(
        source.organization_id,
        source.source_id,
        source.connector_kind,
        request_digest,
        material_digest,
        pages[0].media_type,
        byte_count,
        len(decoded),
        True,
        (),
        observation_body["observedAt"],
        canonical_digest(observation_body),
    )
    batch_body = {
        "organizationId": source.organization_id,
        "batchId": batch_id,
        "sourceId": source.source_id,
        "sourceVersionDigest": source.resource_digest,
        "expectedSchemaDigest": source.expected_schema_digest,
        "activeDomainVersionDigest": source.active_domain_version_digest,
        "semanticMappingDigest": source.semantic_mapping_digest,
        "materialDigest": material_digest,
        "checkpointCandidateDigest": checkpoint_digest,
        "mediaType": pages[0].media_type,
        "connectorKind": source.connector_kind.value,
        "state": BatchState.STAGED.value,
        "recordCount": len(decoded),
        "byteCount": byte_count,
        "recordSetDigest": record_set_digest,
        "fencingToken": lease.fencing_token,
        "stagedAt": staged_at,
    }
    batch = StagedBatch(
        source.organization_id,
        batch_id,
        source.source_id,
        source.resource_digest,
        source.expected_schema_digest,
        source.active_domain_version_digest,
        source.semantic_mapping_digest,
        material_digest,
        checkpoint_digest,
        pages[0].media_type,
        source.connector_kind,
        BatchState.STAGED,
        len(decoded),
        byte_count,
        record_set_digest,
        lease.fencing_token,
        staged_at,
        canonical_digest(batch_body),
    )
    return BatchBuild(batch, staged_records, checkpoint, observation, receipt)
