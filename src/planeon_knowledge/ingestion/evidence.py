"""Public EvidenceRecord projection and metadata-only readiness events."""

from __future__ import annotations

import re
from dataclasses import dataclass

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.common.validation import digest, token, utc_seconds, uuid_text

from .contracts import StagedBatch, positive_int, stable_id
from .provenance import ProvenanceGraph
from .readiness import DataReadinessAssessment, ReadinessDecision

SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")


@dataclass(frozen=True, slots=True)
class ReadinessEvidenceRecord:
    organization_id: str
    evidence_id: str
    version: str
    result: ReadinessDecision
    subject_id: str
    subject_digest: str
    evidence_digest: str
    provenance_digest: str
    collected_at: str
    valid_until: str
    control_ids: tuple[str, ...]
    record_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        stable_id(self.evidence_id, "evidenceId")
        if not isinstance(self.version, str) or SEMVER.fullmatch(self.version) is None:
            raise ValueError("evidence version is invalid")
        stable_id(self.subject_id, "subjectId")
        if not isinstance(self.result, ReadinessDecision):
            raise ValueError("evidence result is invalid")
        for field, value in (
            ("subjectDigest", self.subject_digest),
            ("evidenceDigest", self.evidence_digest),
            ("provenanceDigest", self.provenance_digest),
            ("recordDigest", self.record_digest),
        ):
            digest(value, field)
        utc_seconds(self.collected_at, "collectedAt")
        utc_seconds(self.valid_until, "validUntil")
        if self.collected_at >= self.valid_until:
            raise ValueError("evidence validity is invalid")
        for value in self.control_ids:
            stable_id(value, "controlId")
        if self.control_ids != tuple(sorted(set(self.control_ids))):
            raise ValueError("control ids must be sorted and unique")
        if self.record_digest != canonical_digest(self.public_document()):
            raise ValueError("evidence record digest mismatch")

    def public_document(self) -> dict[str, object]:
        organization_alias = f"organization.{self.organization_id.replace('-', '')}"
        return {
            "apiVersion": "harness.planeon.ai/v1alpha1",
            "kind": "EvidenceRecord",
            "metadata": {"id": self.evidence_id, "version": self.version},
            "spec": {
                "organizationId": organization_alias,
                "recordState": "VERIFIED",
                "axis": "SOURCE",
                "result": self.result.value,
                "subject": {
                    "kind": "data.batch",
                    "id": self.subject_id,
                    "digest": self.subject_digest,
                },
                "producer": {"type": "SYSTEM", "id": "knowledge.data-integration"},
                "producerAuthority": "PLATFORM",
                "evidenceDigest": self.evidence_digest,
                "provenanceDigest": self.provenance_digest,
                "collectedAt": self.collected_at,
                "validUntil": self.valid_until,
                "controlIds": list(self.control_ids),
                "campaignGenerated": False,
            },
        }


@dataclass(frozen=True, slots=True)
class ReadinessEvent:
    event_id: str
    organization_id: str
    source_id: str
    aggregate_version: int
    event_type: str
    batch_digest: str | None
    assessment_digest: str | None
    evidence_record_digest: str | None
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
        for field, value in (
            ("batchDigest", self.batch_digest),
            ("assessmentDigest", self.assessment_digest),
            ("evidenceRecordDigest", self.evidence_record_digest),
        ):
            if value is not None:
                digest(value, field)
        token(self.reason_code, "reasonCode")
        uuid_text(self.correlation_id, "correlationId")
        utc_seconds(self.occurred_at, "occurredAt")
        digest(self.event_digest, "eventDigest")
        if self.event_digest != canonical_digest(self.digest_body()):
            raise ValueError("readiness event digest mismatch")

    def digest_body(self) -> dict[str, object]:
        return {
            "eventId": self.event_id,
            "organizationId": self.organization_id,
            "sourceId": self.source_id,
            "aggregateVersion": self.aggregate_version,
            "eventType": self.event_type,
            "batchDigest": self.batch_digest,
            "assessmentDigest": self.assessment_digest,
            "evidenceRecordDigest": self.evidence_record_digest,
            "reasonCode": self.reason_code,
            "correlationId": self.correlation_id,
            "occurredAt": self.occurred_at,
        }


def build_evidence(
    assessment: DataReadinessAssessment,
    graph: ProvenanceGraph,
    batch: StagedBatch,
) -> ReadinessEvidenceRecord:
    seed = canonical_digest(
        {
            "assessmentDigest": assessment.assessment_digest,
            "provenanceDigest": graph.graph_digest,
            "batchDigest": batch.batch_digest,
        }
    )
    evidence_id = f"evidence.{seed.removeprefix('sha256:')[:24]}"
    subject_id = f"batch.{batch.batch_id.replace('-', '')}"
    controls = (
        "data.classification",
        "data.completeness",
        "data.duplicates",
        "data.freshness",
        "data.provenance",
    )
    temporary = {
        "apiVersion": "harness.planeon.ai/v1alpha1",
        "kind": "EvidenceRecord",
        "metadata": {"id": evidence_id, "version": assessment.version},
        "spec": {
            "organizationId": f"organization.{assessment.organization_id.replace('-', '')}",
            "recordState": "VERIFIED",
            "axis": "SOURCE",
            "result": assessment.decision.value,
            "subject": {"kind": "data.batch", "id": subject_id, "digest": batch.batch_digest},
            "producer": {"type": "SYSTEM", "id": "knowledge.data-integration"},
            "producerAuthority": "PLATFORM",
            "evidenceDigest": assessment.assessment_digest,
            "provenanceDigest": graph.graph_digest,
            "collectedAt": assessment.evaluated_at,
            "validUntil": assessment.valid_until,
            "controlIds": list(controls),
            "campaignGenerated": False,
        },
    }
    return ReadinessEvidenceRecord(
        assessment.organization_id,
        evidence_id,
        assessment.version,
        assessment.decision,
        subject_id,
        batch.batch_digest,
        assessment.assessment_digest,
        graph.graph_digest,
        assessment.evaluated_at,
        assessment.valid_until,
        controls,
        canonical_digest(temporary),
    )


def build_event(
    *,
    event_id: str,
    organization_id: str,
    source_id: str,
    aggregate_version: int,
    event_type: str,
    batch_digest: str | None,
    assessment_digest: str | None,
    evidence_record_digest: str | None,
    reason_code: str,
    correlation_id: str,
    occurred_at: str,
) -> ReadinessEvent:
    body = {
        "eventId": event_id,
        "organizationId": organization_id,
        "sourceId": source_id,
        "aggregateVersion": aggregate_version,
        "eventType": event_type,
        "batchDigest": batch_digest,
        "assessmentDigest": assessment_digest,
        "evidenceRecordDigest": evidence_record_digest,
        "reasonCode": reason_code,
        "correlationId": correlation_id,
        "occurredAt": occurred_at,
    }
    return ReadinessEvent(
        event_id,
        organization_id,
        source_id,
        aggregate_version,
        event_type,
        batch_digest,
        assessment_digest,
        evidence_record_digest,
        reason_code,
        correlation_id,
        occurred_at,
        canonical_digest(body),
    )
