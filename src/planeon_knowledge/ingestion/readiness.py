"""Closed readiness contracts and deterministic metadata-only evaluation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.common.validation import digest, token, utc_seconds, uuid_text

from .classification import classification_band, classification_coverage
from .contracts import StagedBatch, optional_digest, positive_int, stable_id
from .coverage import (
    CoverageFailure,
    canonical_decimal,
    decimal_value,
    maximum_band,
    minimum_band,
    ratio,
)
from .freshness import freshness_band, freshness_minutes, parse_time

SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
GATE_ORDER = (
    "business.owner",
    "business.outcome",
    "data.owner",
    "data.quality",
    "data.completeness",
    "data.freshness",
    "data.provenance",
    "data.classification",
    "integration.readiness",
    "autonomy.boundary",
)
PREREQUISITE_GATES = GATE_ORDER[:3]


class ReadinessFailure(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


class ReadinessDecision(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


class GateStatus(StrEnum):
    PASS = "PASS"
    NEEDS_INPUT = "NEEDS_INPUT"
    BLOCKED = "BLOCKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class SourceReadinessState(StrEnum):
    READY_FOR_APPROVAL = "READY_FOR_APPROVAL"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    REVOKED = "REVOKED"


@dataclass(frozen=True, slots=True)
class ReadinessThresholds:
    completeness_pass_minimum: str
    completeness_warn_minimum: str
    freshness_pass_maximum_minutes: str
    freshness_warn_maximum_minutes: str
    duplicate_pass_maximum: str
    duplicate_warn_maximum: str
    classification_pass_minimum: str
    classification_warn_minimum: str
    provenance_pass_minimum: str
    provenance_warn_minimum: str

    def parsed(self) -> dict[str, Decimal]:
        try:
            values = {
                "completenessPassMinimum": decimal_value(
                    self.completeness_pass_minimum, "completenessPassMinimum", maximum=Decimal(1)
                ),
                "completenessWarnMinimum": decimal_value(
                    self.completeness_warn_minimum, "completenessWarnMinimum", maximum=Decimal(1)
                ),
                "freshnessPassMaximumMinutes": decimal_value(
                    self.freshness_pass_maximum_minutes,
                    "freshnessPassMaximumMinutes",
                    maximum=Decimal(10080),
                ),
                "freshnessWarnMaximumMinutes": decimal_value(
                    self.freshness_warn_maximum_minutes,
                    "freshnessWarnMaximumMinutes",
                    maximum=Decimal(10080),
                ),
                "duplicatePassMaximum": decimal_value(
                    self.duplicate_pass_maximum, "duplicatePassMaximum", maximum=Decimal(1)
                ),
                "duplicateWarnMaximum": decimal_value(
                    self.duplicate_warn_maximum, "duplicateWarnMaximum", maximum=Decimal(1)
                ),
                "classificationPassMinimum": decimal_value(
                    self.classification_pass_minimum, "classificationPassMinimum", maximum=Decimal(1)
                ),
                "classificationWarnMinimum": decimal_value(
                    self.classification_warn_minimum, "classificationWarnMinimum", maximum=Decimal(1)
                ),
                "provenancePassMinimum": decimal_value(
                    self.provenance_pass_minimum, "provenancePassMinimum", maximum=Decimal(1)
                ),
                "provenanceWarnMinimum": decimal_value(
                    self.provenance_warn_minimum, "provenanceWarnMinimum", maximum=Decimal(1)
                ),
            }
            minimum_band(
                Decimal(0), values["completenessPassMinimum"], values["completenessWarnMinimum"]
            )
            maximum_band(
                Decimal(0),
                values["freshnessPassMaximumMinutes"],
                values["freshnessWarnMaximumMinutes"],
            )
            maximum_band(
                Decimal(0), values["duplicatePassMaximum"], values["duplicateWarnMaximum"]
            )
            minimum_band(
                Decimal(0),
                values["classificationPassMinimum"],
                values["classificationWarnMinimum"],
            )
            minimum_band(
                Decimal(0), values["provenancePassMinimum"], values["provenanceWarnMinimum"]
            )
            return values
        except CoverageFailure as exc:
            raise ReadinessFailure(exc.reason_code) from exc

    def public_dict(self) -> dict[str, str]:
        return {
            "completenessPassMinimum": self.completeness_pass_minimum,
            "completenessWarnMinimum": self.completeness_warn_minimum,
            "freshnessPassMaximumMinutes": self.freshness_pass_maximum_minutes,
            "freshnessWarnMaximumMinutes": self.freshness_warn_maximum_minutes,
            "duplicatePassMaximum": self.duplicate_pass_maximum,
            "duplicateWarnMaximum": self.duplicate_warn_maximum,
            "classificationPassMinimum": self.classification_pass_minimum,
            "classificationWarnMinimum": self.classification_warn_minimum,
            "provenancePassMinimum": self.provenance_pass_minimum,
            "provenanceWarnMinimum": self.provenance_warn_minimum,
        }


@dataclass(frozen=True, slots=True)
class ReadinessPolicyObservation:
    organization_id: str
    policy_id: str
    version: str
    thresholds: ReadinessThresholds
    illustrative: bool
    tenant_approval_digest: str | None
    effective_at: str
    expires_at: str
    policy_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        stable_id(self.policy_id, "policyId")
        if not isinstance(self.version, str) or SEMVER.fullmatch(self.version) is None:
            raise ValueError("policy version is invalid")
        if type(self.illustrative) is not bool:
            raise ValueError("illustrative must be boolean")
        self.thresholds.parsed()
        optional_digest(self.tenant_approval_digest, "tenantApprovalDigest")
        if self.illustrative and self.tenant_approval_digest is not None:
            raise ValueError("illustrative policy cannot carry tenant approval")
        if not self.illustrative and self.tenant_approval_digest is None:
            raise ValueError("tenant policy approval is required")
        utc_seconds(self.effective_at, "effectiveAt")
        utc_seconds(self.expires_at, "expiresAt")
        if parse_time(self.effective_at) >= parse_time(self.expires_at):
            raise ValueError("policy validity is invalid")
        digest(self.policy_digest, "policyDigest")
        if self.policy_digest != canonical_digest(self.digest_body()):
            raise ValueError("policy digest mismatch")

    def digest_body(self) -> dict[str, object]:
        return {
            "organizationId": self.organization_id,
            "policyId": self.policy_id,
            "version": self.version,
            "thresholds": self.thresholds.public_dict(),
            "illustrative": self.illustrative,
            "tenantApprovalDigest": self.tenant_approval_digest,
            "effectiveAt": self.effective_at,
            "expiresAt": self.expires_at,
        }


@dataclass(frozen=True, slots=True)
class PrerequisiteGateObservation:
    gate_id: str
    status: GateStatus
    evidence_ids: tuple[str, ...]
    reason_code: str

    def __post_init__(self) -> None:
        if self.gate_id not in PREREQUISITE_GATES:
            raise ValueError("prerequisite gate id is invalid")
        if self.status not in {GateStatus.PASS, GateStatus.NEEDS_INPUT, GateStatus.BLOCKED}:
            raise ValueError("prerequisite gate status is invalid")
        for value in self.evidence_ids:
            stable_id(value, "evidenceId")
        if self.evidence_ids != tuple(sorted(set(self.evidence_ids))):
            raise ValueError("prerequisite evidence ids must be sorted and unique")
        if self.status is GateStatus.PASS and not self.evidence_ids:
            raise ValueError("passing prerequisite requires evidence")
        stable_id(self.reason_code, "reasonCode")

    def public_dict(self) -> dict[str, object]:
        return {
            "gateId": self.gate_id,
            "status": self.status.value,
            "evidenceIds": list(self.evidence_ids),
            "reasonCode": self.reason_code,
        }


def _non_negative(value: int, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 10_000:
        raise ValueError(f"{field} is outside the closed range")
    return value


@dataclass(frozen=True, slots=True)
class MeasurementObservation:
    organization_id: str
    source_id: str
    source_version_digest: str
    batch_id: str
    batch_digest: str
    material_digest: str
    record_set_digest: str
    checkpoint_candidate_digest: str
    partition: str
    expected_observation_count: int
    observed_record_count: int
    nonnull_required_field_count: int
    duplicate_observation_count: int
    classified_observation_count: int
    provenanced_observation_count: int
    latest_source_observation_at: str | None
    questionnaire_session_id: str
    evidence_id: str
    prerequisite_gates: tuple[PrerequisiteGateObservation, ...]
    collected_at: str
    valid_until: str
    observation_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.source_id, "sourceId")
        uuid_text(self.batch_id, "batchId")
        for field, value in (
            ("sourceVersionDigest", self.source_version_digest),
            ("batchDigest", self.batch_digest),
            ("materialDigest", self.material_digest),
            ("recordSetDigest", self.record_set_digest),
            ("checkpointCandidateDigest", self.checkpoint_candidate_digest),
        ):
            digest(value, field)
        token(self.partition, "partition")
        for field, value in (
            ("expectedObservationCount", self.expected_observation_count),
            ("observedRecordCount", self.observed_record_count),
            ("nonnullRequiredFieldCount", self.nonnull_required_field_count),
            ("duplicateObservationCount", self.duplicate_observation_count),
            ("classifiedObservationCount", self.classified_observation_count),
            ("provenancedObservationCount", self.provenanced_observation_count),
        ):
            _non_negative(value, field)
        if self.observed_record_count > self.expected_observation_count:
            raise ValueError("observed count exceeds expected count")
        if any(
            value > self.observed_record_count
            for value in (
                self.nonnull_required_field_count,
                self.duplicate_observation_count,
                self.classified_observation_count,
                self.provenanced_observation_count,
            )
        ):
            raise ValueError("measurement count exceeds observations")
        if self.observed_record_count == 0:
            if self.latest_source_observation_at is not None:
                raise ValueError("missing data cannot have a latest observation")
        else:
            if self.latest_source_observation_at is None:
                raise ValueError("latest source observation is required")
            utc_seconds(self.latest_source_observation_at, "latestSourceObservationAt")
        stable_id(self.questionnaire_session_id, "questionnaireSessionId")
        stable_id(self.evidence_id, "evidenceId")
        if tuple(item.gate_id for item in self.prerequisite_gates) != PREREQUISITE_GATES:
            raise ValueError("prerequisite gates must use the exact order")
        utc_seconds(self.collected_at, "collectedAt")
        utc_seconds(self.valid_until, "validUntil")
        if parse_time(self.collected_at) >= parse_time(self.valid_until):
            raise ValueError("measurement validity is invalid")
        digest(self.observation_digest, "observationDigest")
        if self.observation_digest != canonical_digest(self.digest_body()):
            raise ValueError("measurement observation digest mismatch")

    def digest_body(self) -> dict[str, object]:
        return {
            "organizationId": self.organization_id,
            "sourceId": self.source_id,
            "sourceVersionDigest": self.source_version_digest,
            "batchId": self.batch_id,
            "batchDigest": self.batch_digest,
            "materialDigest": self.material_digest,
            "recordSetDigest": self.record_set_digest,
            "checkpointCandidateDigest": self.checkpoint_candidate_digest,
            "partition": self.partition,
            "expectedObservationCount": self.expected_observation_count,
            "observedRecordCount": self.observed_record_count,
            "nonnullRequiredFieldCount": self.nonnull_required_field_count,
            "duplicateObservationCount": self.duplicate_observation_count,
            "classifiedObservationCount": self.classified_observation_count,
            "provenancedObservationCount": self.provenanced_observation_count,
            "latestSourceObservationAt": self.latest_source_observation_at,
            "questionnaireSessionId": self.questionnaire_session_id,
            "evidenceId": self.evidence_id,
            "prerequisiteGates": [item.public_dict() for item in self.prerequisite_gates],
            "collectedAt": self.collected_at,
            "validUntil": self.valid_until,
        }


@dataclass(frozen=True, slots=True)
class ReadinessFinding:
    finding_id: str
    metric_id: str
    decision: ReadinessDecision
    reason_code: str
    observed_value: str | None
    policy_digest: str
    observation_digest: str
    batch_digest: str
    finding_digest: str

    def __post_init__(self) -> None:
        stable_id(self.finding_id, "findingId")
        stable_id(self.metric_id, "metricId")
        if not isinstance(self.decision, ReadinessDecision):
            raise ValueError("finding decision is invalid")
        token(self.reason_code, "reasonCode")
        if self.observed_value is not None and (
            not isinstance(self.observed_value, str) or len(self.observed_value) > 32
        ):
            raise ValueError("observed value is invalid")
        for field, value in (
            ("policyDigest", self.policy_digest),
            ("observationDigest", self.observation_digest),
            ("batchDigest", self.batch_digest),
            ("findingDigest", self.finding_digest),
        ):
            digest(value, field)
        if self.finding_digest != canonical_digest(self.digest_body()):
            raise ValueError("finding digest mismatch")

    def digest_body(self) -> dict[str, object]:
        return {
            "metricId": self.metric_id,
            "decision": self.decision.value,
            "reasonCode": self.reason_code,
            "observedValue": self.observed_value,
            "policyDigest": self.policy_digest,
            "observationDigest": self.observation_digest,
            "batchDigest": self.batch_digest,
        }


@dataclass(frozen=True, slots=True)
class GateResult:
    gate_id: str
    status: GateStatus
    evidence_ids: tuple[str, ...]
    reason_code: str

    def __post_init__(self) -> None:
        if self.gate_id not in GATE_ORDER or not isinstance(self.status, GateStatus):
            raise ValueError("gate result is invalid")
        for value in self.evidence_ids:
            stable_id(value, "evidenceId")
        if self.evidence_ids != tuple(sorted(set(self.evidence_ids))):
            raise ValueError("gate evidence ids must be sorted and unique")
        stable_id(self.reason_code, "reasonCode")

    def public_dict(self) -> dict[str, object]:
        return {
            "gateId": self.gate_id,
            "status": self.status.value,
            "evidenceIds": list(self.evidence_ids),
            "reasonCode": self.reason_code,
        }


@dataclass(frozen=True, slots=True)
class DataReadinessAssessment:
    organization_id: str
    assessment_id: str
    version: str
    source_id: str
    batch_id: str
    policy_digest: str
    observation_digest: str
    decision: ReadinessDecision
    questionnaire_session_id: str
    overall_status: str
    gate_results: tuple[GateResult, ...]
    missing_gate_ids: tuple[str, ...]
    evaluated_at: str
    valid_until: str
    assessment_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        stable_id(self.assessment_id, "assessmentId")
        if SEMVER.fullmatch(self.version) is None:
            raise ValueError("assessment version is invalid")
        uuid_text(self.source_id, "sourceId")
        uuid_text(self.batch_id, "batchId")
        digest(self.policy_digest, "policyDigest")
        digest(self.observation_digest, "observationDigest")
        if not isinstance(self.decision, ReadinessDecision):
            raise ValueError("assessment decision is invalid")
        stable_id(self.questionnaire_session_id, "questionnaireSessionId")
        if self.overall_status not in {"READY", "BLOCKED"}:
            raise ValueError("assessment overall status is invalid")
        if tuple(item.gate_id for item in self.gate_results) != GATE_ORDER:
            raise ValueError("assessment gate order is invalid")
        if self.missing_gate_ids != tuple(sorted(set(self.missing_gate_ids))):
            raise ValueError("missing gate ids must be sorted and unique")
        if any(value not in GATE_ORDER for value in self.missing_gate_ids):
            raise ValueError("missing gate id is invalid")
        derived_missing = tuple(
            sorted(
                item.gate_id
                for item in self.gate_results
                if item.status in {GateStatus.NEEDS_INPUT, GateStatus.BLOCKED}
            )
        )
        if self.missing_gate_ids != derived_missing:
            raise ValueError("assessment missing gates are inconsistent")
        derived_decision = (
            ReadinessDecision.FAIL
            if any(item.status is GateStatus.BLOCKED for item in self.gate_results)
            else ReadinessDecision.WARN
            if any(item.status is GateStatus.NEEDS_INPUT for item in self.gate_results)
            else ReadinessDecision.PASS
        )
        if self.decision is not derived_decision:
            raise ValueError("assessment decision is inconsistent")
        if (self.overall_status == "READY") is not (self.decision is ReadinessDecision.PASS):
            raise ValueError("assessment overall status is inconsistent")
        utc_seconds(self.evaluated_at, "evaluatedAt")
        utc_seconds(self.valid_until, "validUntil")
        if parse_time(self.evaluated_at) >= parse_time(self.valid_until):
            raise ValueError("assessment validity is invalid")
        digest(self.assessment_digest, "assessmentDigest")
        if self.assessment_digest != canonical_digest(self.public_document()):
            raise ValueError("assessment digest mismatch")

    def public_document(self) -> dict[str, object]:
        return {
            "apiVersion": "harness.planeon.ai/v1alpha1",
            "kind": "DataReadinessAssessment",
            "metadata": {"id": self.assessment_id, "version": self.version},
            "spec": {
                "questionnaireSessionId": self.questionnaire_session_id,
                "overallStatus": self.overall_status,
                "gateResults": [item.public_dict() for item in self.gate_results],
                "missingGateIds": list(self.missing_gate_ids),
            },
        }


@dataclass(frozen=True, slots=True)
class SourceReadinessRevision:
    organization_id: str
    source_id: str
    revision: int
    state: SourceReadinessState
    batch_id: str | None
    assessment_id: str | None
    assessment_digest: str | None
    evidence_id: str | None
    evidence_record_digest: str | None
    policy_digest: str | None
    reason_code: str
    occurred_at: str
    valid_until: str | None
    correlation_id: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.source_id, "sourceId")
        positive_int(self.revision, "revision", 2**63 - 1)
        if not isinstance(self.state, SourceReadinessState):
            raise ValueError("source readiness state is invalid")
        if self.batch_id is not None:
            uuid_text(self.batch_id, "batchId")
        if self.assessment_id is not None:
            stable_id(self.assessment_id, "assessmentId")
        optional_digest(self.assessment_digest, "assessmentDigest")
        if self.evidence_id is not None:
            stable_id(self.evidence_id, "evidenceId")
        optional_digest(self.evidence_record_digest, "evidenceRecordDigest")
        optional_digest(self.policy_digest, "policyDigest")
        token(self.reason_code, "reasonCode")
        utc_seconds(self.occurred_at, "occurredAt")
        if self.valid_until is not None:
            utc_seconds(self.valid_until, "validUntil")
        uuid_text(self.correlation_id, "correlationId")
        bound = (
            self.batch_id,
            self.assessment_id,
            self.assessment_digest,
            self.evidence_id,
            self.evidence_record_digest,
            self.policy_digest,
        )
        if self.state in {SourceReadinessState.READY_FOR_APPROVAL, SourceReadinessState.ACTIVE}:
            if any(value is None for value in bound) or self.valid_until is None:
                raise ValueError("ready source revision is incomplete")
        if self.state is SourceReadinessState.REVOKED:
            if any(value is not None for value in bound) or self.valid_until is not None:
                raise ValueError("revoked source revision must clear pointers")


@dataclass(frozen=True, slots=True)
class OwnerApprovalAttestation:
    approval_id: str
    organization_id: str
    owner_digest: str
    source_id: str
    source_version_digest: str
    batch_id: str
    batch_digest: str
    assessment_digest: str
    evidence_record_digest: str
    policy_digest: str
    provenance_digest: str
    decision: str
    verified: bool
    issued_at: str
    expires_at: str
    approval_digest: str

    def __post_init__(self) -> None:
        stable_id(self.approval_id, "approvalId")
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.source_id, "sourceId")
        uuid_text(self.batch_id, "batchId")
        for field, value in (
            ("ownerDigest", self.owner_digest),
            ("sourceVersionDigest", self.source_version_digest),
            ("batchDigest", self.batch_digest),
            ("assessmentDigest", self.assessment_digest),
            ("evidenceRecordDigest", self.evidence_record_digest),
            ("policyDigest", self.policy_digest),
            ("provenanceDigest", self.provenance_digest),
            ("approvalDigest", self.approval_digest),
        ):
            digest(value, field)
        if self.decision != "APPROVE" or self.verified is not True:
            raise ValueError("owner approval is not verified APPROVE")
        utc_seconds(self.issued_at, "issuedAt")
        utc_seconds(self.expires_at, "expiresAt")
        if parse_time(self.issued_at) >= parse_time(self.expires_at):
            raise ValueError("owner approval validity is invalid")
        if self.approval_digest != canonical_digest(self.digest_body()):
            raise ValueError("owner approval digest mismatch")

    def digest_body(self) -> dict[str, object]:
        return {
            "approvalId": self.approval_id,
            "organizationId": self.organization_id,
            "ownerDigest": self.owner_digest,
            "sourceId": self.source_id,
            "sourceVersionDigest": self.source_version_digest,
            "batchId": self.batch_id,
            "batchDigest": self.batch_digest,
            "assessmentDigest": self.assessment_digest,
            "evidenceRecordDigest": self.evidence_record_digest,
            "policyDigest": self.policy_digest,
            "provenanceDigest": self.provenance_digest,
            "decision": self.decision,
            "verified": self.verified,
            "issuedAt": self.issued_at,
            "expiresAt": self.expires_at,
        }


@dataclass(frozen=True, slots=True)
class BatchCommit:
    organization_id: str
    source_id: str
    source_version_digest: str
    batch_id: str
    batch_digest: str
    partition: str
    assessment_digest: str
    evidence_record_digest: str
    policy_digest: str
    provenance_digest: str
    approval_digest: str
    checkpoint_digest: str
    fencing_token: int
    committed_at: str
    commit_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.source_id, "sourceId")
        uuid_text(self.batch_id, "batchId")
        token(self.partition, "partition")
        for field, value in (
            ("sourceVersionDigest", self.source_version_digest),
            ("batchDigest", self.batch_digest),
            ("assessmentDigest", self.assessment_digest),
            ("evidenceRecordDigest", self.evidence_record_digest),
            ("policyDigest", self.policy_digest),
            ("provenanceDigest", self.provenance_digest),
            ("approvalDigest", self.approval_digest),
            ("checkpointDigest", self.checkpoint_digest),
            ("commitDigest", self.commit_digest),
        ):
            digest(value, field)
        positive_int(self.fencing_token, "fencingToken", 2**63 - 1)
        utc_seconds(self.committed_at, "committedAt")
        if self.commit_digest != canonical_digest(self.digest_body()):
            raise ValueError("batch commit digest mismatch")

    def digest_body(self) -> dict[str, object]:
        return {
            "organizationId": self.organization_id,
            "sourceId": self.source_id,
            "sourceVersionDigest": self.source_version_digest,
            "batchId": self.batch_id,
            "batchDigest": self.batch_digest,
            "partition": self.partition,
            "assessmentDigest": self.assessment_digest,
            "evidenceRecordDigest": self.evidence_record_digest,
            "policyDigest": self.policy_digest,
            "provenanceDigest": self.provenance_digest,
            "approvalDigest": self.approval_digest,
            "checkpointDigest": self.checkpoint_digest,
            "fencingToken": self.fencing_token,
            "committedAt": self.committed_at,
        }


@dataclass(frozen=True, slots=True)
class CheckpointRevision:
    organization_id: str
    source_id: str
    source_version_digest: str
    partition: str
    revision: int
    batch_id: str
    batch_digest: str
    checkpoint_digest: str
    fencing_token: int
    batch_staged_at: str
    activated_at: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.source_id, "sourceId")
        uuid_text(self.batch_id, "batchId")
        digest(self.source_version_digest, "sourceVersionDigest")
        token(self.partition, "partition")
        positive_int(self.revision, "revision", 2**63 - 1)
        digest(self.batch_digest, "batchDigest")
        digest(self.checkpoint_digest, "checkpointDigest")
        positive_int(self.fencing_token, "fencingToken", 2**63 - 1)
        utc_seconds(self.batch_staged_at, "batchStagedAt")
        utc_seconds(self.activated_at, "activatedAt")
        if parse_time(self.activated_at) < parse_time(self.batch_staged_at):
            raise ValueError("checkpoint activation predates the staged batch")


def _decision_status(decision: ReadinessDecision) -> GateStatus:
    return {
        ReadinessDecision.PASS: GateStatus.PASS,
        ReadinessDecision.WARN: GateStatus.NEEDS_INPUT,
        ReadinessDecision.FAIL: GateStatus.BLOCKED,
    }[decision]


def _worst(decisions: tuple[ReadinessDecision, ...]) -> ReadinessDecision:
    if ReadinessDecision.FAIL in decisions:
        return ReadinessDecision.FAIL
    if ReadinessDecision.WARN in decisions:
        return ReadinessDecision.WARN
    return ReadinessDecision.PASS


def _finding(
    *,
    metric_id: str,
    decision: ReadinessDecision,
    reason_code: str,
    observed_value: str | None,
    policy: ReadinessPolicyObservation,
    observation: MeasurementObservation,
) -> ReadinessFinding:
    body = {
        "metricId": metric_id,
        "decision": decision.value,
        "reasonCode": reason_code,
        "observedValue": observed_value,
        "policyDigest": policy.policy_digest,
        "observationDigest": observation.observation_digest,
        "batchDigest": observation.batch_digest,
    }
    finding_digest = canonical_digest(body)
    finding_id = f"finding.{finding_digest.removeprefix('sha256:')[:24]}"
    return ReadinessFinding(
        finding_id,
        metric_id,
        decision,
        reason_code,
        observed_value,
        policy.policy_digest,
        observation.observation_digest,
        observation.batch_digest,
        finding_digest,
    )


def _mapped_finding(
    metric_id: str,
    band: str,
    observed_value: Decimal,
    policy: ReadinessPolicyObservation,
    observation: MeasurementObservation,
    reasons: tuple[str, str, str],
) -> ReadinessFinding:
    decision = ReadinessDecision(band)
    reason = reasons[{"PASS": 0, "WARN": 1, "FAIL": 2}[band]]
    return _finding(
        metric_id=metric_id,
        decision=decision,
        reason_code=reason,
        observed_value=canonical_decimal(observed_value),
        policy=policy,
        observation=observation,
    )


def _metric_gate(metric_id: str, finding: ReadinessFinding, evidence_id: str) -> GateResult:
    reason = {
        "data.completeness": {
            ReadinessDecision.PASS: "evidence.satisfied",
            ReadinessDecision.WARN: "data.completeness-needs-input",
            ReadinessDecision.FAIL: "data.incomplete",
        },
        "data.freshness": {
            ReadinessDecision.PASS: "evidence.satisfied",
            ReadinessDecision.WARN: "data.freshness-needs-input",
            ReadinessDecision.FAIL: "data.stale",
        },
        "data.provenance": {
            ReadinessDecision.PASS: "evidence.satisfied",
            ReadinessDecision.WARN: "data.provenance-needs-input",
            ReadinessDecision.FAIL: "data.unprovenanced",
        },
        "data.classification": {
            ReadinessDecision.PASS: "evidence.satisfied",
            ReadinessDecision.WARN: "data.classification-needs-input",
            ReadinessDecision.FAIL: "data.unclassified",
        },
    }[metric_id][finding.decision]
    return GateResult(metric_id, _decision_status(finding.decision), (evidence_id,), reason)


def evaluate_readiness(
    *,
    policy: ReadinessPolicyObservation,
    observation: MeasurementObservation,
    batch: StagedBatch,
    evaluated_at: str,
    parity_mode: bool = False,
) -> tuple[tuple[ReadinessFinding, ...], DataReadinessAssessment]:
    utc_seconds(evaluated_at, "evaluatedAt")
    now = parse_time(evaluated_at)
    if policy.organization_id != observation.organization_id or policy.organization_id != batch.organization_id:
        raise ReadinessFailure("TENANT_MISMATCH")
    if policy.illustrative and not parity_mode:
        raise ReadinessFailure("POLICY_NOT_TENANT_APPROVED")
    if not (parse_time(policy.effective_at) <= now < parse_time(policy.expires_at)):
        raise ReadinessFailure("POLICY_STALE")
    if not (parse_time(observation.collected_at) <= now < parse_time(observation.valid_until)):
        raise ReadinessFailure("MEASUREMENT_STALE")
    expected = (
        observation.source_id,
        observation.source_version_digest,
        observation.batch_id,
        observation.batch_digest,
        observation.material_digest,
        observation.record_set_digest,
        observation.checkpoint_candidate_digest,
        observation.partition,
    )
    actual = (
        batch.source_id,
        batch.source_version_digest,
        batch.batch_id,
        batch.batch_digest,
        batch.material_digest,
        batch.record_set_digest,
        batch.checkpoint_candidate_digest,
        batch.partition,
    )
    if expected != actual:
        raise ReadinessFailure("MEASUREMENT_SCOPE_MISMATCH")
    if not parity_mode and observation.observed_record_count != batch.record_count:
        raise ReadinessFailure("MEASUREMENT_COUNT_MISMATCH")

    thresholds = policy.thresholds.parsed()
    if observation.observed_record_count == 0:
        findings = (
            _finding(
                metric_id="data.quality",
                decision=ReadinessDecision.FAIL,
                reason_code="MISSING_DATA",
                observed_value=None,
                policy=policy,
                observation=observation,
            ),
        )
        quality_gate = GateResult("data.quality", GateStatus.BLOCKED, (), "data.missing")
        metric_gates = (
            GateResult("data.completeness", GateStatus.NOT_APPLICABLE, (), "data.no-observations"),
            GateResult("data.freshness", GateStatus.NOT_APPLICABLE, (), "data.no-observations"),
            GateResult("data.provenance", GateStatus.NOT_APPLICABLE, (), "data.no-observations"),
            GateResult("data.classification", GateStatus.NOT_APPLICABLE, (), "data.no-observations"),
        )
        metric_decision = ReadinessDecision.FAIL
    else:
        try:
            completeness = ratio(
                observation.nonnull_required_field_count, observation.expected_observation_count
            )
            duplicate_rate = ratio(
                observation.duplicate_observation_count, observation.observed_record_count
            )
            classification = classification_coverage(
                observation.classified_observation_count, observation.observed_record_count
            )
            provenance = ratio(
                observation.provenanced_observation_count, observation.observed_record_count
            )
            freshness = freshness_minutes(evaluated_at, observation.latest_source_observation_at or "")
            findings = (
                _mapped_finding(
                    "data.classification",
                    classification_band(
                        classification,
                        thresholds["classificationPassMinimum"],
                        thresholds["classificationWarnMinimum"],
                    ),
                    classification,
                    policy,
                    observation,
                    ("CLASSIFICATION_COMPLETE", "CLASSIFICATION_NEEDS_INPUT", "UNCLASSIFIED_DATA"),
                ),
                _mapped_finding(
                    "data.completeness",
                    minimum_band(
                        completeness,
                        thresholds["completenessPassMinimum"],
                        thresholds["completenessWarnMinimum"],
                    ),
                    completeness,
                    policy,
                    observation,
                    ("DATA_COMPLETE", "COMPLETENESS_NEEDS_INPUT", "INCOMPLETE_DATA"),
                ),
                _mapped_finding(
                    "data.duplicates",
                    maximum_band(
                        duplicate_rate,
                        thresholds["duplicatePassMaximum"],
                        thresholds["duplicateWarnMaximum"],
                    ),
                    duplicate_rate,
                    policy,
                    observation,
                    ("DUPLICATES_ACCEPTABLE", "DUPLICATES_NEED_INPUT", "DUPLICATE_DATA"),
                ),
                _mapped_finding(
                    "data.freshness",
                    freshness_band(
                        freshness,
                        thresholds["freshnessPassMaximumMinutes"],
                        thresholds["freshnessWarnMaximumMinutes"],
                    ),
                    freshness,
                    policy,
                    observation,
                    ("DATA_FRESH", "FRESHNESS_NEEDS_INPUT", "STALE_DATA"),
                ),
                _mapped_finding(
                    "data.provenance",
                    minimum_band(
                        provenance,
                        thresholds["provenancePassMinimum"],
                        thresholds["provenanceWarnMinimum"],
                    ),
                    provenance,
                    policy,
                    observation,
                    ("PROVENANCE_COMPLETE", "PROVENANCE_NEEDS_INPUT", "UNPROVENANCED_DATA"),
                ),
            )
        except CoverageFailure as exc:
            raise ReadinessFailure(exc.reason_code) from exc
        findings = tuple(sorted(findings, key=lambda item: (item.metric_id, item.reason_code)))
        metric_decision = _worst(tuple(item.decision for item in findings))
        quality_reason = {
            ReadinessDecision.PASS: "evidence.satisfied",
            ReadinessDecision.WARN: "data.quality-needs-input",
            ReadinessDecision.FAIL: "data.quality-blocked",
        }[metric_decision]
        if next(item for item in findings if item.metric_id == "data.duplicates").decision is not ReadinessDecision.PASS:
            duplicate_decision = next(
                item.decision for item in findings if item.metric_id == "data.duplicates"
            )
            if duplicate_decision is ReadinessDecision.FAIL:
                quality_reason = "data.duplicate"
        quality_gate = GateResult(
            "data.quality",
            _decision_status(metric_decision),
            (observation.evidence_id,),
            quality_reason,
        )
        metric_gates = tuple(
            _metric_gate(metric_id, next(item for item in findings if item.metric_id == metric_id), observation.evidence_id)
            for metric_id in (
                "data.completeness",
                "data.freshness",
                "data.provenance",
                "data.classification",
            )
        )

    prerequisite_decisions = tuple(
        ReadinessDecision.PASS
        if item.status is GateStatus.PASS
        else ReadinessDecision.WARN
        if item.status is GateStatus.NEEDS_INPUT
        else ReadinessDecision.FAIL
        for item in observation.prerequisite_gates
    )
    decision = _worst((metric_decision, *prerequisite_decisions))
    gates = tuple(
        [
            GateResult(item.gate_id, item.status, item.evidence_ids, item.reason_code)
            for item in observation.prerequisite_gates
        ]
        + [quality_gate]
        + list(metric_gates)
        + [
            GateResult("integration.readiness", GateStatus.NOT_APPLICABLE, (), "scope.not-applicable"),
            GateResult("autonomy.boundary", GateStatus.NOT_APPLICABLE, (), "scope.not-applicable"),
        ]
    )
    missing = tuple(
        sorted(
            item.gate_id
            for item in gates
            if item.status in {GateStatus.NEEDS_INPUT, GateStatus.BLOCKED}
        )
    )
    identity_digest = canonical_digest(
        {
            "organizationId": observation.organization_id,
            "batchId": observation.batch_id,
            "policyDigest": policy.policy_digest,
            "observationDigest": observation.observation_digest,
            "evaluatedAt": evaluated_at,
        }
    )
    assessment_id = f"readiness.{identity_digest.removeprefix('sha256:')[:24]}"
    valid_until = min(policy.expires_at, observation.valid_until)
    overall_status = "READY" if decision is ReadinessDecision.PASS else "BLOCKED"
    public_document = {
        "apiVersion": "harness.planeon.ai/v1alpha1",
        "kind": "DataReadinessAssessment",
        "metadata": {"id": assessment_id, "version": policy.version},
        "spec": {
            "questionnaireSessionId": observation.questionnaire_session_id,
            "overallStatus": overall_status,
            "gateResults": [item.public_dict() for item in gates],
            "missingGateIds": list(missing),
        },
    }
    assessment = DataReadinessAssessment(
        observation.organization_id,
        assessment_id,
        policy.version,
        observation.source_id,
        observation.batch_id,
        policy.policy_digest,
        observation.observation_digest,
        decision,
        observation.questionnaire_session_id,
        overall_status,
        gates,
        missing,
        evaluated_at,
        valid_until,
        canonical_digest(public_document),
    )
    return findings, assessment
