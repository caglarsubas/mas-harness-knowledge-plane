"""Independent deterministic support for KN-DATA-002 acceptance."""

from __future__ import annotations

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.ingestion.contracts import ConnectorKind
from planeon_knowledge.ingestion.readiness import (
    GateStatus,
    MeasurementObservation,
    OwnerApprovalAttestation,
    PrerequisiteGateObservation,
    ReadinessPolicyObservation,
    ReadinessThresholds,
)
from planeon_knowledge.ingestion.service import (
    ReadinessService,
    batch_scope_digest,
    work_scope_digest,
)

from tests.connectors.support import (
    Clock,
    DeterministicIds,
    acquire_sample_lease,
    create_and_validate,
    identifier,
    identity,
    permit,
    sample,
    service,
)

EVALUATED_AT = "2026-01-01T00:00:00Z"
VALID_UNTIL = "2026-01-02T00:00:00Z"
POLICY_EXPIRES = "2026-02-01T00:00:00Z"


def staged(kind: ConnectorKind = ConnectorKind.HTTP):
    caller = identity()
    clock = Clock(EVALUATED_AT)
    ingestion = service(clock=clock)
    source, binding, validated = create_and_validate(ingestion, caller, kind)
    lease = acquire_sample_lease(ingestion, caller, source)
    batch = sample(ingestion, caller, source, binding, validated.revision, lease)
    readiness = ReadinessService(store=ingestion.store, now=clock, new_id=DeterministicIds())
    return caller, clock, ingestion, readiness, source, binding, validated, lease, batch


def thresholds() -> ReadinessThresholds:
    return ReadinessThresholds("0.95", "0.8", "30", "120", "0.01", "0.05", "0.95", "0.8", "0.95", "0.8")


def policy_for(batch, *, illustrative: bool = False, organization_id: str | None = None, **changes) -> ReadinessPolicyObservation:
    values = {
        "organization_id": organization_id or batch.organization_id,
        "policy_id": "policy.white-goods-readiness",
        "version": "1.0.0",
        "thresholds": thresholds(),
        "illustrative": illustrative,
        "tenant_approval_digest": None if illustrative else canonical_digest({"tenantApproval": "approved"}),
        "effective_at": "2025-12-01T00:00:00Z",
        "expires_at": POLICY_EXPIRES,
    }
    values.update(changes)
    body = {
        "organizationId": values["organization_id"],
        "policyId": values["policy_id"],
        "version": values["version"],
        "thresholds": values["thresholds"].public_dict(),
        "illustrative": values["illustrative"],
        "tenantApprovalDigest": values["tenant_approval_digest"],
        "effectiveAt": values["effective_at"],
        "expiresAt": values["expires_at"],
    }
    return ReadinessPolicyObservation(**values, policy_digest=canonical_digest(body))


def prerequisite_gates(*, status: GateStatus = GateStatus.PASS) -> tuple[PrerequisiteGateObservation, ...]:
    return tuple(
        PrerequisiteGateObservation(
            gate_id,
            status,
            (f"evidence.{gate_id.replace('.', '-')}",) if status is GateStatus.PASS else (),
            "evidence.satisfied" if status is GateStatus.PASS else "evidence.needs-input",
        )
        for gate_id in ("business.owner", "business.outcome", "data.owner")
    )


def observation_for(batch, **changes) -> MeasurementObservation:
    record_count = batch.record_count
    values = {
        "organization_id": batch.organization_id,
        "source_id": batch.source_id,
        "source_version_digest": batch.source_version_digest,
        "batch_id": batch.batch_id,
        "batch_digest": batch.batch_digest,
        "material_digest": batch.material_digest,
        "record_set_digest": batch.record_set_digest,
        "checkpoint_candidate_digest": batch.checkpoint_candidate_digest,
        "partition": batch.partition,
        "expected_observation_count": record_count,
        "observed_record_count": record_count,
        "nonnull_required_field_count": record_count,
        "duplicate_observation_count": 0,
        "classified_observation_count": record_count,
        "provenanced_observation_count": record_count,
        "latest_source_observation_at": "2025-12-31T23:50:00Z",
        "questionnaire_session_id": "questionnaire.white-goods-setup",
        "evidence_id": "evidence.white-goods-measurement",
        "prerequisite_gates": prerequisite_gates(),
        "collected_at": "2025-12-31T23:55:00Z",
        "valid_until": VALID_UNTIL,
    }
    values.update(changes)
    body = {
        "organizationId": values["organization_id"],
        "sourceId": values["source_id"],
        "sourceVersionDigest": values["source_version_digest"],
        "batchId": values["batch_id"],
        "batchDigest": values["batch_digest"],
        "materialDigest": values["material_digest"],
        "recordSetDigest": values["record_set_digest"],
        "checkpointCandidateDigest": values["checkpoint_candidate_digest"],
        "partition": values["partition"],
        "expectedObservationCount": values["expected_observation_count"],
        "observedRecordCount": values["observed_record_count"],
        "nonnullRequiredFieldCount": values["nonnull_required_field_count"],
        "duplicateObservationCount": values["duplicate_observation_count"],
        "classifiedObservationCount": values["classified_observation_count"],
        "provenancedObservationCount": values["provenanced_observation_count"],
        "latestSourceObservationAt": values["latest_source_observation_at"],
        "questionnaireSessionId": values["questionnaire_session_id"],
        "evidenceId": values["evidence_id"],
        "prerequisiteGates": [item.public_dict() for item in values["prerequisite_gates"]],
        "collectedAt": values["collected_at"],
        "validUntil": values["valid_until"],
    }
    return MeasurementObservation(**values, observation_digest=canonical_digest(body))


def assess_and_complete(caller, readiness: ReadinessService, batch, *, policy=None, observation=None):
    policy = policy or policy_for(batch)
    observation = observation or observation_for(batch)
    work = readiness.request_assessment(
        caller,
        permit(caller, "knowledge.ingestion.staged-batch.assess", batch_scope_digest(caller.organization_id, batch.batch_id)),
        batch.batch_id,
        policy=policy,
        observation=observation,
        idempotency_key=f"assess-{batch.batch_id}",
        correlation_id=identifier(f"correlation:assess:{batch.batch_id}"),
    )
    claim = readiness.claim_assessment_work(
        caller,
        permit(caller, "knowledge.ingestion.readiness.process", work_scope_digest(caller.organization_id, work.work_id)),
        work.work_id,
        expected_revision=work.revision,
        ttl_seconds=60,
        correlation_id=identifier(f"correlation:claim:{batch.batch_id}"),
    )
    assessment = readiness.complete_assessment_work(
        caller,
        permit(caller, "knowledge.ingestion.readiness.process", work_scope_digest(caller.organization_id, work.work_id)),
        claim,
        correlation_id=identifier(f"correlation:complete:{batch.batch_id}"),
    )
    return work, claim, assessment


def approval_for(readiness: ReadinessService, source, batch, assessment, **changes) -> OwnerApprovalAttestation:
    snapshot = readiness.store.snapshot()
    evidence_id = snapshot.source_readiness_revisions[(batch.organization_id, batch.source_id)][-1].evidence_id
    evidence = snapshot.readiness_evidence[(batch.organization_id, evidence_id)]
    graph_id = snapshot.assessment_graph_ids[(batch.organization_id, assessment.assessment_id)]
    graph = snapshot.provenance_graphs[(batch.organization_id, graph_id)]
    values = {
        "approval_id": "approval.white-goods-owner",
        "organization_id": batch.organization_id,
        "owner_digest": source.owner_digest,
        "source_id": batch.source_id,
        "source_version_digest": batch.source_version_digest,
        "batch_id": batch.batch_id,
        "batch_digest": batch.batch_digest,
        "assessment_digest": assessment.assessment_digest,
        "evidence_record_digest": evidence.record_digest,
        "policy_digest": assessment.policy_digest,
        "provenance_digest": graph.graph_digest,
        "decision": "APPROVE",
        "verified": True,
        "issued_at": "2025-12-31T23:59:00Z",
        "expires_at": VALID_UNTIL,
    }
    values.update(changes)
    body = {
        "approvalId": values["approval_id"],
        "organizationId": values["organization_id"],
        "ownerDigest": values["owner_digest"],
        "sourceId": values["source_id"],
        "sourceVersionDigest": values["source_version_digest"],
        "batchId": values["batch_id"],
        "batchDigest": values["batch_digest"],
        "assessmentDigest": values["assessment_digest"],
        "evidenceRecordDigest": values["evidence_record_digest"],
        "policyDigest": values["policy_digest"],
        "provenanceDigest": values["provenance_digest"],
        "decision": values["decision"],
        "verified": values["verified"],
        "issuedAt": values["issued_at"],
        "expiresAt": values["expires_at"],
    }
    return OwnerApprovalAttestation(**values, approval_digest=canonical_digest(body))


def changed_observation(observation: MeasurementObservation, **changes) -> MeasurementObservation:
    values = {field: getattr(observation, field) for field in observation.__dataclass_fields__ if field != "observation_digest"}
    values.update(changes)
    body_keys = {
        "organization_id": "organizationId",
        "source_id": "sourceId",
        "source_version_digest": "sourceVersionDigest",
        "batch_id": "batchId",
        "batch_digest": "batchDigest",
        "material_digest": "materialDigest",
        "record_set_digest": "recordSetDigest",
        "checkpoint_candidate_digest": "checkpointCandidateDigest",
        "partition": "partition",
        "expected_observation_count": "expectedObservationCount",
        "observed_record_count": "observedRecordCount",
        "nonnull_required_field_count": "nonnullRequiredFieldCount",
        "duplicate_observation_count": "duplicateObservationCount",
        "classified_observation_count": "classifiedObservationCount",
        "provenanced_observation_count": "provenancedObservationCount",
        "latest_source_observation_at": "latestSourceObservationAt",
        "questionnaire_session_id": "questionnaireSessionId",
        "evidence_id": "evidenceId",
        "prerequisite_gates": "prerequisiteGates",
        "collected_at": "collectedAt",
        "valid_until": "validUntil",
    }
    body = {}
    for field, public_name in body_keys.items():
        value = values[field]
        body[public_name] = [item.public_dict() for item in value] if field == "prerequisite_gates" else value
    return MeasurementObservation(**values, observation_digest=canonical_digest(body))
