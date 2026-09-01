"""Fail-closed source, lease, and staged-sample lifecycle service."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Mapping
from uuid import uuid4

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.common.models import TenantIdentity
from planeon_knowledge.common.validation import token, uuid_text

from .batch import BatchBuild, BatchFailure, StagingPort, build_staged_batch
from .connectors import Binding, ConnectorFailure, ConnectorPort, binding_digest, execute
from .contracts import (
    AccessPermit,
    ConnectorKind,
    ConnectorProfile,
    DomainBindingObservation,
    EndpointGrant,
    IngestionEvidence,
    IngestionEvent,
    LeaseRevision,
    ReadPlan,
    SecretGrant,
    SourceDefinition,
    SourceRevision,
    SourceState,
    StagedBatch,
    public_dict,
)
from .leases import LeaseFailure, acquire, assert_current, release, renew
from .evidence import ReadinessEvidenceRecord, build_evidence, build_event
from .provenance import ProvenanceEdge, ProvenanceGraph, ProvenanceNode, build_graph
from .readiness import (
    BatchCommit,
    CheckpointRevision,
    DataReadinessAssessment,
    MeasurementObservation,
    OwnerApprovalAttestation,
    ReadinessDecision,
    ReadinessFailure,
    ReadinessFinding,
    ReadinessPolicyObservation,
    SourceReadinessRevision,
    SourceReadinessState,
    evaluate_readiness,
)
from .retries import (
    DeadLetterRecord,
    DeadLetterReview,
    ReadinessWorkRevision,
    RetryFailure,
    WorkState,
    build_dead_letter,
    build_review,
    claim_work,
    fail_work,
    finish_work,
    new_work,
)
from .store import InMemoryIngestionStore, LeaseKey, SourceKey, StoreState


class IngestionFailure(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _parse_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _domain_observation_digest(value: DomainBindingObservation) -> str:
    return canonical_digest({
        "organizationId": value.organization_id,
        "sourceId": value.source_id,
        "activeDomainVersionDigest": value.active_domain_version_digest,
        "semanticMappingDigest": value.semantic_mapping_digest,
        "domainActive": value.domain_active,
        "mappingActive": value.mapping_active,
        "observedAt": value.observed_at,
        "expiresAt": value.expires_at,
    })


def source_scope_digest(organization_id: str, source_id: str) -> str:
    return canonical_digest({"organizationId": organization_id, "sourceId": source_id})


def batch_scope_digest(organization_id: str, batch_id: str) -> str:
    return canonical_digest({"organizationId": organization_id, "batchId": batch_id})


def readiness_scope_digest(organization_id: str, source_id: str) -> str:
    return canonical_digest({"organizationId": organization_id, "sourceId": source_id, "scope": "readiness"})


def work_scope_digest(organization_id: str, work_id: str) -> str:
    return canonical_digest({"organizationId": organization_id, "workId": work_id})


def assessment_scope_digest(organization_id: str, assessment_id: str) -> str:
    return canonical_digest({"organizationId": organization_id, "assessmentId": assessment_id})


def dead_letter_scope_digest(organization_id: str, dead_letter_id: str) -> str:
    return canonical_digest({"organizationId": organization_id, "deadLetterId": dead_letter_id})


class IngestionService:
    def __init__(
        self,
        *,
        store: InMemoryIngestionStore,
        profiles: Mapping[ConnectorKind, ConnectorProfile],
        now: Callable[[], str],
        new_id: Callable[[], str] = lambda: str(uuid4()),
    ) -> None:
        expected = set(ConnectorKind)
        if set(profiles) != expected or any(kind is not profile.connector_kind for kind, profile in profiles.items()):
            raise ValueError("exactly four connector profiles are required")
        self.store = store
        self.profiles = dict(profiles)
        self.now = now
        self.new_id = new_id

    @staticmethod
    def _command_fields(idempotency_key: str, correlation_id: str) -> None:
        try:
            token(idempotency_key, "idempotencyKey")
            uuid_text(correlation_id, "correlationId")
        except ValueError as exc:
            raise IngestionFailure("COMMAND_METADATA_INVALID") from exc

    @staticmethod
    def _identity(identity: TenantIdentity, source: SourceDefinition) -> None:
        if identity.organization_id != source.organization_id or identity.subject_id != source.created_by_subject_id:
            raise IngestionFailure("IDENTITY_MISMATCH")

    def _authorize(self, identity: TenantIdentity, permit: AccessPermit, action: str, resource_digest: str) -> None:
        self._preauthorize(identity, permit, action)
        if permit.resource_digest != resource_digest:
            raise IngestionFailure("POLICY_DENIED")

    def _preauthorize(self, identity: TenantIdentity, permit: AccessPermit, action: str) -> None:
        if (
            not permit.allowed
            or permit.organization_id != identity.organization_id
            or permit.subject_id != identity.subject_id
            or permit.action != action
            or _parse_time(permit.expires_at) <= _parse_time(self.now())
        ):
            raise IngestionFailure("POLICY_DENIED")

    def authorize_scope(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        action: str,
        resource_digest: str,
    ) -> None:
        """Authorize an adapter dependency lookup before any owned state is read."""
        self._authorize(identity, permit, action, resource_digest)

    @staticmethod
    def _idempotent(state: StoreState, organization_id: str, key: str, request_digest: str) -> object | None:
        existing = state.idempotency.get((organization_id, key))
        if existing is None:
            return None
        if existing[0] != request_digest:
            raise IngestionFailure("IDEMPOTENCY_CONFLICT")
        return existing[1]

    def _dependencies(
        self,
        source: SourceDefinition,
        *,
        operation: str,
        endpoint: EndpointGrant,
        secret: SecretGrant | None,
        domain: DomainBindingObservation,
        binding: Binding,
    ) -> tuple[str, str]:
        current_time = _parse_time(self.now())
        if (
            not endpoint.allowed
            or endpoint.organization_id != source.organization_id
            or endpoint.source_id != source.source_id
            or endpoint.connector_kind is not source.connector_kind
            or endpoint.operation != operation
            or endpoint.endpoint_ref_digest != source.endpoint_ref_digest
            or endpoint.network_policy_digest != source.network_policy_digest
            or endpoint.binding_digest != binding_digest(binding)
            or _parse_time(endpoint.expires_at) <= current_time
        ):
            raise IngestionFailure("ENDPOINT_GRANT_DENIED")
        if source.credential_ref_digest is None:
            if secret is not None:
                raise IngestionFailure("SECRET_GRANT_UNEXPECTED")
        elif (
            secret is None
            or not secret.allowed
            or secret.organization_id != source.organization_id
            or secret.source_id != source.source_id
            or secret.operation != operation
            or secret.credential_ref_digest != source.credential_ref_digest
            or _parse_time(secret.expires_at) <= current_time
        ):
            raise IngestionFailure("SECRET_GRANT_DENIED")
        if (
            domain.organization_id != source.organization_id
            or domain.source_id != source.source_id
            or domain.active_domain_version_digest != source.active_domain_version_digest
            or domain.semantic_mapping_digest != source.semantic_mapping_digest
            or not domain.domain_active
            or not domain.mapping_active
            or _parse_time(domain.observed_at) > current_time
            or _parse_time(domain.expires_at) <= current_time
            or domain.observation_digest != _domain_observation_digest(domain)
        ):
            raise IngestionFailure("DOMAIN_BINDING_DENIED")
        profile = self.profiles[source.connector_kind]
        if profile.profile_digest != source.profile_digest:
            raise IngestionFailure("CONNECTOR_PROFILE_DENIED")
        return canonical_digest(public_dict(endpoint)), domain.observation_digest

    def _evidence_event(
        self,
        state: StoreState,
        *,
        source: SourceDefinition,
        revision: SourceRevision,
        reason_code: str,
        correlation_id: str,
        batch_digest: str | None = None,
        endpoint_grant_digest: str | None = None,
        domain_observation_digest: str | None = None,
    ) -> IngestionEvidence:
        evidence_body = {
            "organizationId": source.organization_id,
            "sourceId": source.source_id,
            "sourceVersionDigest": source.resource_digest,
            "sourceState": revision.state.value,
            "sourceRevision": revision.revision,
            "batchDigest": batch_digest,
            "endpointGrantDigest": endpoint_grant_digest,
            "domainObservationDigest": domain_observation_digest,
            "reasonCode": reason_code,
            "occurredAt": revision.occurred_at,
        }
        evidence = IngestionEvidence(
            source.organization_id,
            source.source_id,
            source.resource_digest,
            revision.state,
            revision.revision,
            batch_digest,
            endpoint_grant_digest,
            domain_observation_digest,
            reason_code,
            revision.occurred_at,
            canonical_digest(evidence_body),
        )
        suffix = {
            SourceState.DECLARED: "declared",
            SourceState.VALID: "validated",
            SourceState.INVALID: "invalid",
            SourceState.SAMPLED: "sample-staged",
            SourceState.DISABLED: "disabled",
        }.get(revision.state)
        if suffix is None:
            return evidence
        event_body = {
            "eventId": self.new_id(),
            "organizationId": source.organization_id,
            "sourceId": source.source_id,
            "aggregateVersion": revision.revision,
            "eventType": f"data.source.{suffix}.v1",
            "sourceVersionDigest": source.resource_digest,
            "evidenceDigest": evidence.record_digest,
            "batchDigest": batch_digest,
            "reasonCode": reason_code,
            "correlationId": correlation_id,
            "occurredAt": revision.occurred_at,
        }
        event = IngestionEvent(
            event_body["eventId"],
            source.organization_id,
            source.source_id,
            revision.revision,
            event_body["eventType"],
            source.resource_digest,
            evidence.record_digest,
            batch_digest,
            reason_code,
            correlation_id,
            revision.occurred_at,
            canonical_digest(event_body),
        )
        state.evidence.append(evidence)
        state.events.append(event)
        return evidence

    def create_source(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        source: SourceDefinition,
        *,
        idempotency_key: str,
        correlation_id: str,
    ) -> SourceRevision:
        self._command_fields(idempotency_key, correlation_id)
        self._identity(identity, source)
        request_digest = canonical_digest(public_dict(source))
        self._authorize(identity, permit, "knowledge.ingestion.source.create", request_digest)

        def operation(state: StoreState) -> SourceRevision:
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay  # type: ignore[return-value]
            key: SourceKey = (identity.organization_id, source.source_id)
            if key in state.sources:
                raise IngestionFailure("SOURCE_ALREADY_EXISTS")
            revision = SourceRevision(source.organization_id, source.source_id, source.resource_digest, 1, SourceState.DECLARED, "SOURCE_DECLARED", self.now(), correlation_id)
            state.sources[key] = source
            state.source_revisions[key] = [revision]
            self._evidence_event(state, source=source, revision=revision, reason_code=revision.reason_code, correlation_id=correlation_id)
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, revision)
            return revision

        return self.store.transact(operation)

    def get_source(self, identity: TenantIdentity, permit: AccessPermit, source_id: str) -> tuple[SourceDefinition, SourceRevision]:
        self._authorize(
            identity,
            permit,
            "knowledge.ingestion.source.read",
            source_scope_digest(identity.organization_id, source_id),
        )
        key = (identity.organization_id, source_id)
        result = self.store.read(lambda state: (state.sources.get(key), state.source_revisions.get(key)))
        if result[0] is None or not result[1]:
            raise IngestionFailure("SOURCE_NOT_FOUND")
        source = result[0]
        return source, result[1][-1]

    def validate_source(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        source_id: str,
        *,
        expected_revision: int,
        endpoint: EndpointGrant,
        secret: SecretGrant | None,
        domain: DomainBindingObservation,
        binding: Binding,
        idempotency_key: str,
        correlation_id: str,
    ) -> SourceRevision:
        self._command_fields(idempotency_key, correlation_id)
        self._authorize(
            identity,
            permit,
            "knowledge.ingestion.source.validate",
            source_scope_digest(identity.organization_id, source_id),
        )
        key: SourceKey = (identity.organization_id, source_id)
        source = self.store.read(lambda state: state.sources.get(key))
        if source is None:
            raise IngestionFailure("SOURCE_NOT_FOUND")
        endpoint_digest, domain_digest = self._dependencies(source, operation="VALIDATE", endpoint=endpoint, secret=secret, domain=domain, binding=binding)
        request_digest = canonical_digest({"sourceVersionDigest": source.resource_digest, "expectedRevision": expected_revision, "endpointGrantDigest": endpoint_digest, "domainObservationDigest": domain_digest})

        def operation(state: StoreState) -> SourceRevision:
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay  # type: ignore[return-value]
            current = state.source_revisions[key][-1]
            if current.revision != expected_revision:
                raise IngestionFailure("STALE_REVISION")
            if current.state is not SourceState.DECLARED:
                raise IngestionFailure("TRANSITION_FORBIDDEN")
            validating = SourceRevision(source.organization_id, source.source_id, source.resource_digest, expected_revision + 1, SourceState.VALIDATING, "SOURCE_VALIDATION_STARTED", self.now(), correlation_id)
            valid = SourceRevision(source.organization_id, source.source_id, source.resource_digest, expected_revision + 2, SourceState.VALID, "SOURCE_CONTRACT_VALIDATED", self.now(), correlation_id)
            state.source_revisions[key].extend((validating, valid))
            self._evidence_event(state, source=source, revision=valid, reason_code=valid.reason_code, correlation_id=correlation_id, endpoint_grant_digest=endpoint_digest, domain_observation_digest=domain_digest)
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, valid)
            return valid

        return self.store.transact(operation)

    def invalidate_source(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        source_id: str,
        *,
        expected_revision: int,
        reason_code: str,
        idempotency_key: str,
        correlation_id: str,
    ) -> SourceRevision:
        self._command_fields(idempotency_key, correlation_id)
        self._authorize(
            identity,
            permit,
            "knowledge.ingestion.source.validate",
            source_scope_digest(identity.organization_id, source_id),
        )
        if reason_code not in {"CONNECTOR_PROFILE_INVALID", "DOMAIN_BINDING_INVALID", "SOURCE_SCHEMA_INVALID"}:
            raise IngestionFailure("REASON_CODE_INVALID")
        key = (identity.organization_id, source_id)
        source = self.store.read(lambda state: state.sources.get(key))
        if source is None:
            raise IngestionFailure("SOURCE_NOT_FOUND")
        request_digest = canonical_digest({"sourceVersionDigest": source.resource_digest, "expectedRevision": expected_revision, "reasonCode": reason_code})

        def operation(state: StoreState) -> SourceRevision:
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay  # type: ignore[return-value]
            current = state.source_revisions[key][-1]
            if current.revision != expected_revision or current.state is not SourceState.DECLARED:
                raise IngestionFailure("TRANSITION_FORBIDDEN")
            validating = SourceRevision(source.organization_id, source.source_id, source.resource_digest, expected_revision + 1, SourceState.VALIDATING, "SOURCE_VALIDATION_STARTED", self.now(), correlation_id)
            invalid = SourceRevision(source.organization_id, source.source_id, source.resource_digest, expected_revision + 2, SourceState.INVALID, reason_code, self.now(), correlation_id)
            state.source_revisions[key].extend((validating, invalid))
            self._evidence_event(state, source=source, revision=invalid, reason_code=reason_code, correlation_id=correlation_id)
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, invalid)
            return invalid

        return self.store.transact(operation)

    def acquire_lease(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        source_id: str,
        *,
        partition: str,
        owner_worker_id: str,
        ttl_seconds: int,
        endpoint: EndpointGrant,
        secret: SecretGrant | None,
        domain: DomainBindingObservation,
        binding: Binding,
        idempotency_key: str,
        correlation_id: str,
    ) -> LeaseRevision:
        self._command_fields(idempotency_key, correlation_id)
        self._authorize(
            identity,
            permit,
            "knowledge.ingestion.lease.acquire",
            source_scope_digest(identity.organization_id, source_id),
        )
        key: SourceKey = (identity.organization_id, source_id)
        source_state = self.store.read(lambda state: (state.sources.get(key), state.source_revisions.get(key)))
        if source_state[0] is None or not source_state[1]:
            raise IngestionFailure("SOURCE_NOT_FOUND")
        source: SourceDefinition = source_state[0]
        if source_state[1][-1].state not in {SourceState.VALID, SourceState.SAMPLED}:
            raise IngestionFailure("SOURCE_NOT_LEASABLE")
        endpoint_digest, domain_digest = self._dependencies(
            source,
            operation="LEASE",
            endpoint=endpoint,
            secret=secret,
            domain=domain,
            binding=binding,
        )
        request_digest = canonical_digest({
            "sourceVersionDigest": source.resource_digest,
            "partition": partition,
            "ownerWorkerId": owner_worker_id,
            "ttlSeconds": ttl_seconds,
            "endpointGrantDigest": endpoint_digest,
            "domainObservationDigest": domain_digest,
        })

        def operation(state: StoreState) -> LeaseRevision:
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay  # type: ignore[return-value]
            lease_key: LeaseKey = (identity.organization_id, source_id, partition)
            history = tuple(state.lease_revisions.get(lease_key, ()))
            try:
                additions = acquire(
                    history,
                    organization_id=identity.organization_id,
                    source_id=source_id,
                    source_version_digest=source.resource_digest,
                    partition=partition,
                    owner_worker_id=owner_worker_id,
                    ttl_seconds=ttl_seconds,
                    now=self.now(),
                    lease_id=self.new_id(),
                    correlation_id=correlation_id,
                )
            except (ValueError, LeaseFailure) as exc:
                raise IngestionFailure(getattr(exc, "reason_code", "LEASE_INVALID")) from exc
            state.lease_revisions.setdefault(lease_key, []).extend(additions)
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, additions[-1])
            return additions[-1]

        return self.store.transact(operation)

    def renew_lease(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        supplied: LeaseRevision,
        *,
        ttl_seconds: int,
        endpoint: EndpointGrant,
        secret: SecretGrant | None,
        domain: DomainBindingObservation,
        binding: Binding,
        idempotency_key: str,
        correlation_id: str,
    ) -> LeaseRevision:
        return self._change_lease(
            identity,
            permit,
            supplied,
            ttl_seconds=ttl_seconds,
            release_lease=False,
            endpoint=endpoint,
            secret=secret,
            domain=domain,
            binding=binding,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
        )

    def release_lease(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        supplied: LeaseRevision,
        *,
        idempotency_key: str,
        correlation_id: str,
    ) -> LeaseRevision:
        return self._change_lease(
            identity,
            permit,
            supplied,
            ttl_seconds=None,
            release_lease=True,
            endpoint=None,
            secret=None,
            domain=None,
            binding=None,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
        )

    def _change_lease(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        supplied: LeaseRevision,
        *,
        ttl_seconds: int | None,
        release_lease: bool,
        endpoint: EndpointGrant | None,
        secret: SecretGrant | None,
        domain: DomainBindingObservation | None,
        binding: Binding | None,
        idempotency_key: str,
        correlation_id: str,
    ) -> LeaseRevision:
        self._command_fields(idempotency_key, correlation_id)
        if supplied.organization_id != identity.organization_id:
            raise IngestionFailure("LEASE_SCOPE_MISMATCH")
        action = "knowledge.ingestion.lease.release" if release_lease else "knowledge.ingestion.lease.renew"
        self._authorize(
            identity,
            permit,
            action,
            source_scope_digest(identity.organization_id, supplied.source_id),
        )
        source = self.store.read(lambda state: state.sources.get((identity.organization_id, supplied.source_id)))
        if source is None or source.resource_digest != supplied.source_version_digest:
            raise IngestionFailure("SOURCE_NOT_FOUND")
        dependency_digests: tuple[str, str] | None = None
        if not release_lease:
            if endpoint is None or domain is None or binding is None:
                raise IngestionFailure("DEPENDENCY_UNAVAILABLE")
            dependency_digests = self._dependencies(
                source,
                operation="LEASE",
                endpoint=endpoint,
                secret=secret,
                domain=domain,
                binding=binding,
            )
        request_digest = canonical_digest({
            "leaseId": supplied.lease_id,
            "revision": supplied.revision,
            "fencingToken": supplied.fencing_token,
            "ownerWorkerId": supplied.owner_worker_id,
            "ttlSeconds": ttl_seconds,
            "action": action,
            "dependencyDigests": list(dependency_digests) if dependency_digests is not None else None,
        })

        def operation(state: StoreState) -> LeaseRevision:
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay  # type: ignore[return-value]
            lease_key = (identity.organization_id, supplied.source_id, supplied.partition)
            history = state.lease_revisions.get(lease_key)
            if not history:
                raise IngestionFailure("LEASE_NOT_FOUND")
            current = history[-1]
            try:
                changed = release(
                    current,
                    expected_revision=supplied.revision,
                    lease_id=supplied.lease_id,
                    owner_worker_id=supplied.owner_worker_id,
                    fencing_token=supplied.fencing_token,
                    now=self.now(),
                    correlation_id=correlation_id,
                ) if release_lease else renew(
                    current,
                    expected_revision=supplied.revision,
                    lease_id=supplied.lease_id,
                    owner_worker_id=supplied.owner_worker_id,
                    fencing_token=supplied.fencing_token,
                    ttl_seconds=ttl_seconds if ttl_seconds is not None else 0,
                    now=self.now(),
                    correlation_id=correlation_id,
                )
            except (ValueError, LeaseFailure) as exc:
                raise IngestionFailure(getattr(exc, "reason_code", "LEASE_INVALID")) from exc
            history.append(changed)
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, changed)
            return changed

        return self.store.transact(operation)

    def sample_source(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        source_id: str,
        *,
        expected_revision: int,
        endpoint: EndpointGrant,
        secret: SecretGrant | None,
        domain: DomainBindingObservation,
        binding: Binding,
        lease: LeaseRevision,
        port: ConnectorPort,
        staging_port: StagingPort,
        parameters: object | None,
        checkpoint: str | None,
        idempotency_key: str,
        correlation_id: str,
    ) -> StagedBatch:
        self._command_fields(idempotency_key, correlation_id)
        self._authorize(
            identity,
            permit,
            "knowledge.ingestion.source.sample",
            source_scope_digest(identity.organization_id, source_id),
        )
        key: SourceKey = (identity.organization_id, source_id)
        source = self.store.read(lambda state: state.sources.get(key))
        if source is None:
            raise IngestionFailure("SOURCE_NOT_FOUND")
        endpoint_digest, domain_digest = self._dependencies(source, operation="SAMPLE", endpoint=endpoint, secret=secret, domain=domain, binding=binding)
        parameter_digest = canonical_digest(parameters if parameters is not None else {})
        checkpoint_input_digest = canonical_digest({"checkpoint": checkpoint})
        request_digest = canonical_digest({
            "sourceVersionDigest": source.resource_digest,
            "expectedRevision": expected_revision,
            "endpointGrantDigest": endpoint_digest,
            "domainObservationDigest": domain_digest,
            "bindingDigest": binding_digest(binding),
            "leaseId": lease.lease_id,
            "leaseRevision": lease.revision,
            "fencingToken": lease.fencing_token,
            "parameterDigest": parameter_digest,
            "checkpointInputDigest": checkpoint_input_digest,
        })
        replay = self.store.read(lambda state: self._idempotent(state, identity.organization_id, idempotency_key, request_digest))
        if replay is not None:
            if isinstance(replay, SourceRevision):
                raise IngestionFailure(replay.reason_code)
            return replay  # type: ignore[return-value]
        current_source_revision = self.store.read(lambda state: state.source_revisions.get(key, [None])[-1])
        if current_source_revision is None:
            raise IngestionFailure("SOURCE_NOT_FOUND")
        if current_source_revision.revision != expected_revision:
            raise IngestionFailure("STALE_REVISION")
        if current_source_revision.state not in {SourceState.VALID, SourceState.SAMPLED}:
            raise IngestionFailure("TRANSITION_FORBIDDEN")
        lease_key: LeaseKey = (identity.organization_id, source_id, lease.partition)
        current_lease = self.store.read(lambda state: state.lease_revisions.get(lease_key, [None])[-1])
        try:
            assert_current(current_lease, lease, organization_id=identity.organization_id, source_id=source_id, source_version_digest=source.resource_digest, now=self.now())
        except LeaseFailure as exc:
            raise IngestionFailure(exc.reason_code) from exc
        profile = self.profiles[source.connector_kind]
        plan = ReadPlan(
            identity.organization_id,
            source_id,
            source.resource_digest,
            source.connector_kind,
            endpoint.grant_id,
            endpoint.binding_digest,
            lease.lease_id,
            lease.revision,
            lease.fencing_token,
            source.max_records,
            source.max_bytes,
            profile.max_pages,
            source.deadline_ms,
            request_digest,
        )
        try:
            pages = execute(plan, binding, port, parameters=parameters, checkpoint=checkpoint)
            batch_id = self.new_id()
            build = build_staged_batch(
                source=source,
                lease=lease,
                pages=pages,
                batch_id=batch_id,
                staged_at=self.now(),
                request_digest=request_digest,
                staging_port=staging_port,
            )
        except BatchFailure as exc:
            if exc.reason_code in {"STAGING_RECEIPT_MISMATCH", "STAGING_SINK_UNAVAILABLE"}:
                raise IngestionFailure(exc.reason_code) from exc
            self._record_sample_failure(source, expected_revision, request_digest, idempotency_key, correlation_id, exc.reason_code, endpoint_digest, domain_digest)
            raise IngestionFailure(exc.reason_code) from exc
        except ConnectorFailure as exc:
            self._record_sample_failure(source, expected_revision, request_digest, idempotency_key, correlation_id, exc.reason_code, endpoint_digest, domain_digest)
            raise IngestionFailure(exc.reason_code) from exc
        except Exception as exc:
            self._record_sample_failure(source, expected_revision, request_digest, idempotency_key, correlation_id, "CONNECTOR_DEPENDENCY_UNAVAILABLE", endpoint_digest, domain_digest)
            raise IngestionFailure("CONNECTOR_DEPENDENCY_UNAVAILABLE") from exc

        try:
            return self._commit_sample(source, lease_key, lease, expected_revision, request_digest, idempotency_key, correlation_id, endpoint_digest, domain_digest, build)
        except Exception:
            try:
                staging_port.abort(build.receipt)
            finally:
                raise

    def _record_sample_failure(
        self,
        source: SourceDefinition,
        expected_revision: int,
        request_digest: str,
        idempotency_key: str,
        correlation_id: str,
        reason_code: str,
        endpoint_digest: str,
        domain_digest: str,
    ) -> None:
        key = (source.organization_id, source.source_id)

        def operation(state: StoreState) -> SourceRevision:
            current = state.source_revisions[key][-1]
            if current.revision != expected_revision or current.state not in {SourceState.VALID, SourceState.SAMPLED}:
                raise IngestionFailure("TRANSITION_FORBIDDEN")
            sampling = SourceRevision(source.organization_id, source.source_id, source.resource_digest, expected_revision + 1, SourceState.SAMPLING, "SOURCE_SAMPLING_STARTED", self.now(), correlation_id)
            invalid = SourceRevision(source.organization_id, source.source_id, source.resource_digest, expected_revision + 2, SourceState.INVALID, reason_code, self.now(), correlation_id)
            state.source_revisions[key].extend((sampling, invalid))
            self._evidence_event(state, source=source, revision=invalid, reason_code=reason_code, correlation_id=correlation_id, endpoint_grant_digest=endpoint_digest, domain_observation_digest=domain_digest)
            state.idempotency[(source.organization_id, idempotency_key)] = (request_digest, invalid)
            return invalid

        self.store.transact(operation)

    def _commit_sample(
        self,
        source: SourceDefinition,
        lease_key: LeaseKey,
        lease: LeaseRevision,
        expected_revision: int,
        request_digest: str,
        idempotency_key: str,
        correlation_id: str,
        endpoint_digest: str,
        domain_digest: str,
        build: BatchBuild,
    ) -> StagedBatch:
        key = (source.organization_id, source.source_id)

        def operation(state: StoreState) -> StagedBatch:
            replay = self._idempotent(state, source.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay  # type: ignore[return-value]
            current = state.source_revisions[key][-1]
            if current.revision != expected_revision:
                raise IngestionFailure("STALE_REVISION")
            if current.state not in {SourceState.VALID, SourceState.SAMPLED}:
                raise IngestionFailure("TRANSITION_FORBIDDEN")
            current_lease = state.lease_revisions.get(lease_key, [None])[-1]
            try:
                assert_current(current_lease, lease, organization_id=source.organization_id, source_id=source.source_id, source_version_digest=source.resource_digest, now=self.now())
            except LeaseFailure as exc:
                raise IngestionFailure(exc.reason_code) from exc
            batch_key = (source.organization_id, build.batch.batch_id)
            if batch_key in state.batches or any(item.batch_digest == build.batch.batch_digest for item in state.batches.values()):
                raise IngestionFailure("DUPLICATE_STAGED_BATCH")
            sampling = SourceRevision(source.organization_id, source.source_id, source.resource_digest, expected_revision + 1, SourceState.SAMPLING, "SOURCE_SAMPLING_STARTED", self.now(), correlation_id)
            sampled = SourceRevision(source.organization_id, source.source_id, source.resource_digest, expected_revision + 2, SourceState.SAMPLED, "SOURCE_SAMPLE_STAGED", self.now(), correlation_id)
            state.source_revisions[key].extend((sampling, sampled))
            state.batches[batch_key] = build.batch
            state.batch_records[batch_key] = build.records
            state.checkpoint_candidates[batch_key] = build.checkpoint
            self._evidence_event(state, source=source, revision=sampled, reason_code=sampled.reason_code, correlation_id=correlation_id, batch_digest=build.batch.batch_digest, endpoint_grant_digest=endpoint_digest, domain_observation_digest=domain_digest)
            state.idempotency[(source.organization_id, idempotency_key)] = (request_digest, build.batch)
            return build.batch

        return self.store.transact(operation)

    def get_staged_batch(self, identity: TenantIdentity, permit: AccessPermit, batch_id: str) -> StagedBatch:
        self._authorize(
            identity,
            permit,
            "knowledge.ingestion.staged-batch.read",
            batch_scope_digest(identity.organization_id, batch_id),
        )
        batch = self.store.read(lambda state: state.batches.get((identity.organization_id, batch_id)))
        if batch is None:
            raise IngestionFailure("STAGED_BATCH_NOT_FOUND")
        return batch

    def disable_source(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        source_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
        correlation_id: str,
    ) -> SourceRevision:
        self._command_fields(idempotency_key, correlation_id)
        self._authorize(
            identity,
            permit,
            "knowledge.ingestion.source.disable",
            source_scope_digest(identity.organization_id, source_id),
        )
        key = (identity.organization_id, source_id)
        source = self.store.read(lambda state: state.sources.get(key))
        if source is None:
            raise IngestionFailure("SOURCE_NOT_FOUND")
        request_digest = canonical_digest({"sourceVersionDigest": source.resource_digest, "expectedRevision": expected_revision, "state": SourceState.DISABLED.value})

        def operation(state: StoreState) -> SourceRevision:
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay  # type: ignore[return-value]
            current = state.source_revisions[key][-1]
            if current.revision != expected_revision:
                raise IngestionFailure("STALE_REVISION")
            if current.state not in {SourceState.VALID, SourceState.SAMPLED}:
                raise IngestionFailure("TRANSITION_FORBIDDEN")
            disabled = SourceRevision(source.organization_id, source.source_id, source.resource_digest, expected_revision + 1, SourceState.DISABLED, "SOURCE_DISABLED", self.now(), correlation_id)
            state.source_revisions[key].append(disabled)
            self._evidence_event(state, source=source, revision=disabled, reason_code=disabled.reason_code, correlation_id=correlation_id)
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, disabled)
            return disabled

        return self.store.transact(operation)


def _graph_id(label: str, *values: str) -> str:
    value = canonical_digest({"label": label, "values": list(values)})
    return f"provenance.{value.removeprefix('sha256:')[:24]}"


def _assessment_graph(
    *,
    batch: StagedBatch,
    policy: ReadinessPolicyObservation,
    observation: MeasurementObservation,
    findings: tuple[ReadinessFinding, ...],
    assessment: DataReadinessAssessment,
    created_at: str,
) -> ProvenanceGraph:
    lease_binding_digest = canonical_digest(
        {
            "organizationId": batch.organization_id,
            "sourceId": batch.source_id,
            "partition": batch.partition,
            "fencingToken": batch.fencing_token,
        }
    )
    nodes = [
        ProvenanceNode("assessment.result", "readiness.assessment", assessment.assessment_digest),
        ProvenanceNode("batch.staged", "data.staged-batch", batch.batch_digest),
        ProvenanceNode("checkpoint.candidate", "data.checkpoint-candidate", batch.checkpoint_candidate_digest),
        ProvenanceNode("domain.version", "domain.version", batch.active_domain_version_digest),
        ProvenanceNode("lease.binding", "data.lease-binding", lease_binding_digest),
        ProvenanceNode("material.object", "data.material", batch.material_digest),
        ProvenanceNode("measurement.observation", "readiness.measurement", observation.observation_digest),
        ProvenanceNode("policy.readiness", "readiness.policy", policy.policy_digest),
        ProvenanceNode("records.set", "data.record-set", batch.record_set_digest),
        ProvenanceNode("semantic.mapping", "domain.semantic-mapping", batch.semantic_mapping_digest),
        ProvenanceNode("source.version", "data.source-version", batch.source_version_digest),
    ]
    for finding in findings:
        nodes.append(ProvenanceNode(finding.finding_id, "readiness.finding", finding.finding_digest))
    edges = [
        ProvenanceEdge("source.version", "batch.staged", "source.produces"),
        ProvenanceEdge("material.object", "batch.staged", "material.binds"),
        ProvenanceEdge("records.set", "batch.staged", "records.bind"),
        ProvenanceEdge("checkpoint.candidate", "batch.staged", "checkpoint.binds"),
        ProvenanceEdge("lease.binding", "batch.staged", "lease.fences"),
        ProvenanceEdge("domain.version", "batch.staged", "domain.binds"),
        ProvenanceEdge("semantic.mapping", "batch.staged", "mapping.binds"),
        ProvenanceEdge("batch.staged", "measurement.observation", "batch.measured-by"),
        ProvenanceEdge("policy.readiness", "assessment.result", "policy.governs"),
        ProvenanceEdge("measurement.observation", "assessment.result", "measurement.supports"),
    ]
    for finding in findings:
        edges.append(ProvenanceEdge("measurement.observation", finding.finding_id, "measurement.yields"))
        edges.append(ProvenanceEdge(finding.finding_id, "assessment.result", "finding.supports"))
    graph_id = _graph_id(
        "assessment", assessment.assessment_digest, policy.policy_digest, observation.observation_digest
    )
    return build_graph(
        organization_id=batch.organization_id,
        graph_id=graph_id,
        purpose="ASSESSMENT",
        nodes=tuple(nodes),
        edges=tuple(edges),
        created_at=created_at,
    )


class ReadinessService:
    """Tenant-isolated readiness, retry, evidence, and activation service."""

    def __init__(
        self,
        *,
        store: InMemoryIngestionStore,
        now: Callable[[], str],
        new_id: Callable[[], str] = lambda: str(uuid4()),
    ) -> None:
        self.store = store
        self.now = now
        self.new_id = new_id

    @staticmethod
    def _command_fields(idempotency_key: str, correlation_id: str) -> None:
        IngestionService._command_fields(idempotency_key, correlation_id)

    @staticmethod
    def _idempotent(state: StoreState, organization_id: str, key: str, request_digest: str) -> object | None:
        return IngestionService._idempotent(state, organization_id, key, request_digest)

    def _authorize(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        action: str,
        resource_digest: str,
    ) -> None:
        if (
            not permit.allowed
            or permit.organization_id != identity.organization_id
            or permit.subject_id != identity.subject_id
            or permit.action != action
            or permit.resource_digest != resource_digest
            or _parse_time(permit.expires_at) <= _parse_time(self.now())
        ):
            raise IngestionFailure("POLICY_DENIED")

    def authorize_scope(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        action: str,
        resource_digest: str,
    ) -> None:
        self._authorize(identity, permit, action, resource_digest)

    @staticmethod
    def _batch_dependencies(
        batch: StagedBatch,
        policy: ReadinessPolicyObservation,
        observation: MeasurementObservation,
        *,
        operational: bool,
        now: str,
    ) -> None:
        if not batch.partition:
            raise IngestionFailure("BATCH_PARTITION_UNBOUND")
        if policy.organization_id != batch.organization_id or observation.organization_id != batch.organization_id:
            raise IngestionFailure("TENANT_MISMATCH")
        if operational and (policy.illustrative or policy.tenant_approval_digest is None):
            raise IngestionFailure("POLICY_NOT_TENANT_APPROVED")
        timestamp = _parse_time(now)
        if not (_parse_time(policy.effective_at) <= timestamp < _parse_time(policy.expires_at)):
            raise IngestionFailure("POLICY_STALE")
        if not (_parse_time(observation.collected_at) <= timestamp < _parse_time(observation.valid_until)):
            raise IngestionFailure("MEASUREMENT_STALE")
        if (
            observation.source_id,
            observation.source_version_digest,
            observation.batch_id,
            observation.batch_digest,
            observation.material_digest,
            observation.record_set_digest,
            observation.checkpoint_candidate_digest,
            observation.partition,
            observation.observed_record_count,
        ) != (
            batch.source_id,
            batch.source_version_digest,
            batch.batch_id,
            batch.batch_digest,
            batch.material_digest,
            batch.record_set_digest,
            batch.checkpoint_candidate_digest,
            batch.partition,
            batch.record_count,
        ):
            raise IngestionFailure("MEASUREMENT_SCOPE_MISMATCH")

    def request_assessment(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        batch_id: str,
        *,
        policy: ReadinessPolicyObservation,
        observation: MeasurementObservation,
        idempotency_key: str,
        correlation_id: str,
    ) -> ReadinessWorkRevision:
        self._command_fields(idempotency_key, correlation_id)
        scope = batch_scope_digest(identity.organization_id, batch_id)
        self._authorize(identity, permit, "knowledge.ingestion.staged-batch.assess", scope)
        batch_key = (identity.organization_id, batch_id)
        snapshot = self.store.snapshot()
        batch = snapshot.batches.get(batch_key)
        if batch is None:
            raise IngestionFailure("STAGED_BATCH_NOT_FOUND")
        if batch_key in snapshot.batch_commits:
            raise IngestionFailure("BATCH_ALREADY_COMMITTED")
        readiness_history = snapshot.source_readiness_revisions.get(
            (identity.organization_id, batch.source_id), []
        )
        if readiness_history and readiness_history[-1].state is SourceReadinessState.REVOKED:
            raise IngestionFailure("SOURCE_REVOKED")
        self._batch_dependencies(batch, policy, observation, operational=True, now=self.now())
        request_digest = canonical_digest(
            {
                "batchDigest": batch.batch_digest,
                "policyDigest": policy.policy_digest,
                "observationDigest": observation.observation_digest,
            }
        )

        def operation(state: StoreState) -> ReadinessWorkRevision:
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay  # type: ignore[return-value]
            current_batch = state.batches.get(batch_key)
            if current_batch != batch or batch_key in state.batch_commits:
                raise IngestionFailure("BATCH_STATE_CHANGED")
            current_readiness = state.source_readiness_revisions.get(
                (identity.organization_id, batch.source_id), []
            )
            if current_readiness and current_readiness[-1].state is SourceReadinessState.REVOKED:
                raise IngestionFailure("SOURCE_REVOKED")
            policy_key = (identity.organization_id, policy.policy_id, policy.version)
            existing_policy = state.readiness_policies.get(policy_key)
            if existing_policy is not None and existing_policy != policy:
                raise IngestionFailure("POLICY_VERSION_CONFLICT")
            observation_key = (identity.organization_id, batch_id, observation.observation_digest)
            existing_observation = state.measurement_observations.get(observation_key)
            if existing_observation is not None and existing_observation != observation:
                raise IngestionFailure("MEASUREMENT_DIGEST_CONFLICT")
            work = new_work(
                organization_id=identity.organization_id,
                work_id=self.new_id(),
                source_id=batch.source_id,
                batch_id=batch.batch_id,
                batch_digest=batch.batch_digest,
                policy_digest=policy.policy_digest,
                observation_digest=observation.observation_digest,
                now=self.now(),
                correlation_id=correlation_id,
            )
            state.readiness_policies[policy_key] = policy
            state.measurement_observations[observation_key] = observation
            state.readiness_work_revisions[(identity.organization_id, work.work_id)] = [work]
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, work)
            return work

        return self.store.transact(operation)

    def claim_assessment_work(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        work_id: str,
        *,
        expected_revision: int,
        ttl_seconds: int,
        correlation_id: str,
    ) -> ReadinessWorkRevision:
        self._authorize(
            identity,
            permit,
            "knowledge.ingestion.readiness.process",
            work_scope_digest(identity.organization_id, work_id),
        )
        key = (identity.organization_id, work_id)

        def operation(state: StoreState) -> ReadinessWorkRevision:
            history = state.readiness_work_revisions.get(key)
            if not history:
                raise IngestionFailure("WORK_NOT_FOUND")
            current = history[-1]
            if current.revision != expected_revision:
                raise IngestionFailure("WORK_STALE_REVISION")
            try:
                claimed = claim_work(
                    current,
                    worker_id=identity.subject_id,
                    ttl_seconds=ttl_seconds,
                    now=self.now(),
                    correlation_id=correlation_id,
                )
            except RetryFailure as exc:
                raise IngestionFailure(exc.reason_code) from exc
            history.append(claimed)
            return claimed

        return self.store.transact(operation)

    @staticmethod
    def _find_policy(state: StoreState, organization_id: str, policy_digest: str) -> ReadinessPolicyObservation:
        matches = [
            item
            for (tenant, _, _), item in state.readiness_policies.items()
            if tenant == organization_id and item.policy_digest == policy_digest
        ]
        if len(matches) != 1:
            raise IngestionFailure("POLICY_DEPENDENCY_UNAVAILABLE")
        return matches[0]

    @staticmethod
    def _find_observation(
        state: StoreState,
        organization_id: str,
        batch_id: str,
        observation_digest: str,
    ) -> MeasurementObservation:
        item = state.measurement_observations.get((organization_id, batch_id, observation_digest))
        if item is None:
            raise IngestionFailure("MEASUREMENT_DEPENDENCY_UNAVAILABLE")
        return item

    def complete_assessment_work(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        supplied_claim: ReadinessWorkRevision,
        *,
        correlation_id: str,
    ) -> DataReadinessAssessment:
        self._authorize(
            identity,
            permit,
            "knowledge.ingestion.readiness.process",
            work_scope_digest(identity.organization_id, supplied_claim.work_id),
        )
        snapshot = self.store.snapshot()
        work_key = (identity.organization_id, supplied_claim.work_id)
        history = snapshot.readiness_work_revisions.get(work_key)
        if not history or history[-1] != supplied_claim:
            raise IngestionFailure("WORK_FENCE_MISMATCH")
        batch = snapshot.batches.get((identity.organization_id, supplied_claim.batch_id))
        if batch is None:
            raise IngestionFailure("STAGED_BATCH_NOT_FOUND")
        readiness_history = snapshot.source_readiness_revisions.get(
            (identity.organization_id, batch.source_id), []
        )
        if readiness_history and readiness_history[-1].state is SourceReadinessState.REVOKED:
            raise IngestionFailure("SOURCE_REVOKED")
        policy = self._find_policy(snapshot, identity.organization_id, supplied_claim.policy_digest)
        observation = self._find_observation(
            snapshot,
            identity.organization_id,
            supplied_claim.batch_id,
            supplied_claim.observation_digest,
        )
        evaluated_at = self.now()
        self._batch_dependencies(batch, policy, observation, operational=True, now=evaluated_at)
        try:
            findings, assessment = evaluate_readiness(
                policy=policy,
                observation=observation,
                batch=batch,
                evaluated_at=evaluated_at,
            )
        except ReadinessFailure as exc:
            raise IngestionFailure(exc.reason_code) from exc
        graph = _assessment_graph(
            batch=batch,
            policy=policy,
            observation=observation,
            findings=findings,
            assessment=assessment,
            created_at=evaluated_at,
        )
        evidence = build_evidence(assessment, graph, batch)

        def operation(state: StoreState) -> DataReadinessAssessment:
            current_history = state.readiness_work_revisions.get(work_key)
            if not current_history or current_history[-1] != supplied_claim:
                raise IngestionFailure("WORK_FENCE_MISMATCH")
            if state.batches.get((identity.organization_id, batch.batch_id)) != batch:
                raise IngestionFailure("BATCH_STATE_CHANGED")
            current_readiness = state.source_readiness_revisions.get(
                (identity.organization_id, batch.source_id), []
            )
            if current_readiness and current_readiness[-1].state is SourceReadinessState.REVOKED:
                raise IngestionFailure("SOURCE_REVOKED")
            try:
                finished = finish_work(
                    supplied_claim,
                    worker_id=identity.subject_id,
                    now=evaluated_at,
                    correlation_id=correlation_id,
                )
            except RetryFailure as exc:
                raise IngestionFailure(exc.reason_code) from exc
            assessment_key = (identity.organization_id, assessment.assessment_id)
            if assessment_key in state.readiness_assessments:
                raise IngestionFailure("ASSESSMENT_DUPLICATE")
            graph_key = (identity.organization_id, graph.graph_id)
            evidence_key = (identity.organization_id, evidence.evidence_id)
            if graph_key in state.provenance_graphs or evidence_key in state.readiness_evidence:
                raise IngestionFailure("READINESS_EVIDENCE_DUPLICATE")
            source_key = (identity.organization_id, batch.source_id)
            readiness_history = state.source_readiness_revisions.setdefault(source_key, [])
            source_state = (
                SourceReadinessState.READY_FOR_APPROVAL
                if assessment.decision is ReadinessDecision.PASS
                else SourceReadinessState.DEGRADED
            )
            reason_code = f"READINESS_{assessment.decision.value}"
            revision = SourceReadinessRevision(
                identity.organization_id,
                batch.source_id,
                len(readiness_history) + 1,
                source_state,
                batch.batch_id,
                assessment.assessment_id,
                assessment.assessment_digest,
                evidence.evidence_id,
                evidence.record_digest,
                policy.policy_digest,
                reason_code,
                evaluated_at,
                assessment.valid_until,
                correlation_id,
            )
            event_type = f"data.readiness.{assessment.decision.value.lower()}.v1"
            event = build_event(
                event_id=self.new_id(),
                organization_id=identity.organization_id,
                source_id=batch.source_id,
                aggregate_version=revision.revision,
                event_type=event_type,
                batch_digest=batch.batch_digest,
                assessment_digest=assessment.assessment_digest,
                evidence_record_digest=evidence.record_digest,
                reason_code=reason_code,
                correlation_id=correlation_id,
                occurred_at=evaluated_at,
            )
            state.readiness_findings[assessment_key] = findings
            state.readiness_assessments[assessment_key] = assessment
            state.assessment_graph_ids[assessment_key] = graph.graph_id
            state.provenance_graphs[graph_key] = graph
            state.readiness_evidence[evidence_key] = evidence
            readiness_history.append(revision)
            state.readiness_events.append(event)
            current_history.append(finished)
            return assessment

        return self.store.transact(operation)

    def record_assessment_failure(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        supplied_claim: ReadinessWorkRevision,
        *,
        reason_code: str,
        correlation_id: str,
        recover_expired: bool = False,
    ) -> tuple[ReadinessWorkRevision, DeadLetterRecord | None]:
        self._authorize(
            identity,
            permit,
            "knowledge.ingestion.readiness.process",
            work_scope_digest(identity.organization_id, supplied_claim.work_id),
        )
        key = (identity.organization_id, supplied_claim.work_id)

        def operation(state: StoreState) -> tuple[ReadinessWorkRevision, DeadLetterRecord | None]:
            history = state.readiness_work_revisions.get(key)
            if not history or history[-1] != supplied_claim:
                raise IngestionFailure("WORK_FENCE_MISMATCH")
            try:
                failed = fail_work(
                    supplied_claim,
                    worker_id=identity.subject_id,
                    reason_code=reason_code,
                    now=self.now(),
                    correlation_id=correlation_id,
                    allow_expired_claim=recover_expired,
                )
            except RetryFailure as exc:
                raise IngestionFailure(exc.reason_code) from exc
            history.append(failed)
            dead_letter = None
            if failed.state is WorkState.DEAD_LETTERED:
                dead_letter = build_dead_letter(dead_letter_id=self.new_id(), work=failed)
                state.dead_letters[(identity.organization_id, dead_letter.dead_letter_id)] = dead_letter
                readiness_history = state.source_readiness_revisions.setdefault(
                    (identity.organization_id, failed.source_id), []
                )
                revision = SourceReadinessRevision(
                    identity.organization_id,
                    failed.source_id,
                    len(readiness_history) + 1,
                    SourceReadinessState.DEGRADED,
                    failed.batch_id,
                    None,
                    None,
                    None,
                    None,
                    failed.policy_digest,
                    "READINESS_DEAD_LETTERED",
                    failed.occurred_at,
                    None,
                    correlation_id,
                )
                readiness_history.append(revision)
                state.readiness_events.append(
                    build_event(
                        event_id=self.new_id(),
                        organization_id=identity.organization_id,
                        source_id=failed.source_id,
                        aggregate_version=revision.revision,
                        event_type="data.readiness.dead-lettered.v1",
                        batch_digest=failed.batch_digest,
                        assessment_digest=None,
                        evidence_record_digest=None,
                        reason_code=failed.reason_code,
                        correlation_id=correlation_id,
                        occurred_at=failed.occurred_at,
                    )
                )
            return failed, dead_letter

        return self.store.transact(operation)

    def get_assessment(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        assessment_id: str,
    ) -> DataReadinessAssessment:
        self._authorize(
            identity,
            permit,
            "knowledge.ingestion.readiness.read",
            assessment_scope_digest(identity.organization_id, assessment_id),
        )
        assessment = self.store.read(
            lambda state: state.readiness_assessments.get((identity.organization_id, assessment_id))
        )
        if assessment is None:
            raise IngestionFailure("ASSESSMENT_NOT_FOUND")
        return assessment

    def get_source_readiness(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        source_id: str,
    ) -> tuple[str, SourceReadinessRevision | None]:
        self._authorize(
            identity,
            permit,
            "knowledge.ingestion.readiness.read",
            readiness_scope_digest(identity.organization_id, source_id),
        )
        current = self.store.read(
            lambda state: state.source_readiness_revisions.get((identity.organization_id, source_id), [None])[-1]
        )
        if current is None:
            source = self.store.read(lambda state: state.sources.get((identity.organization_id, source_id)))
            if source is None:
                raise IngestionFailure("SOURCE_NOT_FOUND")
            return "UNASSESSED", None
        if current.state is SourceReadinessState.REVOKED:
            return current.state.value, current
        if current.valid_until is None or _parse_time(current.valid_until) <= _parse_time(self.now()):
            return SourceReadinessState.DEGRADED.value, current
        return current.state.value, current

    def commit_batch(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        batch_id: str,
        *,
        expected_readiness_revision: int,
        approval: OwnerApprovalAttestation,
        idempotency_key: str,
        correlation_id: str,
    ) -> BatchCommit:
        self._command_fields(idempotency_key, correlation_id)
        self._authorize(
            identity,
            permit,
            "knowledge.ingestion.batch.commit",
            batch_scope_digest(identity.organization_id, batch_id),
        )
        request_digest = canonical_digest(
            {
                "batchId": batch_id,
                "expectedReadinessRevision": expected_readiness_revision,
                "approvalDigest": approval.approval_digest,
            }
        )

        def operation(state: StoreState) -> BatchCommit:
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay  # type: ignore[return-value]
            batch_key = (identity.organization_id, batch_id)
            batch = state.batches.get(batch_key)
            if batch is None:
                raise IngestionFailure("STAGED_BATCH_NOT_FOUND")
            if not batch.partition:
                raise IngestionFailure("BATCH_PARTITION_UNBOUND")
            if batch_key in state.batch_commits:
                raise IngestionFailure("BATCH_ALREADY_COMMITTED")
            source = state.sources.get((identity.organization_id, batch.source_id))
            if source is None:
                raise IngestionFailure("SOURCE_NOT_FOUND")
            readiness_history = state.source_readiness_revisions.get(
                (identity.organization_id, batch.source_id)
            )
            if not readiness_history:
                raise IngestionFailure("READINESS_NOT_FOUND")
            current = readiness_history[-1]
            if current.revision != expected_readiness_revision:
                raise IngestionFailure("STALE_REVISION")
            if current.state is not SourceReadinessState.READY_FOR_APPROVAL:
                raise IngestionFailure("SOURCE_NOT_READY_FOR_APPROVAL")
            if current.batch_id != batch_id or current.assessment_id is None or current.evidence_id is None:
                raise IngestionFailure("READINESS_SCOPE_MISMATCH")
            assessment = state.readiness_assessments.get(
                (identity.organization_id, current.assessment_id)
            )
            evidence = state.readiness_evidence.get((identity.organization_id, current.evidence_id))
            graph_id = state.assessment_graph_ids.get((identity.organization_id, current.assessment_id))
            graph = state.provenance_graphs.get((identity.organization_id, graph_id or ""))
            if assessment is None or evidence is None or graph is None:
                raise IngestionFailure("READINESS_EVIDENCE_MISSING")
            now = self.now()
            if (
                assessment.decision is not ReadinessDecision.PASS
                or assessment.overall_status != "READY"
                or current.assessment_digest != assessment.assessment_digest
                or current.evidence_record_digest != evidence.record_digest
                or current.policy_digest != assessment.policy_digest
                or current.valid_until is None
                or _parse_time(current.valid_until) <= _parse_time(now)
                or _parse_time(assessment.valid_until) <= _parse_time(now)
                or evidence.result is not ReadinessDecision.PASS
                or _parse_time(evidence.valid_until) <= _parse_time(now)
                or evidence.subject_digest != batch.batch_digest
                or evidence.evidence_digest != assessment.assessment_digest
                or evidence.provenance_digest != graph.graph_digest
                or graph.organization_id != identity.organization_id
                or graph.purpose != "ASSESSMENT"
            ):
                raise IngestionFailure("READINESS_STALE")
            if (
                approval.organization_id,
                approval.owner_digest,
                approval.source_id,
                approval.source_version_digest,
                approval.batch_id,
                approval.batch_digest,
                approval.assessment_digest,
                approval.evidence_record_digest,
                approval.policy_digest,
                approval.provenance_digest,
            ) != (
                identity.organization_id,
                source.owner_digest,
                batch.source_id,
                batch.source_version_digest,
                batch.batch_id,
                batch.batch_digest,
                assessment.assessment_digest,
                evidence.record_digest,
                assessment.policy_digest,
                graph.graph_digest,
            ):
                raise IngestionFailure("OWNER_APPROVAL_MISMATCH")
            if not (_parse_time(approval.issued_at) <= _parse_time(now) < _parse_time(approval.expires_at)):
                raise IngestionFailure("OWNER_APPROVAL_STALE")
            checkpoint = state.checkpoint_candidates.get(batch_key)
            if checkpoint is None or (
                checkpoint.organization_id,
                checkpoint.source_id,
                checkpoint.source_version_digest,
                checkpoint.partition,
                checkpoint.checkpoint_digest,
            ) != (
                batch.organization_id,
                batch.source_id,
                batch.source_version_digest,
                batch.partition,
                batch.checkpoint_candidate_digest,
            ):
                raise IngestionFailure("CHECKPOINT_CANDIDATE_MISMATCH")
            checkpoint_key = (identity.organization_id, batch.source_id, batch.partition)
            checkpoint_history = state.checkpoint_revisions.setdefault(checkpoint_key, [])
            if checkpoint_history:
                prior = checkpoint_history[-1]
                if batch.fencing_token <= prior.fencing_token or _parse_time(batch.staged_at) <= _parse_time(prior.batch_staged_at):
                    raise IngestionFailure("CHECKPOINT_ORDER_INVALID")
            checkpoint_revision = CheckpointRevision(
                identity.organization_id,
                batch.source_id,
                batch.source_version_digest,
                batch.partition,
                len(checkpoint_history) + 1,
                batch.batch_id,
                batch.batch_digest,
                checkpoint.checkpoint_digest,
                batch.fencing_token,
                batch.staged_at,
                now,
            )
            checkpoint_revision_digest = canonical_digest(
                {
                    "organizationId": checkpoint_revision.organization_id,
                    "sourceId": checkpoint_revision.source_id,
                    "sourceVersionDigest": checkpoint_revision.source_version_digest,
                    "partition": checkpoint_revision.partition,
                    "revision": checkpoint_revision.revision,
                    "batchId": checkpoint_revision.batch_id,
                    "batchDigest": checkpoint_revision.batch_digest,
                    "checkpointDigest": checkpoint_revision.checkpoint_digest,
                    "fencingToken": checkpoint_revision.fencing_token,
                    "batchStagedAt": checkpoint_revision.batch_staged_at,
                    "activatedAt": checkpoint_revision.activated_at,
                }
            )
            commit_core_digest = canonical_digest(
                {
                    "organizationId": identity.organization_id,
                    "sourceId": batch.source_id,
                    "batchDigest": batch.batch_digest,
                    "assessmentDigest": assessment.assessment_digest,
                    "evidenceRecordDigest": evidence.record_digest,
                    "approvalDigest": approval.approval_digest,
                    "checkpointDigest": checkpoint.checkpoint_digest,
                    "checkpointRevision": checkpoint_revision.revision,
                    "committedAt": now,
                }
            )
            commit_graph = build_graph(
                organization_id=identity.organization_id,
                graph_id=_graph_id("commit", commit_core_digest, graph.graph_digest),
                purpose="COMMIT",
                nodes=(
                    ProvenanceNode("approval.owner", "readiness.owner-approval", approval.approval_digest),
                    ProvenanceNode("assessment.graph", "readiness.provenance", graph.graph_digest),
                    ProvenanceNode("batch.committed", "data.committed-batch", commit_core_digest),
                    ProvenanceNode("batch.staged", "data.staged-batch", batch.batch_digest),
                    ProvenanceNode(
                        "checkpoint.activated",
                        "data.checkpoint-revision",
                        checkpoint_revision_digest,
                    ),
                ),
                edges=(
                    ProvenanceEdge("approval.owner", "batch.committed", "approval.authorizes"),
                    ProvenanceEdge("assessment.graph", "batch.committed", "assessment.authorizes"),
                    ProvenanceEdge("batch.staged", "batch.committed", "batch.promotes"),
                    ProvenanceEdge("batch.committed", "checkpoint.activated", "commit.advances"),
                ),
                created_at=now,
            )
            commit_evidence = build_evidence(assessment, commit_graph, batch)
            commit_body = {
                "organizationId": identity.organization_id,
                "sourceId": batch.source_id,
                "sourceVersionDigest": batch.source_version_digest,
                "batchId": batch.batch_id,
                "batchDigest": batch.batch_digest,
                "partition": batch.partition,
                "assessmentDigest": assessment.assessment_digest,
                "evidenceRecordDigest": commit_evidence.record_digest,
                "policyDigest": assessment.policy_digest,
                "provenanceDigest": commit_graph.graph_digest,
                "approvalDigest": approval.approval_digest,
                "checkpointDigest": checkpoint.checkpoint_digest,
                "fencingToken": batch.fencing_token,
                "committedAt": now,
            }
            commit = BatchCommit(
                identity.organization_id,
                batch.source_id,
                batch.source_version_digest,
                batch.batch_id,
                batch.batch_digest,
                batch.partition,
                assessment.assessment_digest,
                commit_evidence.record_digest,
                assessment.policy_digest,
                commit_graph.graph_digest,
                approval.approval_digest,
                checkpoint.checkpoint_digest,
                batch.fencing_token,
                now,
                canonical_digest(commit_body),
            )
            active = SourceReadinessRevision(
                identity.organization_id,
                batch.source_id,
                current.revision + 1,
                SourceReadinessState.ACTIVE,
                batch.batch_id,
                assessment.assessment_id,
                assessment.assessment_digest,
                commit_evidence.evidence_id,
                commit_evidence.record_digest,
                assessment.policy_digest,
                "SOURCE_ACTIVATED",
                now,
                min(assessment.valid_until, approval.expires_at),
                correlation_id,
            )
            graph_key = (identity.organization_id, commit_graph.graph_id)
            evidence_key = (identity.organization_id, commit_evidence.evidence_id)
            if graph_key in state.provenance_graphs or evidence_key in state.readiness_evidence:
                raise IngestionFailure("COMMIT_EVIDENCE_DUPLICATE")
            state.provenance_graphs[graph_key] = commit_graph
            state.readiness_evidence[evidence_key] = commit_evidence
            state.batch_commits[batch_key] = commit
            checkpoint_history.append(checkpoint_revision)
            readiness_history.append(active)
            for event_type in ("data.batch.committed.v1", "data.source.activated.v1"):
                state.readiness_events.append(
                    build_event(
                        event_id=self.new_id(),
                        organization_id=identity.organization_id,
                        source_id=batch.source_id,
                        aggregate_version=active.revision,
                        event_type=event_type,
                        batch_digest=batch.batch_digest,
                        assessment_digest=assessment.assessment_digest,
                        evidence_record_digest=commit_evidence.record_digest,
                        reason_code="SOURCE_ACTIVATED",
                        correlation_id=correlation_id,
                        occurred_at=now,
                    )
                )
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, commit)
            return commit

        return self.store.transact(operation)

    def revoke_source(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        source_id: str,
        *,
        expected_readiness_revision: int,
        idempotency_key: str,
        correlation_id: str,
    ) -> SourceReadinessRevision:
        self._command_fields(idempotency_key, correlation_id)
        self._authorize(
            identity,
            permit,
            "knowledge.ingestion.source.revoke",
            readiness_scope_digest(identity.organization_id, source_id),
        )
        request_digest = canonical_digest(
            {"sourceId": source_id, "expectedReadinessRevision": expected_readiness_revision, "state": "REVOKED"}
        )

        def operation(state: StoreState) -> SourceReadinessRevision:
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay  # type: ignore[return-value]
            if (identity.organization_id, source_id) not in state.sources:
                raise IngestionFailure("SOURCE_NOT_FOUND")
            history = state.source_readiness_revisions.get((identity.organization_id, source_id))
            if not history or history[-1].revision != expected_readiness_revision:
                raise IngestionFailure("STALE_REVISION")
            if history[-1].state is SourceReadinessState.REVOKED:
                raise IngestionFailure("SOURCE_REVOKED")
            now = self.now()
            revoked = SourceReadinessRevision(
                identity.organization_id,
                source_id,
                expected_readiness_revision + 1,
                SourceReadinessState.REVOKED,
                None,
                None,
                None,
                None,
                None,
                None,
                "SOURCE_REVOKED",
                now,
                None,
                correlation_id,
            )
            history.append(revoked)
            state.readiness_events.append(
                build_event(
                    event_id=self.new_id(),
                    organization_id=identity.organization_id,
                    source_id=source_id,
                    aggregate_version=revoked.revision,
                    event_type="data.source.revoked.v1",
                    batch_digest=None,
                    assessment_digest=None,
                    evidence_record_digest=None,
                    reason_code="SOURCE_REVOKED",
                    correlation_id=correlation_id,
                    occurred_at=now,
                )
            )
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, revoked)
            return revoked

        return self.store.transact(operation)

    def get_dead_letter(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        dead_letter_id: str,
    ) -> DeadLetterRecord:
        self._authorize(
            identity,
            permit,
            "knowledge.ingestion.dead-letter.read",
            dead_letter_scope_digest(identity.organization_id, dead_letter_id),
        )
        record = self.store.read(
            lambda state: state.dead_letters.get((identity.organization_id, dead_letter_id))
        )
        if record is None:
            raise IngestionFailure("DEAD_LETTER_NOT_FOUND")
        return record

    def review_dead_letter(
        self,
        identity: TenantIdentity,
        permit: AccessPermit,
        dead_letter_id: str,
        *,
        decision: str,
        reason_code: str,
        idempotency_key: str,
        correlation_id: str,
    ) -> DeadLetterReview:
        self._command_fields(idempotency_key, correlation_id)
        if decision != "ACKNOWLEDGED":
            raise IngestionFailure("REVIEW_DECISION_INVALID")
        self._authorize(
            identity,
            permit,
            "knowledge.ingestion.dead-letter.review",
            dead_letter_scope_digest(identity.organization_id, dead_letter_id),
        )
        request_digest = canonical_digest(
            {"deadLetterId": dead_letter_id, "decision": decision, "reasonCode": reason_code}
        )

        def operation(state: StoreState) -> DeadLetterReview:
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay  # type: ignore[return-value]
            if (identity.organization_id, dead_letter_id) not in state.dead_letters:
                raise IngestionFailure("DEAD_LETTER_NOT_FOUND")
            review = build_review(
                organization_id=identity.organization_id,
                review_id=self.new_id(),
                dead_letter_id=dead_letter_id,
                reason_code=reason_code,
                reviewer_subject_id=identity.subject_id,
                reviewed_at=self.now(),
                correlation_id=correlation_id,
            )
            state.dead_letter_reviews.setdefault((identity.organization_id, dead_letter_id), []).append(review)
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, review)
            return review

        return self.store.transact(operation)
