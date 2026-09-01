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
from .store import InMemoryIngestionStore, LeaseKey, SourceKey, StoreFailure, StoreState


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
        if current_source_revision.state is not SourceState.VALID:
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
            if current.revision != expected_revision or current.state is not SourceState.VALID:
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
            if current.state is not SourceState.VALID:
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
