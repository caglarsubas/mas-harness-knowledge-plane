"""Fail-closed domain and semantic-mapping lifecycle service."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Callable
from uuid import uuid4

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.common.models import TenantIdentity
from planeon_knowledge.common.validation import token, uuid_text

from .contracts import (
    ApprovalAttestation,
    CompatibilityMode,
    CompatibilityReport,
    CompatibilityState,
    Decision,
    DomainDefinition,
    DomainEvidence,
    DomainEvent,
    DomainVersion,
    Finding,
    MappingApprovalAttestation,
    MappingRevision,
    MappingState,
    PolicyPermit,
    SemanticMapping,
    ValidationReport,
    VersionRevision,
    VersionState,
    public_dict,
)
from .semantic import SemanticFailure, SemanticMaterial, SemanticSnapshot, SemanticValidator, classify_compatibility
from .store import InMemoryDomainStore, MappingKey, StoreState, VersionKey


class DomainFailure(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _parse_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _failure_digest(reason_code: str) -> str:
    return canonical_digest({"reasonCode": reason_code})


def _event_type(lifecycle_state: str, reason_code: str) -> str:
    mapping_event = reason_code.startswith("MAPPING_") or reason_code == "DOMAIN_VERSION_SUPERSEDED"
    prefix = "domain.mapping" if mapping_event else "domain.version"
    suffixes = {
        "DRAFT": "created",
        "VALIDATING": "validation-started",
        "VALID": "validated",
        "INVALID": "validated",
        "AWAITING_APPROVAL": "approval-requested",
        "ACTIVE": "activated" if mapping_event else "published",
        "REJECTED": "rejected",
        "SUPERSEDED": "superseded",
        "RETIRED": "retired",
    }
    return f"{prefix}.{suffixes[lifecycle_state]}.v1"


class DomainService:
    def __init__(
        self,
        *,
        store: InMemoryDomainStore,
        validator: SemanticValidator,
        material_provider: Callable[[DomainVersion], SemanticMaterial],
        now: Callable[[], str],
        new_id: Callable[[], str] = lambda: str(uuid4()),
    ) -> None:
        self.store = store
        self.validator = validator
        self.material_provider = material_provider
        self.now = now
        self.new_id = new_id

    def _authorize(self, identity: TenantIdentity, permit: PolicyPermit, action: str, resource_digest: str) -> None:
        if (
            not permit.allowed
            or permit.organization_id != identity.organization_id
            or permit.subject_id != identity.subject_id
            or permit.action != action
            or permit.resource_digest != resource_digest
            or _parse_time(permit.expires_at) <= _parse_time(self.now())
        ):
            raise DomainFailure("POLICY_DENIED")

    @staticmethod
    def _command_fields(idempotency_key: str, correlation_id: str) -> None:
        try:
            token(idempotency_key, "idempotencyKey")
            uuid_text(correlation_id, "correlationId")
        except ValueError as exc:
            raise DomainFailure("COMMAND_METADATA_INVALID") from exc

    @staticmethod
    def _check_identity(identity: TenantIdentity, organization_id: str, creator: str | None = None) -> None:
        if identity.organization_id != organization_id or (creator is not None and identity.subject_id != creator):
            raise DomainFailure("IDENTITY_MISMATCH")

    @staticmethod
    def _idempotent(state: StoreState, organization_id: str, key: str, request_digest: str):
        existing = state.idempotency.get((organization_id, key))
        if existing is None:
            return None
        if existing[0] != request_digest:
            raise DomainFailure("IDEMPOTENCY_CONFLICT")
        return existing[1]

    def _evidence_event(
        self,
        state: StoreState,
        *,
        organization_id: str,
        aggregate_id: str,
        version: str,
        lifecycle_state: str,
        revision: int,
        resource_digest: str,
        package_digest: str,
        report_digest: str | None,
        approval_digest: str | None,
        compatibility_digest: str | None,
        reason_code: str,
        correlation_id: str,
        causation_id: str | None = None,
    ) -> DomainEvidence:
        occurred_at = self.now()
        evidence_body = {
            "organizationId": organization_id,
            "domainId": aggregate_id,
            "version": version,
            "state": lifecycle_state,
            "revision": revision,
            "packageDigest": package_digest,
            "reportDigest": report_digest,
            "approvalEvidenceDigest": approval_digest,
            "compatibilityDigest": compatibility_digest,
            "reasonCode": reason_code,
            "occurredAt": occurred_at,
        }
        evidence = DomainEvidence(record_digest=canonical_digest(evidence_body), **{
            "organization_id": organization_id,
            "domain_id": aggregate_id,
            "version": version,
            "state": lifecycle_state,
            "revision": revision,
            "package_digest": package_digest,
            "report_digest": report_digest,
            "approval_evidence_digest": approval_digest,
            "compatibility_digest": compatibility_digest,
            "reason_code": reason_code,
            "occurred_at": occurred_at,
        })
        event_body = {
            "eventId": self.new_id(),
            "organizationId": organization_id,
            "aggregateId": aggregate_id,
            "aggregateVersion": revision,
            "eventType": _event_type(lifecycle_state, reason_code),
            "resourceDigest": resource_digest,
            "evidenceDigest": evidence.record_digest,
            "reasonCode": reason_code,
            "correlationId": correlation_id,
            "causationId": causation_id,
            "occurredAt": occurred_at,
        }
        event = DomainEvent(event_digest=canonical_digest(event_body), **{
            "event_id": event_body["eventId"],
            "organization_id": organization_id,
            "aggregate_id": aggregate_id,
            "aggregate_version": revision,
            "event_type": event_body["eventType"],
            "resource_digest": resource_digest,
            "evidence_digest": evidence.record_digest,
            "reason_code": reason_code,
            "correlation_id": correlation_id,
            "causation_id": causation_id,
            "occurred_at": occurred_at,
        })
        state.evidence.append(evidence)
        state.events.append(event)
        return evidence

    def create_domain(self, identity: TenantIdentity, permit: PolicyPermit, definition: DomainDefinition, *, idempotency_key: str, correlation_id: str) -> DomainDefinition:
        self._command_fields(idempotency_key, correlation_id)
        self._check_identity(identity, definition.organization_id, definition.created_by_subject_id)
        request_digest = canonical_digest(public_dict(definition))
        self._authorize(identity, permit, "knowledge.domain.create", request_digest)

        def operation(state: StoreState):
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay
            key = (identity.organization_id, definition.domain_id)
            if key in state.definitions:
                raise DomainFailure("DOMAIN_ALREADY_EXISTS")
            state.definitions[key] = definition
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, definition)
            return definition

        return self.store.transact(operation)

    def create_version(self, identity: TenantIdentity, permit: PolicyPermit, version: DomainVersion, *, idempotency_key: str, correlation_id: str) -> VersionRevision:
        self._command_fields(idempotency_key, correlation_id)
        self._check_identity(identity, version.organization_id, version.created_by_subject_id)
        self._authorize(identity, permit, "knowledge.domain.version.create", version.resource_digest)
        request_digest = canonical_digest(public_dict(version))

        def operation(state: StoreState):
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay
            if (identity.organization_id, version.domain_id) not in state.definitions:
                raise DomainFailure("DOMAIN_NOT_FOUND")
            key: VersionKey = (identity.organization_id, version.domain_id, version.version)
            if key in state.versions:
                raise DomainFailure("VERSION_ALREADY_EXISTS")
            revision = VersionRevision(identity.organization_id, version.domain_id, version.version, 1, VersionState.DRAFT, "VERSION_CREATED", self.now(), correlation_id)
            state.versions[key] = version
            state.version_revisions[key] = [revision]
            self._evidence_event(state, organization_id=identity.organization_id, aggregate_id=version.domain_id, version=version.version, lifecycle_state=revision.state.value, revision=1, resource_digest=version.resource_digest, package_digest=version.package_digest, report_digest=None, approval_digest=None, compatibility_digest=None, reason_code=revision.reason_code, correlation_id=correlation_id)
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, revision)
            return revision

        return self.store.transact(operation)

    def _failure_snapshot(self, version: DomainVersion, reason_code: str, started_at: str, completed_at: str) -> SemanticSnapshot:
        finding = Finding(reason_code, "VIOLATION", _failure_digest("FOCUS_REDACTED"), _failure_digest("PATH_REDACTED"), reason_code)
        body = {
            "organizationId": version.organization_id,
            "domainId": version.domain_id,
            "version": version.version,
            "packageDigest": version.package_digest,
            "reasonCode": reason_code,
            "startedAt": started_at,
            "completedAt": completed_at,
        }
        report = ValidationReport(
            version.organization_id, version.domain_id, version.version,
            version.package_digest, _failure_digest("GRAPH_UNAVAILABLE"),
            _failure_digest("SHAPES_UNAVAILABLE"), _failure_digest("ENGINE_UNAVAILABLE"),
            _failure_digest("SAFE_MODES"), False, 0, 0, (finding,),
            canonical_digest([]), started_at, completed_at, canonical_digest(body),
        )
        return SemanticSnapshot(report, ())

    def validate_version(self, identity: TenantIdentity, permit: PolicyPermit, domain_id: str, version_text: str, *, expected_revision: int, idempotency_key: str, correlation_id: str) -> ValidationReport:
        self._command_fields(idempotency_key, correlation_id)
        key: VersionKey = (identity.organization_id, domain_id, version_text)
        version = self.store.read(lambda state: state.versions.get(key))
        if version is None:
            raise DomainFailure("VERSION_NOT_FOUND")
        self._authorize(identity, permit, "knowledge.domain.version.validate", version.resource_digest)
        request_digest = canonical_digest({"resourceDigest": version.resource_digest, "expectedRevision": expected_revision})
        replay = self.store.read(lambda state: self._idempotent(state, identity.organization_id, idempotency_key, request_digest))
        if replay is not None:
            return replay
        current = self.store.read(lambda state: state.version_revisions[key][-1])
        if current.revision != expected_revision:
            raise DomainFailure("STALE_REVISION")
        if current.state is not VersionState.DRAFT:
            raise DomainFailure("TRANSITION_FORBIDDEN")
        started_at = self.now()
        try:
            material = self.material_provider(version)
            snapshot = self.validator.validate(
                organization_id=identity.organization_id,
                domain_id=domain_id,
                version=version_text,
                package_digest=version.package_digest,
                expected_ontology_digest=version.ontology_digest,
                expected_shapes_digest=version.shapes_digest,
                material=material,
                started_at=started_at,
                completed_at=self.now(),
            )
        except SemanticFailure as exc:
            snapshot = self._failure_snapshot(version, exc.reason_code, started_at, self.now())
        except Exception:
            snapshot = self._failure_snapshot(version, "MATERIAL_PROVIDER_UNAVAILABLE", started_at, self.now())
        final_state = VersionState.VALID if snapshot.report.conforms else VersionState.INVALID
        reason = "VALIDATION_CONFORMS" if snapshot.report.conforms else snapshot.report.findings[0].reason_code

        def operation(state: StoreState):
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay
            revisions = state.version_revisions[key]
            if revisions[-1].revision != expected_revision:
                raise DomainFailure("STALE_REVISION")
            if revisions[-1].state is not VersionState.DRAFT:
                raise DomainFailure("TRANSITION_FORBIDDEN")
            validating = VersionRevision(identity.organization_id, domain_id, version_text, expected_revision + 1, VersionState.VALIDATING, "VALIDATION_STARTED", started_at, correlation_id)
            final = VersionRevision(identity.organization_id, domain_id, version_text, expected_revision + 2, final_state, reason, self.now(), correlation_id)
            revisions.extend((validating, final))
            state.reports[key] = snapshot.report
            state.snapshots[key] = snapshot
            self._evidence_event(state, organization_id=identity.organization_id, aggregate_id=domain_id, version=version_text, lifecycle_state=final.state.value, revision=final.revision, resource_digest=version.resource_digest, package_digest=version.package_digest, report_digest=snapshot.report.report_digest, approval_digest=None, compatibility_digest=None, reason_code=reason, correlation_id=correlation_id)
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, snapshot.report)
            return snapshot.report

        return self.store.transact(operation)

    def request_approval(self, identity: TenantIdentity, permit: PolicyPermit, domain_id: str, version_text: str, *, expected_revision: int, idempotency_key: str, correlation_id: str) -> VersionRevision:
        return self._transition(identity, permit, domain_id, version_text, expected_revision=expected_revision, expected_state=VersionState.VALID, new_state=VersionState.AWAITING_APPROVAL, action="knowledge.domain.version.request-approval", reason_code="APPROVAL_REQUESTED", idempotency_key=idempotency_key, correlation_id=correlation_id)

    def _transition(self, identity: TenantIdentity, permit: PolicyPermit, domain_id: str, version_text: str, *, expected_revision: int, expected_state: VersionState, new_state: VersionState, action: str, reason_code: str, idempotency_key: str, correlation_id: str) -> VersionRevision:
        self._command_fields(idempotency_key, correlation_id)
        key: VersionKey = (identity.organization_id, domain_id, version_text)
        version = self.store.read(lambda state: state.versions.get(key))
        if version is None:
            raise DomainFailure("VERSION_NOT_FOUND")
        self._authorize(identity, permit, action, version.resource_digest)
        request_digest = canonical_digest({"resourceDigest": version.resource_digest, "expectedRevision": expected_revision, "state": new_state.value})

        def operation(state: StoreState):
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay
            current = state.version_revisions[key][-1]
            if current.revision != expected_revision:
                raise DomainFailure("STALE_REVISION")
            if current.state is not expected_state:
                raise DomainFailure("TRANSITION_FORBIDDEN")
            revision = VersionRevision(identity.organization_id, domain_id, version_text, expected_revision + 1, new_state, reason_code, self.now(), correlation_id)
            state.version_revisions[key].append(revision)
            report = state.reports.get(key)
            approval = state.approvals.get(key)
            self._evidence_event(state, organization_id=identity.organization_id, aggregate_id=domain_id, version=version_text, lifecycle_state=new_state.value, revision=revision.revision, resource_digest=version.resource_digest, package_digest=version.package_digest, report_digest=report.report_digest if report else None, approval_digest=approval.evidence_digest if approval else None, compatibility_digest=None, reason_code=reason_code, correlation_id=correlation_id)
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, revision)
            return revision

        return self.store.transact(operation)

    def record_decision(self, identity: TenantIdentity, permit: PolicyPermit, attestation: ApprovalAttestation, *, expected_revision: int, idempotency_key: str, correlation_id: str) -> VersionRevision:
        self._command_fields(idempotency_key, correlation_id)
        self._check_identity(identity, attestation.organization_id)
        key: VersionKey = (identity.organization_id, attestation.domain_id, attestation.version)
        version = self.store.read(lambda state: state.versions.get(key))
        if version is None:
            raise DomainFailure("VERSION_NOT_FOUND")
        self._authorize(identity, permit, "knowledge.domain.version.record-decision", version.resource_digest)
        if attestation.package_digest != version.package_digest or attestation.approver_subject_id == version.created_by_subject_id:
            raise DomainFailure("APPROVAL_MISMATCH")
        request_digest = canonical_digest(public_dict(attestation))

        def operation(state: StoreState):
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay
            current = state.version_revisions[key][-1]
            if current.revision != expected_revision:
                raise DomainFailure("STALE_REVISION")
            if current.state is not VersionState.AWAITING_APPROVAL or key in state.approvals:
                raise DomainFailure("TRANSITION_FORBIDDEN")
            state.approvals[key] = attestation
            if attestation.decision is Decision.REJECTED:
                current = VersionRevision(identity.organization_id, attestation.domain_id, attestation.version, expected_revision + 1, VersionState.REJECTED, "APPROVAL_REJECTED", self.now(), correlation_id)
                state.version_revisions[key].append(current)
            self._evidence_event(state, organization_id=identity.organization_id, aggregate_id=attestation.domain_id, version=attestation.version, lifecycle_state=current.state.value, revision=current.revision, resource_digest=version.resource_digest, package_digest=version.package_digest, report_digest=state.reports[key].report_digest, approval_digest=attestation.evidence_digest, compatibility_digest=None, reason_code="APPROVAL_RECORDED", correlation_id=correlation_id)
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, current)
            return current

        return self.store.transact(operation)

    @staticmethod
    def _compatibility_allowed(mode: CompatibilityMode, report: CompatibilityReport) -> bool:
        return report.state is CompatibilityState.IDENTICAL or (mode is CompatibilityMode.BACKWARD and report.state is CompatibilityState.BACKWARD_COMPATIBLE)

    def publish(self, identity: TenantIdentity, permit: PolicyPermit, domain_id: str, version_text: str, *, expected_revision: int, idempotency_key: str, correlation_id: str) -> VersionRevision:
        return self._activate(identity, permit, domain_id, version_text, expected_revision=expected_revision, expected_state=VersionState.AWAITING_APPROVAL, action="knowledge.domain.version.publish", idempotency_key=idempotency_key, correlation_id=correlation_id)

    def rollback(self, identity: TenantIdentity, permit: PolicyPermit, domain_id: str, version_text: str, *, expected_revision: int, idempotency_key: str, correlation_id: str) -> VersionRevision:
        return self._activate(identity, permit, domain_id, version_text, expected_revision=expected_revision, expected_state=VersionState.SUPERSEDED, action="knowledge.domain.version.rollback", idempotency_key=idempotency_key, correlation_id=correlation_id)

    def _activate(self, identity: TenantIdentity, permit: PolicyPermit, domain_id: str, version_text: str, *, expected_revision: int, expected_state: VersionState, action: str, idempotency_key: str, correlation_id: str) -> VersionRevision:
        self._command_fields(idempotency_key, correlation_id)
        key: VersionKey = (identity.organization_id, domain_id, version_text)
        version = self.store.read(lambda state: state.versions.get(key))
        if version is None:
            raise DomainFailure("VERSION_NOT_FOUND")
        self._authorize(identity, permit, action, version.resource_digest)
        request_digest = canonical_digest({"resourceDigest": version.resource_digest, "expectedRevision": expected_revision, "action": action})

        def operation(state: StoreState):
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay
            current = state.version_revisions[key][-1]
            if current.revision != expected_revision:
                raise DomainFailure("STALE_REVISION")
            if current.state is not expected_state:
                raise DomainFailure("TRANSITION_FORBIDDEN")
            approval = state.approvals.get(key)
            report = state.reports.get(key)
            snapshot = state.snapshots.get(key)
            if approval is None or approval.decision is not Decision.APPROVED or report is None or not report.conforms or snapshot is None:
                raise DomainFailure("APPROVAL_OR_VALIDATION_REQUIRED")
            definition = state.definitions[(identity.organization_id, domain_id)]
            prior_version_text = state.active_domains.get((identity.organization_id, domain_id))
            prior_snapshot = state.snapshots.get((identity.organization_id, domain_id, prior_version_text)) if prior_version_text else None
            compatibility = (
                classify_compatibility(prior_snapshot.term_statements, snapshot.term_statements)
                if prior_snapshot is not None
                else classify_compatibility(snapshot.term_statements, snapshot.term_statements)
            )
            if not self._compatibility_allowed(definition.compatibility_mode, compatibility):
                raise DomainFailure("COMPATIBILITY_BLOCKED")
            if prior_version_text == version_text:
                raise DomainFailure("VERSION_ALREADY_ACTIVE")
            if prior_version_text is not None:
                prior_key = (identity.organization_id, domain_id, prior_version_text)
                prior_current = state.version_revisions[prior_key][-1]
                if prior_current.state is not VersionState.ACTIVE:
                    raise DomainFailure("ACTIVE_POINTER_CORRUPT")
                prior_revision = VersionRevision(identity.organization_id, domain_id, prior_version_text, prior_current.revision + 1, VersionState.SUPERSEDED, "VERSION_SUPERSEDED", self.now(), correlation_id)
                state.version_revisions[prior_key].append(prior_revision)
                prior_version = state.versions[prior_key]
                self._evidence_event(state, organization_id=identity.organization_id, aggregate_id=domain_id, version=prior_version_text, lifecycle_state=VersionState.SUPERSEDED.value, revision=prior_revision.revision, resource_digest=prior_version.resource_digest, package_digest=prior_version.package_digest, report_digest=state.reports[prior_key].report_digest, approval_digest=state.approvals[prior_key].evidence_digest, compatibility_digest=canonical_digest(asdict(compatibility)), reason_code="VERSION_SUPERSEDED", correlation_id=correlation_id)
                for active_key, active_mapping_version in tuple(state.active_mappings.items()):
                    mapping_key = (active_key[0], active_key[1], active_mapping_version)
                    mapping = state.mappings[mapping_key]
                    if active_key[0] != identity.organization_id or mapping.domain_version_digest != prior_version.resource_digest:
                        continue
                    mapping_current = state.mapping_revisions[mapping_key][-1]
                    if mapping_current.state is not MappingState.ACTIVE:
                        raise DomainFailure("ACTIVE_MAPPING_POINTER_CORRUPT")
                    mapping_revision = MappingRevision(
                        identity.organization_id,
                        mapping.mapping_id,
                        mapping.version,
                        mapping_current.revision + 1,
                        MappingState.SUPERSEDED,
                        "DOMAIN_VERSION_SUPERSEDED",
                        self.now(),
                        correlation_id,
                    )
                    state.mapping_revisions[mapping_key].append(mapping_revision)
                    del state.active_mappings[active_key]
                    approval_digest = state.mapping_approvals[mapping_key].evidence_digest
                    self._evidence_event(
                        state,
                        organization_id=identity.organization_id,
                        aggregate_id=mapping.mapping_id,
                        version=mapping.version,
                        lifecycle_state=MappingState.SUPERSEDED.value,
                        revision=mapping_revision.revision,
                        resource_digest=mapping.resource_digest,
                        package_digest=mapping.domain_version_digest,
                        report_digest=state.mapping_validation_digests[mapping_key],
                        approval_digest=approval_digest,
                        compatibility_digest=None,
                        reason_code="DOMAIN_VERSION_SUPERSEDED",
                        correlation_id=correlation_id,
                    )
            active = VersionRevision(identity.organization_id, domain_id, version_text, expected_revision + 1, VersionState.ACTIVE, "VERSION_ACTIVATED", self.now(), correlation_id)
            state.version_revisions[key].append(active)
            state.active_domains[(identity.organization_id, domain_id)] = version_text
            self._evidence_event(state, organization_id=identity.organization_id, aggregate_id=domain_id, version=version_text, lifecycle_state=VersionState.ACTIVE.value, revision=active.revision, resource_digest=version.resource_digest, package_digest=version.package_digest, report_digest=report.report_digest, approval_digest=approval.evidence_digest, compatibility_digest=canonical_digest(asdict(compatibility)), reason_code="VERSION_ACTIVATED", correlation_id=correlation_id)
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, active)
            return active

        return self.store.transact(operation)

    def retire_version(self, identity: TenantIdentity, permit: PolicyPermit, domain_id: str, version_text: str, *, expected_revision: int, idempotency_key: str, correlation_id: str) -> VersionRevision:
        return self._transition(
            identity,
            permit,
            domain_id,
            version_text,
            expected_revision=expected_revision,
            expected_state=VersionState.SUPERSEDED,
            new_state=VersionState.RETIRED,
            action="knowledge.domain.version.retire",
            reason_code="VERSION_RETIRED",
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
        )

    def list_versions(self, identity: TenantIdentity, permit: PolicyPermit, domain_id: str) -> tuple[VersionRevision, ...]:
        resource = canonical_digest({"organizationId": identity.organization_id, "domainId": domain_id})
        self._authorize(identity, permit, "knowledge.domain.read", resource)
        return self.store.read(lambda state: tuple(sorted((revisions[-1] for key, revisions in state.version_revisions.items() if key[:2] == (identity.organization_id, domain_id)), key=lambda item: item.version)))

    def report(self, identity: TenantIdentity, permit: PolicyPermit, domain_id: str, version_text: str) -> ValidationReport:
        key = (identity.organization_id, domain_id, version_text)
        version = self.store.read(lambda state: state.versions.get(key))
        if version is None:
            raise DomainFailure("VERSION_NOT_FOUND")
        self._authorize(identity, permit, "knowledge.domain.read", version.resource_digest)
        report = self.store.read(lambda state: state.reports.get(key))
        if report is None:
            raise DomainFailure("REPORT_NOT_FOUND")
        return report

    def resolve(self, identity: TenantIdentity, permit: PolicyPermit, domain_id: str, version_text: str, term: str) -> dict[str, str]:
        key = (identity.organization_id, domain_id, version_text)
        version = self.store.read(lambda state: state.versions.get(key))
        if version is None:
            raise DomainFailure("VERSION_NOT_FOUND")
        self._authorize(identity, permit, "knowledge.domain.resolve", version.resource_digest)
        snapshot, current = self.store.read(lambda state: (state.snapshots.get(key), state.version_revisions[key][-1]))
        if current.state is not VersionState.ACTIVE or snapshot is None or term not in snapshot.terms:
            raise DomainFailure("TERM_NOT_RESOLVABLE")
        return {"schemaVersion": "planeon.knowledge.domain/v1", "term": term, "termDigest": canonical_digest({"term": term}), "domainVersionDigest": version.resource_digest}

    def validate_mapping(self, identity: TenantIdentity, permit: PolicyPermit, mapping: SemanticMapping, *, idempotency_key: str, correlation_id: str) -> MappingRevision:
        self._command_fields(idempotency_key, correlation_id)
        self._check_identity(identity, mapping.organization_id, mapping.created_by_subject_id)
        self._authorize(identity, permit, "knowledge.domain.mapping.validate", mapping.resource_digest)
        request_digest = canonical_digest(public_dict(mapping))

        def operation(state: StoreState):
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay
            domain_key = next((key for key, item in state.versions.items() if key[0] == identity.organization_id and item.resource_digest == mapping.domain_version_digest), None)
            if domain_key is None or state.version_revisions[domain_key][-1].state is not VersionState.ACTIVE:
                raise DomainFailure("ACTIVE_DOMAIN_DIGEST_REQUIRED")
            snapshot = state.snapshots[domain_key]
            missing = sorted({assertion.target_term for assertion in mapping.assertions} - snapshot.terms)
            final = MappingState.INVALID if missing else MappingState.VALID
            reason = "MAPPING_TARGET_MISSING" if missing else "MAPPING_VALID"
            report_digest = canonical_digest({"missingTermDigests": [canonical_digest({"term": term}) for term in missing]})
            key: MappingKey = (identity.organization_id, mapping.mapping_id, mapping.version)
            if key in state.mappings:
                raise DomainFailure("MAPPING_ALREADY_EXISTS")
            state.mappings[key] = mapping
            state.mapping_revisions[key] = [
                MappingRevision(identity.organization_id, mapping.mapping_id, mapping.version, 1, MappingState.DRAFT, "MAPPING_CREATED", self.now(), correlation_id),
                MappingRevision(identity.organization_id, mapping.mapping_id, mapping.version, 2, MappingState.VALIDATING, "MAPPING_VALIDATION_STARTED", self.now(), correlation_id),
                MappingRevision(identity.organization_id, mapping.mapping_id, mapping.version, 3, final, reason, self.now(), correlation_id),
            ]
            state.mapping_validation_digests[key] = report_digest
            result = state.mapping_revisions[key][-1]
            self._evidence_event(state, organization_id=identity.organization_id, aggregate_id=mapping.mapping_id, version=mapping.version, lifecycle_state=final.value, revision=3, resource_digest=mapping.resource_digest, package_digest=mapping.domain_version_digest, report_digest=report_digest, approval_digest=None, compatibility_digest=None, reason_code=reason, correlation_id=correlation_id)
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, result)
            return result

        return self.store.transact(operation)

    def request_mapping_approval(self, identity: TenantIdentity, permit: PolicyPermit, mapping_id: str, version_text: str, *, expected_revision: int, idempotency_key: str, correlation_id: str) -> MappingRevision:
        self._command_fields(idempotency_key, correlation_id)
        key: MappingKey = (identity.organization_id, mapping_id, version_text)
        mapping = self.store.read(lambda state: state.mappings.get(key))
        if mapping is None:
            raise DomainFailure("MAPPING_NOT_FOUND")
        self._authorize(identity, permit, "knowledge.domain.mapping.request-approval", mapping.resource_digest)
        request_digest = canonical_digest({"resourceDigest": mapping.resource_digest, "expectedRevision": expected_revision, "state": MappingState.AWAITING_APPROVAL.value})

        def operation(state: StoreState):
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay
            current = state.mapping_revisions[key][-1]
            if current.revision != expected_revision:
                raise DomainFailure("STALE_REVISION")
            if current.state is not MappingState.VALID:
                raise DomainFailure("TRANSITION_FORBIDDEN")
            revision = MappingRevision(identity.organization_id, mapping_id, version_text, expected_revision + 1, MappingState.AWAITING_APPROVAL, "MAPPING_APPROVAL_REQUESTED", self.now(), correlation_id)
            state.mapping_revisions[key].append(revision)
            self._evidence_event(state, organization_id=identity.organization_id, aggregate_id=mapping_id, version=version_text, lifecycle_state=revision.state.value, revision=revision.revision, resource_digest=mapping.resource_digest, package_digest=mapping.domain_version_digest, report_digest=state.mapping_validation_digests[key], approval_digest=None, compatibility_digest=None, reason_code=revision.reason_code, correlation_id=correlation_id)
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, revision)
            return revision

        return self.store.transact(operation)

    def record_mapping_decision(self, identity: TenantIdentity, permit: PolicyPermit, attestation: MappingApprovalAttestation, *, expected_revision: int, idempotency_key: str, correlation_id: str) -> MappingRevision:
        self._command_fields(idempotency_key, correlation_id)
        self._check_identity(identity, attestation.organization_id)
        key: MappingKey = (identity.organization_id, attestation.mapping_id, attestation.version)
        mapping = self.store.read(lambda state: state.mappings.get(key))
        if mapping is None:
            raise DomainFailure("MAPPING_NOT_FOUND")
        self._authorize(identity, permit, "knowledge.domain.mapping.record-decision", mapping.resource_digest)
        if attestation.mapping_digest != mapping.resource_digest or attestation.approver_subject_id == mapping.created_by_subject_id:
            raise DomainFailure("APPROVAL_MISMATCH")
        request_digest = canonical_digest(public_dict(attestation))

        def operation(state: StoreState):
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay
            current = state.mapping_revisions[key][-1]
            if current.revision != expected_revision:
                raise DomainFailure("STALE_REVISION")
            if current.state is not MappingState.AWAITING_APPROVAL or key in state.mapping_approvals:
                raise DomainFailure("TRANSITION_FORBIDDEN")
            state.mapping_approvals[key] = attestation
            reason_code = "MAPPING_APPROVAL_RECORDED"
            if attestation.decision is Decision.REJECTED:
                current = MappingRevision(identity.organization_id, attestation.mapping_id, attestation.version, expected_revision + 1, MappingState.REJECTED, "MAPPING_APPROVAL_REJECTED", self.now(), correlation_id)
                state.mapping_revisions[key].append(current)
                reason_code = "MAPPING_APPROVAL_REJECTED"
            self._evidence_event(state, organization_id=identity.organization_id, aggregate_id=mapping.mapping_id, version=mapping.version, lifecycle_state=current.state.value, revision=current.revision, resource_digest=mapping.resource_digest, package_digest=mapping.domain_version_digest, report_digest=state.mapping_validation_digests[key], approval_digest=attestation.evidence_digest, compatibility_digest=None, reason_code=reason_code, correlation_id=correlation_id)
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, current)
            return current

        return self.store.transact(operation)

    def activate_mapping(self, identity: TenantIdentity, permit: PolicyPermit, mapping_id: str, version_text: str, *, expected_revision: int, idempotency_key: str, correlation_id: str) -> MappingRevision:
        self._command_fields(idempotency_key, correlation_id)
        key: MappingKey = (identity.organization_id, mapping_id, version_text)
        mapping = self.store.read(lambda state: state.mappings.get(key))
        if mapping is None:
            raise DomainFailure("MAPPING_NOT_FOUND")
        self._authorize(identity, permit, "knowledge.domain.mapping.activate", mapping.resource_digest)
        request_digest = canonical_digest({"resourceDigest": mapping.resource_digest, "expectedRevision": expected_revision, "action": "activate"})

        def operation(state: StoreState):
            replay = self._idempotent(state, identity.organization_id, idempotency_key, request_digest)
            if replay is not None:
                return replay
            current = state.mapping_revisions[key][-1]
            if current.revision != expected_revision:
                raise DomainFailure("STALE_REVISION")
            if current.state is not MappingState.AWAITING_APPROVAL:
                raise DomainFailure("TRANSITION_FORBIDDEN")
            approval = state.mapping_approvals.get(key)
            if approval is None or approval.decision is not Decision.APPROVED:
                raise DomainFailure("APPROVAL_OR_VALIDATION_REQUIRED")
            domain_key = next((candidate for candidate, item in state.versions.items() if candidate[0] == identity.organization_id and item.resource_digest == mapping.domain_version_digest), None)
            if domain_key is None or state.version_revisions[domain_key][-1].state is not VersionState.ACTIVE:
                raise DomainFailure("ACTIVE_DOMAIN_DIGEST_REQUIRED")
            active_key = (identity.organization_id, mapping.mapping_id)
            prior_version = state.active_mappings.get(active_key)
            if prior_version == version_text:
                raise DomainFailure("MAPPING_ALREADY_ACTIVE")
            if prior_version is not None:
                prior_key = (identity.organization_id, mapping.mapping_id, prior_version)
                prior_current = state.mapping_revisions[prior_key][-1]
                if prior_current.state is not MappingState.ACTIVE:
                    raise DomainFailure("ACTIVE_MAPPING_POINTER_CORRUPT")
                prior_mapping = state.mappings[prior_key]
                prior_revision = MappingRevision(identity.organization_id, mapping.mapping_id, prior_version, prior_current.revision + 1, MappingState.SUPERSEDED, "MAPPING_SUPERSEDED", self.now(), correlation_id)
                state.mapping_revisions[prior_key].append(prior_revision)
                self._evidence_event(state, organization_id=identity.organization_id, aggregate_id=prior_mapping.mapping_id, version=prior_mapping.version, lifecycle_state=prior_revision.state.value, revision=prior_revision.revision, resource_digest=prior_mapping.resource_digest, package_digest=prior_mapping.domain_version_digest, report_digest=state.mapping_validation_digests[prior_key], approval_digest=state.mapping_approvals[prior_key].evidence_digest, compatibility_digest=None, reason_code=prior_revision.reason_code, correlation_id=correlation_id)
            active = MappingRevision(identity.organization_id, mapping.mapping_id, mapping.version, expected_revision + 1, MappingState.ACTIVE, "MAPPING_ACTIVATED", self.now(), correlation_id)
            state.mapping_revisions[key].append(active)
            state.active_mappings[active_key] = version_text
            self._evidence_event(state, organization_id=identity.organization_id, aggregate_id=mapping.mapping_id, version=mapping.version, lifecycle_state=active.state.value, revision=active.revision, resource_digest=mapping.resource_digest, package_digest=mapping.domain_version_digest, report_digest=state.mapping_validation_digests[key], approval_digest=approval.evidence_digest, compatibility_digest=None, reason_code=active.reason_code, correlation_id=correlation_id)
            state.idempotency[(identity.organization_id, idempotency_key)] = (request_digest, active)
            return active

        return self.store.transact(operation)
