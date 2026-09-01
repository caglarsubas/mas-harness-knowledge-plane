"""Closed immutable domain-service contracts."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.common.validation import digest, token, utc_seconds, uuid_text

SCHEMA = "planeon.knowledge.domain/v1"
STABLE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$")
LANGUAGE = re.compile(r"^[a-z]{2,3}(?:-[A-Z]{2})?$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$")
W3C_IRI_ROOT = "http" + "://www.w3.org/"
TERM = re.compile(
    r"^(?:urn:planeon:[a-z0-9.-]+:[^\s]+|"
    + re.escape(W3C_IRI_ROOT)
    + r"(?:1999/02/22-rdf-syntax-ns#|2000/01/rdf-schema#|2001/XMLSchema#|2002/07/owl#|ns/shacl#)[^\s]*)$"
)


def stable_id(value: str, field: str) -> str:
    if not isinstance(value, str) or STABLE_ID.fullmatch(value) is None or len(value) > 128:
        raise ValueError(f"{field} must be a stable id")
    return value


def semver(value: str, field: str = "version") -> str:
    if not isinstance(value, str) or SEMVER.fullmatch(value) is None or len(value) > 64:
        raise ValueError(f"{field} must be semantic version text")
    return value


def closed_tuple(values: tuple[str, ...], field: str, validator, *, minimum: int = 1, maximum: int = 32) -> tuple[str, ...]:
    if not isinstance(values, tuple) or not minimum <= len(values) <= maximum:
        raise ValueError(f"{field} cardinality is outside the closed range")
    checked = tuple(validator(value, field) for value in values)
    if checked != tuple(sorted(set(checked))):
        raise ValueError(f"{field} must be sorted and unique")
    return checked


def language(value: str, field: str) -> str:
    if not isinstance(value, str) or LANGUAGE.fullmatch(value) is None:
        raise ValueError(f"{field} is not a supported language tag")
    return value


def optional_digest(value: str | None, field: str) -> str | None:
    if value is not None:
        digest(value, field)
    return value


class CompatibilityMode(StrEnum):
    BACKWARD = "BACKWARD"
    STRICT = "STRICT"


class CompatibilityState(StrEnum):
    IDENTICAL = "IDENTICAL"
    BACKWARD_COMPATIBLE = "BACKWARD_COMPATIBLE"
    BREAKING = "BREAKING"


class VersionState(StrEnum):
    DRAFT = "DRAFT"
    VALIDATING = "VALIDATING"
    VALID = "VALID"
    INVALID = "INVALID"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    ACTIVE = "ACTIVE"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"
    RETIRED = "RETIRED"


class MappingState(StrEnum):
    DRAFT = "DRAFT"
    VALIDATING = "VALIDATING"
    VALID = "VALID"
    INVALID = "INVALID"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    ACTIVE = "ACTIVE"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"


class Decision(StrEnum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class TransformationKind(StrEnum):
    DIRECT = "DIRECT"
    ENUM = "ENUM"
    UNIT = "UNIT"
    DERIVED = "DERIVED"


@dataclass(frozen=True, slots=True)
class DomainDefinition:
    organization_id: str
    domain_id: str
    display_name: str
    default_language: str
    supported_languages: tuple[str, ...]
    business_owner_ids: tuple[str, ...]
    data_owner_ids: tuple[str, ...]
    compatibility_mode: CompatibilityMode
    created_at: str
    created_by_subject_id: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        stable_id(self.domain_id, "domainId")
        if not isinstance(self.display_name, str) or not 1 <= len(self.display_name) <= 160 or any(character in self.display_name for character in "\r\n\x00"):
            raise ValueError("displayName is outside the closed text domain")
        language(self.default_language, "defaultLanguage")
        closed_tuple(self.supported_languages, "supportedLanguages", language)
        if self.default_language not in self.supported_languages:
            raise ValueError("defaultLanguage must be supported")
        closed_tuple(self.business_owner_ids, "businessOwnerIds", token)
        closed_tuple(self.data_owner_ids, "dataOwnerIds", token)
        if not isinstance(self.compatibility_mode, CompatibilityMode):
            raise ValueError("compatibilityMode is invalid")
        utc_seconds(self.created_at, "createdAt")
        token(self.created_by_subject_id, "createdBySubjectId")


@dataclass(frozen=True, slots=True)
class DomainVersion:
    organization_id: str
    domain_id: str
    version: str
    package_digest: str
    ontology_digest: str
    shapes_digest: str
    import_manifest_digest: str
    owners_digest: str
    created_at: str
    created_by_subject_id: str
    license_expression: str = "Apache-2.0"

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        stable_id(self.domain_id, "domainId")
        semver(self.version)
        for field, value in (("packageDigest", self.package_digest), ("ontologyDigest", self.ontology_digest), ("shapesDigest", self.shapes_digest), ("importManifestDigest", self.import_manifest_digest), ("ownersDigest", self.owners_digest)):
            digest(value, field)
        utc_seconds(self.created_at, "createdAt")
        token(self.created_by_subject_id, "createdBySubjectId")
        if self.license_expression != "Apache-2.0":
            raise ValueError("only Apache-2.0 domain material is admitted")

    @property
    def resource_digest(self) -> str:
        return canonical_digest({
            "organizationId": self.organization_id,
            "domainId": self.domain_id,
            "version": self.version,
            "packageDigest": self.package_digest,
            "ontologyDigest": self.ontology_digest,
            "shapesDigest": self.shapes_digest,
            "importManifestDigest": self.import_manifest_digest,
            "ownersDigest": self.owners_digest,
            "licenseExpression": self.license_expression,
        })


@dataclass(frozen=True, slots=True)
class VersionRevision:
    organization_id: str
    domain_id: str
    version: str
    revision: int
    state: VersionState
    reason_code: str
    occurred_at: str
    correlation_id: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        stable_id(self.domain_id, "domainId")
        semver(self.version)
        if not isinstance(self.revision, int) or isinstance(self.revision, bool) or self.revision < 1:
            raise ValueError("revision must be positive")
        token(self.reason_code, "reasonCode")
        if not isinstance(self.state, VersionState):
            raise ValueError("version state is invalid")
        utc_seconds(self.occurred_at, "occurredAt")
        uuid_text(self.correlation_id, "correlationId")


@dataclass(frozen=True, slots=True)
class PolicyPermit:
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
class ApprovalAttestation:
    approval_id: str
    organization_id: str
    domain_id: str
    version: str
    package_digest: str
    decision: Decision
    decided_at: str
    approver_subject_id: str
    evidence_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.approval_id, "approvalId")
        uuid_text(self.organization_id, "organizationId")
        stable_id(self.domain_id, "domainId")
        semver(self.version)
        digest(self.package_digest, "packageDigest")
        if not isinstance(self.decision, Decision):
            raise ValueError("decision is invalid")
        utc_seconds(self.decided_at, "decidedAt")
        token(self.approver_subject_id, "approverSubjectId")
        digest(self.evidence_digest, "evidenceDigest")


@dataclass(frozen=True, slots=True)
class Finding:
    reason_code: str
    severity: str
    focus_digest: str
    path_digest: str
    constraint_component: str

    def __post_init__(self) -> None:
        token(self.reason_code, "reasonCode")
        if self.severity not in {"INFO", "WARNING", "VIOLATION"}:
            raise ValueError("severity is invalid")
        digest(self.focus_digest, "focusDigest")
        digest(self.path_digest, "pathDigest")
        token(self.constraint_component, "constraintComponent")


@dataclass(frozen=True, slots=True)
class ValidationReport:
    organization_id: str
    domain_id: str
    version: str
    package_digest: str
    graph_digest: str
    shapes_digest: str
    engine_versions_digest: str
    mode_digest: str
    conforms: bool
    data_triples: int
    shape_triples: int
    findings: tuple[Finding, ...]
    term_inventory_digest: str
    started_at: str
    completed_at: str
    report_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        stable_id(self.domain_id, "domainId")
        semver(self.version)
        for field, value in (("packageDigest", self.package_digest), ("graphDigest", self.graph_digest), ("shapesDigest", self.shapes_digest), ("engineVersionsDigest", self.engine_versions_digest), ("modeDigest", self.mode_digest), ("termInventoryDigest", self.term_inventory_digest), ("reportDigest", self.report_digest)):
            digest(value, field)
        if type(self.conforms) is not bool or not 0 <= self.data_triples <= 50_000 or not 0 <= self.shape_triples <= 20_000 or len(self.findings) > 128:
            raise ValueError("validation report bounds are invalid")
        if self.findings != tuple(sorted(self.findings, key=lambda item: (item.reason_code, item.focus_digest, item.path_digest, item.constraint_component))):
            raise ValueError("findings must be deterministically sorted")
        utc_seconds(self.started_at, "startedAt")
        utc_seconds(self.completed_at, "completedAt")


@dataclass(frozen=True, slots=True)
class CompatibilityReport:
    state: CompatibilityState
    prior_inventory_digest: str
    candidate_inventory_digest: str
    changed_terms_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.state, CompatibilityState):
            raise ValueError("compatibility state is invalid")
        digest(self.prior_inventory_digest, "priorInventoryDigest")
        digest(self.candidate_inventory_digest, "candidateInventoryDigest")
        digest(self.changed_terms_digest, "changedTermsDigest")


@dataclass(frozen=True, slots=True)
class MappingAssertion:
    source_field_digest: str
    target_term: str
    transformation_kind: TransformationKind
    provenance_digests: tuple[str, ...]

    def __post_init__(self) -> None:
        digest(self.source_field_digest, "sourceFieldDigest")
        if not isinstance(self.target_term, str) or TERM.fullmatch(self.target_term) is None:
            raise ValueError("targetTerm is outside the closed IRI domain")
        if not isinstance(self.transformation_kind, TransformationKind):
            raise ValueError("transformationKind is invalid")
        closed_tuple(self.provenance_digests, "provenanceDigests", digest, maximum=64)


@dataclass(frozen=True, slots=True)
class SemanticMapping:
    organization_id: str
    mapping_id: str
    version: str
    domain_version_digest: str
    source_schema_digest: str
    assertions: tuple[MappingAssertion, ...]
    owners_digest: str
    created_at: str
    created_by_subject_id: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        stable_id(self.mapping_id, "mappingId")
        semver(self.version)
        digest(self.domain_version_digest, "domainVersionDigest")
        digest(self.source_schema_digest, "sourceSchemaDigest")
        if not isinstance(self.assertions, tuple) or not 1 <= len(self.assertions) <= 512:
            raise ValueError("assertions cardinality is outside the closed range")
        if self.assertions != tuple(sorted(set(self.assertions), key=lambda item: (item.source_field_digest, item.target_term, item.transformation_kind.value, item.provenance_digests))):
            raise ValueError("assertions must be sorted and unique")
        digest(self.owners_digest, "ownersDigest")
        utc_seconds(self.created_at, "createdAt")
        token(self.created_by_subject_id, "createdBySubjectId")

    @property
    def assertions_digest(self) -> str:
        return canonical_digest([
            {
                "sourceFieldDigest": item.source_field_digest,
                "targetTerm": item.target_term,
                "transformationKind": item.transformation_kind.value,
                "provenanceDigests": list(item.provenance_digests),
            }
            for item in self.assertions
        ])

    @property
    def resource_digest(self) -> str:
        return canonical_digest({
            "organizationId": self.organization_id,
            "mappingId": self.mapping_id,
            "version": self.version,
            "domainVersionDigest": self.domain_version_digest,
            "sourceSchemaDigest": self.source_schema_digest,
            "assertionsDigest": self.assertions_digest,
            "ownersDigest": self.owners_digest,
        })


@dataclass(frozen=True, slots=True)
class MappingRevision:
    organization_id: str
    mapping_id: str
    version: str
    revision: int
    state: MappingState
    reason_code: str
    occurred_at: str
    correlation_id: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        stable_id(self.mapping_id, "mappingId")
        semver(self.version)
        if not isinstance(self.revision, int) or isinstance(self.revision, bool) or self.revision < 1:
            raise ValueError("revision must be positive")
        if not isinstance(self.state, MappingState):
            raise ValueError("mapping state is invalid")
        token(self.reason_code, "reasonCode")
        utc_seconds(self.occurred_at, "occurredAt")
        uuid_text(self.correlation_id, "correlationId")


@dataclass(frozen=True, slots=True)
class MappingApprovalAttestation:
    approval_id: str
    organization_id: str
    mapping_id: str
    version: str
    mapping_digest: str
    decision: Decision
    decided_at: str
    approver_subject_id: str
    evidence_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.approval_id, "approvalId")
        uuid_text(self.organization_id, "organizationId")
        stable_id(self.mapping_id, "mappingId")
        semver(self.version)
        digest(self.mapping_digest, "mappingDigest")
        if not isinstance(self.decision, Decision):
            raise ValueError("decision is invalid")
        utc_seconds(self.decided_at, "decidedAt")
        token(self.approver_subject_id, "approverSubjectId")
        digest(self.evidence_digest, "evidenceDigest")


@dataclass(frozen=True, slots=True)
class DomainEvidence:
    organization_id: str
    domain_id: str
    version: str
    state: str
    revision: int
    package_digest: str
    report_digest: str | None
    approval_evidence_digest: str | None
    compatibility_digest: str | None
    reason_code: str
    occurred_at: str
    record_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        stable_id(self.domain_id, "domainId")
        semver(self.version)
        token(self.state, "state")
        if not isinstance(self.revision, int) or isinstance(self.revision, bool) or self.revision < 1:
            raise ValueError("revision must be positive")
        digest(self.package_digest, "packageDigest")
        optional_digest(self.report_digest, "reportDigest")
        optional_digest(self.approval_evidence_digest, "approvalEvidenceDigest")
        optional_digest(self.compatibility_digest, "compatibilityDigest")
        token(self.reason_code, "reasonCode")
        utc_seconds(self.occurred_at, "occurredAt")
        digest(self.record_digest, "recordDigest")
        body = public_dict(self)
        body.pop("schemaVersion")
        body.pop("recordDigest")
        if canonical_digest(body) != self.record_digest:
            raise ValueError("recordDigest does not bind evidence metadata")


@dataclass(frozen=True, slots=True)
class DomainEvent:
    event_id: str
    organization_id: str
    aggregate_id: str
    aggregate_version: int
    event_type: str
    resource_digest: str
    evidence_digest: str
    reason_code: str
    correlation_id: str
    causation_id: str | None
    occurred_at: str
    event_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.event_id, "eventId")
        uuid_text(self.organization_id, "organizationId")
        stable_id(self.aggregate_id, "aggregateId")
        if not isinstance(self.aggregate_version, int) or isinstance(self.aggregate_version, bool) or self.aggregate_version < 1:
            raise ValueError("aggregateVersion must be positive")
        token(self.event_type, "eventType")
        digest(self.resource_digest, "resourceDigest")
        digest(self.evidence_digest, "evidenceDigest")
        token(self.reason_code, "reasonCode")
        uuid_text(self.correlation_id, "correlationId")
        if self.causation_id is not None:
            uuid_text(self.causation_id, "causationId")
        utc_seconds(self.occurred_at, "occurredAt")
        digest(self.event_digest, "eventDigest")
        body = public_dict(self)
        body.pop("schemaVersion")
        body.pop("eventDigest")
        if canonical_digest(body) != self.event_digest:
            raise ValueError("eventDigest does not bind event metadata")


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
