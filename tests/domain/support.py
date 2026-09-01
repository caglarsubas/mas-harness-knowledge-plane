"""Deterministic packet-local domain-service acceptance support."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.common.models import TenantIdentity
from planeon_knowledge.domain.contracts import (
    ApprovalAttestation,
    CompatibilityMode,
    Decision,
    DomainDefinition,
    DomainVersion,
    MappingApprovalAttestation,
    MappingAssertion,
    PolicyPermit,
    SemanticMapping,
    TransformationKind,
    public_dict,
)
from planeon_knowledge.domain.semantic import SemanticMaterial, SemanticValidator
from planeon_knowledge.domain.service import DomainService
from planeon_knowledge.domain.store import InMemoryDomainStore

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures/domain/white-goods"
ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111"
OTHER_ORGANIZATION_ID = "22222222-2222-4222-8222-222222222222"
SUBJECT_ID = "domain-author"
APPROVER_ID = "domain-approver"
DOMAIN_ID = "white-goods.enterprise"
NOW = "2026-01-01T00:00:00Z"
EXPIRES = "2030-01-01T00:00:00Z"


def identifier(label: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"planeon-kn-dom-001:{label}"))


def digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def fixture_bytes(name: str) -> bytes:
    return (FIXTURE / name).read_bytes()


def material(*, valid: bool = True, ontology: bytes | None = None, shapes: bytes | None = None, data: bytes | None = None, **media: str) -> SemanticMaterial:
    return SemanticMaterial(
        ontology=fixture_bytes("ontology.ttl") if ontology is None else ontology,
        shapes=fixture_bytes("shapes.ttl") if shapes is None else shapes,
        data=fixture_bytes("valid.ttl" if valid else "invalid.ttl") if data is None else data,
        ontology_media_type=media.get("ontology_media_type", "text/turtle"),
        shapes_media_type=media.get("shapes_media_type", "text/turtle"),
        data_media_type=media.get("data_media_type", "text/turtle"),
    )


def identity(*, organization_id: str = ORGANIZATION_ID, subject_id: str = SUBJECT_ID) -> TenantIdentity:
    return TenantIdentity(organization_id, subject_id, canonical_digest({"organizationId": organization_id, "subjectId": subject_id}))


def permit(caller: TenantIdentity, action: str, resource_digest: str, *, allowed: bool = True, expires_at: str = EXPIRES) -> PolicyPermit:
    return PolicyPermit(caller.organization_id, caller.subject_id, action, resource_digest, allowed, expires_at, identifier(f"permit:{caller.organization_id}:{caller.subject_id}:{action}:{resource_digest}:{allowed}:{expires_at}"))


def definition(*, mode: CompatibilityMode = CompatibilityMode.BACKWARD, organization_id: str = ORGANIZATION_ID, creator: str = SUBJECT_ID) -> DomainDefinition:
    return DomainDefinition(
        organization_id,
        DOMAIN_ID,
        "White goods enterprise quality",
        "en",
        ("en", "tr"),
        ("business-owner",),
        ("data-owner",),
        mode,
        NOW,
        creator,
    )


def version(version_text: str = "1.0.0", *, semantic_material: SemanticMaterial | None = None, organization_id: str = ORGANIZATION_ID, creator: str = SUBJECT_ID) -> DomainVersion:
    supplied = semantic_material or material()
    ontology_digest = digest_bytes(supplied.ontology)
    shapes_digest = digest_bytes(supplied.shapes)
    package_digest = canonical_digest({"ontologyDigest": ontology_digest, "shapesDigest": shapes_digest, "version": version_text})
    return DomainVersion(
        organization_id,
        DOMAIN_ID,
        version_text,
        package_digest,
        ontology_digest,
        shapes_digest,
        canonical_digest([]),
        canonical_digest({"businessOwners": ["business-owner"], "dataOwners": ["data-owner"]}),
        NOW,
        creator,
    )


class DeterministicIds:
    def __init__(self) -> None:
        self.index = 0

    def __call__(self) -> str:
        self.index += 1
        return identifier(f"event:{self.index}")


def service(*, materials: dict[str, SemanticMaterial] | None = None, clock=None) -> DomainService:
    supplied = materials or {"1.0.0": material()}

    def provider(candidate: DomainVersion) -> SemanticMaterial:
        return supplied[candidate.version]

    validator = SemanticValidator() if clock is None else SemanticValidator(clock=clock)
    return DomainService(store=InMemoryDomainStore(), validator=validator, material_provider=provider, now=lambda: NOW, new_id=DeterministicIds())


def create_domain(target: DomainService, caller: TenantIdentity, *, mode: CompatibilityMode = CompatibilityMode.BACKWARD) -> DomainDefinition:
    value = definition(mode=mode, organization_id=caller.organization_id, creator=caller.subject_id)
    target.create_domain(caller, permit(caller, "knowledge.domain.create", canonical_digest(public_dict(value))), value, idempotency_key="create-domain", correlation_id=identifier("correlation:create-domain"))
    return value


def create_and_validate_version(target: DomainService, caller: TenantIdentity, candidate: DomainVersion, *, key_suffix: str = ""):
    created = target.create_version(caller, permit(caller, "knowledge.domain.version.create", candidate.resource_digest), candidate, idempotency_key=f"create-version{key_suffix}", correlation_id=identifier(f"correlation:create-version{key_suffix}"))
    report = target.validate_version(caller, permit(caller, "knowledge.domain.version.validate", candidate.resource_digest), candidate.domain_id, candidate.version, expected_revision=created.revision, idempotency_key=f"validate-version{key_suffix}", correlation_id=identifier(f"correlation:validate-version{key_suffix}"))
    return created, report


def approve_and_publish(target: DomainService, caller: TenantIdentity, candidate: DomainVersion, *, expected_revision: int = 3, key_suffix: str = ""):
    awaiting = target.request_approval(caller, permit(caller, "knowledge.domain.version.request-approval", candidate.resource_digest), candidate.domain_id, candidate.version, expected_revision=expected_revision, idempotency_key=f"request-approval{key_suffix}", correlation_id=identifier(f"correlation:request-approval{key_suffix}"))
    approval = ApprovalAttestation(
        identifier(f"approval{key_suffix}"), caller.organization_id, candidate.domain_id,
        candidate.version, candidate.package_digest, Decision.APPROVED, NOW,
        APPROVER_ID, canonical_digest({"approval": key_suffix or "initial"}),
    )
    target.record_decision(caller, permit(caller, "knowledge.domain.version.record-decision", candidate.resource_digest), approval, expected_revision=awaiting.revision, idempotency_key=f"record-decision{key_suffix}", correlation_id=identifier(f"correlation:record-decision{key_suffix}"))
    return target.publish(caller, permit(caller, "knowledge.domain.version.publish", candidate.resource_digest), candidate.domain_id, candidate.version, expected_revision=awaiting.revision, idempotency_key=f"publish{key_suffix}", correlation_id=identifier(f"correlation:publish{key_suffix}"))


def mapping(active_domain_digest: str, *, version_text: str = "1.0.0", organization_id: str = ORGANIZATION_ID, creator: str = SUBJECT_ID, unknown_term: bool = False) -> SemanticMapping:
    raw = json.loads((FIXTURE / "mapping.json").read_text(encoding="utf-8"))
    assertions = []
    for index, item in enumerate(raw["assertions"]):
        target = "urn:planeon:white-goods.enterprise:UnknownTerm" if unknown_term and index == 0 else item["targetTerm"]
        assertions.append(MappingAssertion(item["sourceFieldDigest"], target, TransformationKind(item["transformationKind"]), tuple(item["provenanceDigests"])))
    return SemanticMapping(
        organization_id,
        raw["mappingId"],
        version_text,
        active_domain_digest,
        raw["sourceSchemaDigest"],
        tuple(assertions),
        raw["ownersDigest"],
        raw["createdAt"],
        creator,
    )


def mapping_approval(value: SemanticMapping, *, approver: str = APPROVER_ID, decision: Decision = Decision.APPROVED, suffix: str = "") -> MappingApprovalAttestation:
    return MappingApprovalAttestation(
        identifier(f"mapping-approval:{suffix or value.version}"), value.organization_id,
        value.mapping_id, value.version, value.resource_digest, decision, NOW,
        approver, canonical_digest({"mappingApproval": suffix or value.version}),
    )
