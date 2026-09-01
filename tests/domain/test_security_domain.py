from __future__ import annotations

import unittest
from unittest.mock import patch

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.domain.contracts import CompatibilityMode, VersionState, public_dict
from planeon_knowledge.domain.semantic import SemanticFailure, SemanticMaterial, SemanticValidator
from planeon_knowledge.domain.service import DomainFailure

from support import (
    DOMAIN_ID,
    NOW,
    OTHER_ORGANIZATION_ID,
    ORGANIZATION_ID,
    create_domain,
    digest_bytes,
    fixture_bytes,
    identifier,
    identity,
    material,
    permit,
    service,
    version,
)


def validate(supplied: SemanticMaterial):
    candidate = version(semantic_material=supplied)
    return SemanticValidator().validate(
        organization_id=ORGANIZATION_ID,
        domain_id=DOMAIN_ID,
        version=candidate.version,
        package_digest=candidate.package_digest,
        expected_ontology_digest=candidate.ontology_digest,
        expected_shapes_digest=candidate.shapes_digest,
        material=supplied,
        started_at=NOW,
        completed_at=NOW,
    )


class SemanticSecurityTests(unittest.TestCase):
    def assert_reason(self, reason: str, supplied: SemanticMaterial) -> None:
        with self.assertRaises(SemanticFailure) as raised:
            validate(supplied)
        self.assertEqual(raised.exception.reason_code, reason)
        self.assertEqual(str(raised.exception), reason)

    def test_remote_context_and_jsonld_import_are_rejected_before_parser(self) -> None:
        for raw, reason in (
            (b'{"@context":"https://outside.invalid/context","@id":"urn:planeon:white-goods.enterprise:A"}', "JSONLD_REMOTE_CONTEXT_FORBIDDEN"),
            (b'{"@context":{"@import":"https://outside.invalid/context"},"@id":"urn:planeon:white-goods.enterprise:A"}', "JSONLD_IMPORT_FORBIDDEN"),
        ):
            with self.subTest(reason=reason):
                supplied = SemanticMaterial(raw, b"", b"", "application/ld+json", "text/turtle", "text/turtle")
                self.assert_reason(reason, supplied)

    def test_import_foreign_iri_and_executable_literal_are_rejected(self) -> None:
        vectors = (
            (b"@prefix owl: <http://www.w3.org/2002/07/owl#> . <urn:planeon:white-goods.enterprise:A> owl:imports <urn:planeon:white-goods.enterprise:B> .", "OWL_IMPORT_FORBIDDEN"),
            (b"<urn:planeon:white-goods.enterprise:A> <urn:planeon:white-goods.enterprise:p> <https://outside.invalid/resource> .", "IRI_NOT_ALLOWLISTED"),
            (b'@prefix wg: <urn:planeon:white-goods.enterprise:> . wg:A wg:p "value"^^<https://outside.invalid/type> .', "IRI_NOT_ALLOWLISTED"),
            (b'<urn:planeon:white-goods.enterprise:A> <urn:planeon:white-goods.enterprise:p> "javascript:alert(1)" .', "EXECUTABLE_LITERAL_FORBIDDEN"),
        )
        for ontology, reason in vectors:
            with self.subTest(reason=reason):
                self.assert_reason(reason, SemanticMaterial(ontology, b"", b""))

    def test_shacl_sparql_javascript_and_rules_are_rejected(self) -> None:
        prefix = b"@prefix sh: <http://www.w3.org/ns/shacl#> . @prefix wg: <urn:planeon:white-goods.enterprise:> . "
        vectors = (
            prefix + b'wg:S a sh:NodeShape ; sh:sparql [ sh:select "SELECT * WHERE {}" ] .',
            prefix + b'wg:S a sh:NodeShape ; sh:js [ sh:jsFunctionName "unsafe" ] .',
            prefix + b"wg:S a sh:NodeShape ; sh:rule [ a sh:TripleRule ] .",
        )
        for shapes in vectors:
            with self.subTest(shapes=shapes[-30:]):
                self.assert_reason("SHACL_EXECUTABLE_FEATURE_FORBIDDEN", SemanticMaterial(fixture_bytes("ontology.ttl"), shapes, fixture_bytes("valid.ttl")))

    def test_size_media_and_engine_bounds_fail_closed(self) -> None:
        self.assert_reason("DOCUMENT_SIZE_EXCEEDED", SemanticMaterial(b" " * (2 * 1024 * 1024 + 1), b"", b""))
        self.assert_reason("TOTAL_SIZE_EXCEEDED", SemanticMaterial(b" " * (2 * 1024 * 1024), b" " * (2 * 1024 * 1024), b" "))
        with self.assertRaisesRegex(SemanticFailure, "MEDIA_TYPE_UNSUPPORTED"):
            SemanticMaterial(b"", b"", b"", "application/rdf+xml", "text/turtle", "text/turtle")
        with patch.object(SemanticValidator, "engine_versions", return_value={"rdflib": "0", "pyshacl": "0"}):
            self.assert_reason("SEMANTIC_ENGINE_MISMATCH", material())


class ServiceIsolationTests(unittest.TestCase):
    def test_policy_mismatch_expiry_and_tenant_mismatch_reveal_no_state(self) -> None:
        caller = identity()
        target = service()
        create_domain(target, caller)
        candidate = version()
        cases = (
            permit(caller, "knowledge.domain.version.create", candidate.resource_digest, allowed=False),
            permit(caller, "knowledge.domain.version.read", candidate.resource_digest),
            permit(caller, "knowledge.domain.version.create", candidate.resource_digest, expires_at="2025-01-01T00:00:00Z"),
        )
        for index, denied in enumerate(cases):
            with self.subTest(index=index), self.assertRaisesRegex(DomainFailure, "POLICY_DENIED"):
                target.create_version(caller, denied, candidate, idempotency_key=f"denied-{index}", correlation_id=identifier(f"correlation:denied-{index}"))
        other = identity(organization_id=OTHER_ORGANIZATION_ID)
        foreign = version(organization_id=OTHER_ORGANIZATION_ID)
        with self.assertRaisesRegex(DomainFailure, "IDENTITY_MISMATCH"):
            target.create_version(caller, permit(caller, "knowledge.domain.version.create", foreign.resource_digest), foreign, idempotency_key="foreign", correlation_id=identifier("correlation:foreign"))
        self.assertEqual(target.store.snapshot().versions, {})

    def test_provider_failure_is_bounded_invalid_evidence_without_echo(self) -> None:
        caller = identity()
        target = service()
        create_domain(target, caller)
        candidate = version()
        created = target.create_version(caller, permit(caller, "knowledge.domain.version.create", candidate.resource_digest), candidate, idempotency_key="provider-create", correlation_id=identifier("correlation:provider-create"))

        def unavailable(_candidate):
            raise RuntimeError("sensitive path and credential must never echo")

        target.material_provider = unavailable
        report = target.validate_version(caller, permit(caller, "knowledge.domain.version.validate", candidate.resource_digest), DOMAIN_ID, "1.0.0", expected_revision=created.revision, idempotency_key="provider-validate", correlation_id=identifier("correlation:provider-validate"))
        self.assertFalse(report.conforms)
        self.assertEqual(report.findings[0].reason_code, "MATERIAL_PROVIDER_UNAVAILABLE")
        snapshot = target.store.snapshot()
        rendered = str((report, snapshot.evidence, snapshot.events))
        self.assertNotIn("sensitive path", rendered)
        self.assertNotIn("credential", rendered)
        self.assertIs(snapshot.version_revisions[(caller.organization_id, DOMAIN_ID, "1.0.0")][-1].state, VersionState.INVALID)

    def test_idempotency_conflict_and_stale_revision_preserve_state(self) -> None:
        caller = identity()
        target = service()
        definition = create_domain(target, caller, mode=CompatibilityMode.BACKWARD)
        before = target.store.snapshot()
        changed = type(definition)(
            definition.organization_id, definition.domain_id, "Changed name",
            definition.default_language, definition.supported_languages,
            definition.business_owner_ids, definition.data_owner_ids,
            definition.compatibility_mode, definition.created_at,
            definition.created_by_subject_id,
        )
        with self.assertRaisesRegex(DomainFailure, "IDEMPOTENCY_CONFLICT"):
            target.create_domain(caller, permit(caller, "knowledge.domain.create", canonical_digest(public_dict(changed))), changed, idempotency_key="create-domain", correlation_id=identifier("correlation:create-domain-conflict"))
        self.assertEqual(target.store.snapshot(), before)
        candidate = version()
        created = target.create_version(caller, permit(caller, "knowledge.domain.version.create", candidate.resource_digest), candidate, idempotency_key="stale-create", correlation_id=identifier("correlation:stale-create"))
        with self.assertRaisesRegex(DomainFailure, "STALE_REVISION"):
            target.validate_version(caller, permit(caller, "knowledge.domain.version.validate", candidate.resource_digest), DOMAIN_ID, candidate.version, expected_revision=created.revision + 1, idempotency_key="stale-validate", correlation_id=identifier("correlation:stale-validate"))
        self.assertEqual(target.store.snapshot().version_revisions[(caller.organization_id, DOMAIN_ID, candidate.version)], [created])


if __name__ == "__main__":
    unittest.main()
