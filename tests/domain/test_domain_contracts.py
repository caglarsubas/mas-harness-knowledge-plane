from __future__ import annotations

import unittest

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.domain.contracts import (
    CompatibilityState,
    MappingAssertion,
    SemanticMapping,
    TransformationKind,
    public_dict,
)
from planeon_knowledge.domain.semantic import SemanticFailure, SemanticMaterial, SemanticValidator, classify_compatibility

from support import DOMAIN_ID, NOW, ORGANIZATION_ID, digest_bytes, fixture_bytes, material, mapping, version


class ContractTests(unittest.TestCase):
    def test_public_mapping_contract_is_closed_and_camel_cased(self) -> None:
        value = mapping("sha256:" + "7" * 64)
        body = public_dict(value)
        self.assertEqual(body["schemaVersion"], "planeon.knowledge.domain/v1")
        self.assertEqual(body["assertions"][0]["transformationKind"], "DIRECT")
        self.assertIn("targetTerm", body["assertions"][0])
        self.assertNotIn("target_term", str(body))

    def test_assertion_requires_sorted_nonempty_digest_provenance(self) -> None:
        with self.assertRaisesRegex(ValueError, "sorted and unique"):
            MappingAssertion(
                "sha256:" + "1" * 64,
                f"urn:planeon:{DOMAIN_ID}:CriticalToQuality",
                TransformationKind.DIRECT,
                ("sha256:" + "2" * 64, "sha256:" + "2" * 64),
            )
        with self.assertRaisesRegex(ValueError, "cardinality"):
            MappingAssertion("sha256:" + "1" * 64, f"urn:planeon:{DOMAIN_ID}:CriticalToQuality", TransformationKind.DIRECT, ())

    def test_mapping_rejects_raw_or_foreign_target_identifiers(self) -> None:
        with self.assertRaisesRegex(ValueError, "closed IRI"):
            MappingAssertion("sha256:" + "1" * 64, "customer.email", TransformationKind.DIRECT, ("sha256:" + "2" * 64,))
        with self.assertRaisesRegex(ValueError, "sorted and unique"):
            assertion = MappingAssertion("sha256:" + "1" * 64, f"urn:planeon:{DOMAIN_ID}:CriticalToQuality", TransformationKind.DIRECT, ("sha256:" + "2" * 64,))
            SemanticMapping(ORGANIZATION_ID, "white-goods.mapping", "1.0.0", "sha256:" + "3" * 64, "sha256:" + "4" * 64, (assertion, assertion), "sha256:" + "5" * 64, NOW, "creator")


class SemanticValidatorTests(unittest.TestCase):
    def validate(self, supplied: SemanticMaterial):
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

    def test_valid_graph_is_deterministic_and_report_contains_only_digests(self) -> None:
        first = self.validate(material())
        second = self.validate(material())
        self.assertTrue(first.report.conforms)
        self.assertEqual(first, second)
        self.assertEqual(len(first.terms), 18)
        rendered = str(public_dict(first.report))
        self.assertNotIn("seal-integrity", rendered)
        self.assertNotIn("inspection-record", rendered)

    def test_invalid_graph_returns_sorted_digest_only_findings(self) -> None:
        snapshot = self.validate(material(valid=False))
        self.assertFalse(snapshot.report.conforms)
        self.assertGreaterEqual(len(snapshot.report.findings), 2)
        self.assertEqual(snapshot.report.findings, tuple(sorted(snapshot.report.findings, key=lambda item: (item.reason_code, item.focus_digest, item.path_digest, item.constraint_component))))
        rendered = str(public_dict(snapshot.report))
        self.assertNotIn("owner-missing", rendered)
        self.assertNotIn("family-missing", rendered)

    def test_inline_context_jsonld_is_local_and_supported(self) -> None:
        ontology = b'{"@context":{"wg":"urn:planeon:white-goods.enterprise:","owl":"http://www.w3.org/2002/07/owl#"},"@id":"wg:BusinessObjective","@type":"owl:Class"}'
        supplied = SemanticMaterial(ontology, b"", b"", "application/ld+json", "text/turtle", "text/turtle")
        snapshot = self.validate(supplied)
        self.assertTrue(snapshot.report.conforms)
        self.assertEqual(snapshot.terms, frozenset({"urn:planeon:white-goods.enterprise:BusinessObjective"}))

    def test_raw_material_digest_mismatch_is_rejected(self) -> None:
        supplied = material()
        candidate = version(semantic_material=supplied)
        with self.assertRaisesRegex(SemanticFailure, "MATERIAL_DIGEST_MISMATCH"):
            SemanticValidator().validate(
                organization_id=ORGANIZATION_ID, domain_id=DOMAIN_ID,
                version=candidate.version, package_digest=candidate.package_digest,
                expected_ontology_digest="sha256:" + "0" * 64,
                expected_shapes_digest=candidate.shapes_digest, material=supplied,
                started_at=NOW, completed_at=NOW,
            )

    def test_compatibility_classifier_is_closed(self) -> None:
        a = (("urn:planeon:white-goods.enterprise:A", canonical_digest(["a"])),)
        b = a + (("urn:planeon:white-goods.enterprise:B", canonical_digest(["b"])),)
        changed = ((a[0][0], canonical_digest(["changed"])),)
        self.assertIs(classify_compatibility(a, a).state, CompatibilityState.IDENTICAL)
        self.assertIs(classify_compatibility(a, b).state, CompatibilityState.BACKWARD_COMPATIBLE)
        self.assertIs(classify_compatibility(a, changed).state, CompatibilityState.BREAKING)

    def test_deadline_is_injected_and_fail_closed(self) -> None:
        ticks = iter((0.0, 31.0))
        validator = SemanticValidator(clock=lambda: next(ticks))
        supplied = material()
        candidate = version(semantic_material=supplied)
        with self.assertRaisesRegex(SemanticFailure, "VALIDATION_DEADLINE_EXCEEDED"):
            validator.validate(
                organization_id=ORGANIZATION_ID, domain_id=DOMAIN_ID,
                version=candidate.version, package_digest=candidate.package_digest,
                expected_ontology_digest=digest_bytes(fixture_bytes("ontology.ttl")),
                expected_shapes_digest=digest_bytes(fixture_bytes("shapes.ttl")),
                material=supplied, started_at=NOW, completed_at=NOW,
            )


if __name__ == "__main__":
    unittest.main()
