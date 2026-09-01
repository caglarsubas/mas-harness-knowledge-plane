from __future__ import annotations

import hashlib
import json
import unittest

from rdflib import Graph, Namespace, RDF, URIRef
from rdflib.namespace import OWL

from planeon_knowledge.domain.contracts import MappingState

from support import (
    DOMAIN_ID,
    FIXTURE,
    approve_and_publish,
    create_and_validate_version,
    create_domain,
    identifier,
    identity,
    mapping,
    material,
    permit,
    service,
    version,
)


class WhiteGoodsParityTests(unittest.TestCase):
    def test_required_concepts_and_four_product_families_reach_full_coverage(self) -> None:
        coverage = json.loads((FIXTURE / "coverage.json").read_text(encoding="utf-8"))
        ontology = Graph().parse(FIXTURE / "ontology.ttl", format="turtle")
        data = Graph().parse(FIXTURE / "valid.ttl", format="turtle")
        namespace = Namespace(f"urn:planeon:{DOMAIN_ID}:")
        declared = {str(subject).removeprefix(str(namespace)) for subject in ontology.subjects(RDF.type, OWL.Class) if str(subject).startswith(str(namespace))}
        self.assertEqual(set(coverage["businessConcepts"]), declared)
        self.assertEqual(len(declared), 11)
        families = {str(subject).removeprefix(str(namespace) + "family.") for subject in data.subjects(RDF.type, namespace.ProductFamily)}
        self.assertEqual(families, set(coverage["productFamilies"]))
        self.assertFalse(any(coverage[name] for name in ("publication", "runtime", "assurance", "tenantAcceptance")))

    def test_positive_and_negative_shacl_vectors_are_independent(self) -> None:
        caller = identity()
        target = service(materials={"1.0.0": material(), "2.0.0": material(valid=False)})
        create_domain(target, caller)
        positive = version("1.0.0", semantic_material=material())
        _created, positive_report = create_and_validate_version(target, caller, positive, key_suffix="-positive")
        negative = version("2.0.0", semantic_material=material(valid=False))
        _created, negative_report = create_and_validate_version(target, caller, negative, key_suffix="-negative")
        self.assertTrue(positive_report.conforms)
        self.assertFalse(negative_report.conforms)
        self.assertGreaterEqual(len(negative_report.findings), 2)

    def test_digest_only_mapping_parity_and_unknown_target_denial(self) -> None:
        caller = identity()
        target = service()
        create_domain(target, caller)
        candidate = version()
        create_and_validate_version(target, caller, candidate)
        approve_and_publish(target, caller, candidate)
        valid = mapping(candidate.resource_digest)
        valid_revision = target.validate_mapping(caller, permit(caller, "knowledge.domain.mapping.validate", valid.resource_digest), valid, idempotency_key="white-mapping", correlation_id=identifier("correlation:white-mapping"))
        self.assertIs(valid_revision.state, MappingState.VALID)
        invalid = mapping(candidate.resource_digest, version_text="2.0.0", unknown_term=True)
        invalid_revision = target.validate_mapping(caller, permit(caller, "knowledge.domain.mapping.validate", invalid.resource_digest), invalid, idempotency_key="white-mapping-invalid", correlation_id=identifier("correlation:white-mapping-invalid"))
        self.assertIs(invalid_revision.state, MappingState.INVALID)
        rendered = json.dumps(json.loads((FIXTURE / "mapping.json").read_text(encoding="utf-8")), sort_keys=True)
        for forbidden in ("query", "credential", "formula", "sourceValue", "rawField"):
            self.assertNotIn(forbidden, rendered)

    def test_public_predecessor_locks_are_exact_and_fixture_bytes_are_new(self) -> None:
        locks = json.loads((FIXTURE.parent / "upstream-locks.json").read_text(encoding="utf-8"))
        self.assertEqual(locks["industryPack"]["commit"], "714e311b550798c230d440c869d36f7ad5a857b4")
        self.assertEqual(locks["knowledgeFoundation"]["commit"], "672e73e512113fbf2bb96c222b2ffea7f58e79ed")
        upstream_hashes = {value.removeprefix("sha256:") for value in locks["industryPack"]["artifacts"].values() if isinstance(value, str) and value.startswith("sha256:")}
        local_hashes = {hashlib.sha256(path.read_bytes()).hexdigest() for path in FIXTURE.iterdir() if path.is_file()}
        self.assertTrue(upstream_hashes.isdisjoint(local_hashes))
        self.assertEqual(len(local_hashes), len([path for path in FIXTURE.iterdir() if path.is_file()]))


if __name__ == "__main__":
    unittest.main()
