from __future__ import annotations

import unittest

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.domain.contracts import CompatibilityMode, Decision, MappingState, VersionState
from planeon_knowledge.domain.service import DomainFailure
from planeon_knowledge.domain.store import StoreFailure

from support import (
    APPROVER_ID,
    DOMAIN_ID,
    NOW,
    approve_and_publish,
    create_and_validate_version,
    create_domain,
    identifier,
    identity,
    mapping,
    mapping_approval,
    material,
    permit,
    service,
    version,
)


class DomainLifecycleTests(unittest.TestCase):
    def test_first_strict_publication_is_valid_and_atomic(self) -> None:
        caller = identity()
        target = service()
        create_domain(target, caller, mode=CompatibilityMode.STRICT)
        candidate = version()
        _created, report = create_and_validate_version(target, caller, candidate)
        self.assertTrue(report.conforms)
        active = approve_and_publish(target, caller, candidate)
        self.assertIs(active.state, VersionState.ACTIVE)
        snapshot = target.store.snapshot()
        self.assertEqual(snapshot.active_domains[(caller.organization_id, DOMAIN_ID)], "1.0.0")
        self.assertEqual(len(snapshot.evidence), len(snapshot.events))
        self.assertTrue(all(item.organization_id == caller.organization_id for item in snapshot.evidence))

    def test_validation_replay_does_not_reopen_material_provider(self) -> None:
        caller = identity()
        supplied = material()
        calls = 0
        target = service(materials={"1.0.0": supplied})
        original = target.material_provider

        def counted(candidate):
            nonlocal calls
            calls += 1
            return original(candidate)

        target.material_provider = counted
        create_domain(target, caller)
        candidate = version(semantic_material=supplied)
        created, first = create_and_validate_version(target, caller, candidate)
        second = target.validate_version(
            caller,
            permit(caller, "knowledge.domain.version.validate", candidate.resource_digest),
            DOMAIN_ID,
            candidate.version,
            expected_revision=created.revision,
            idempotency_key="validate-version",
            correlation_id=identifier("correlation:validate-version"),
        )
        self.assertEqual(first, second)
        self.assertEqual(calls, 1)

    def test_commit_failure_leaves_no_partial_activation(self) -> None:
        caller = identity()
        target = service()
        create_domain(target, caller)
        candidate = version()
        create_and_validate_version(target, caller, candidate)
        awaiting = target.request_approval(caller, permit(caller, "knowledge.domain.version.request-approval", candidate.resource_digest), DOMAIN_ID, "1.0.0", expected_revision=3, idempotency_key="approval", correlation_id=identifier("correlation:approval"))
        from planeon_knowledge.domain.contracts import ApprovalAttestation
        approval = ApprovalAttestation(identifier("atomic-approval"), caller.organization_id, DOMAIN_ID, "1.0.0", candidate.package_digest, Decision.APPROVED, NOW, APPROVER_ID, canonical_digest({"approval": "atomic"}))
        target.record_decision(caller, permit(caller, "knowledge.domain.version.record-decision", candidate.resource_digest), approval, expected_revision=awaiting.revision, idempotency_key="decision", correlation_id=identifier("correlation:decision"))
        before = target.store.snapshot()
        target.store.inject_commit_failure()
        with self.assertRaises(StoreFailure):
            target.publish(caller, permit(caller, "knowledge.domain.version.publish", candidate.resource_digest), DOMAIN_ID, "1.0.0", expected_revision=awaiting.revision, idempotency_key="publish-atomic", correlation_id=identifier("correlation:publish-atomic"))
        self.assertEqual(target.store.snapshot(), before)

    def test_identical_supersede_rollback_and_retirement(self) -> None:
        caller = identity()
        supplied = material()
        target = service(materials={"1.0.0": supplied, "2.0.0": supplied})
        create_domain(target, caller, mode=CompatibilityMode.STRICT)
        first = version("1.0.0", semantic_material=supplied)
        create_and_validate_version(target, caller, first, key_suffix="-v1")
        approve_and_publish(target, caller, first, key_suffix="-v1")
        second = version("2.0.0", semantic_material=supplied)
        create_and_validate_version(target, caller, second, key_suffix="-v2")
        approve_and_publish(target, caller, second, key_suffix="-v2")
        state = target.store.snapshot()
        self.assertIs(state.version_revisions[(caller.organization_id, DOMAIN_ID, "1.0.0")][-1].state, VersionState.SUPERSEDED)
        rolled_back = target.rollback(caller, permit(caller, "knowledge.domain.version.rollback", first.resource_digest), DOMAIN_ID, "1.0.0", expected_revision=6, idempotency_key="rollback-v1", correlation_id=identifier("correlation:rollback-v1"))
        self.assertIs(rolled_back.state, VersionState.ACTIVE)
        retired = target.retire_version(caller, permit(caller, "knowledge.domain.version.retire", second.resource_digest), DOMAIN_ID, "2.0.0", expected_revision=6, idempotency_key="retire-v2", correlation_id=identifier("correlation:retire-v2"))
        self.assertIs(retired.state, VersionState.RETIRED)
        with self.assertRaisesRegex(DomainFailure, "TRANSITION_FORBIDDEN"):
            target.rollback(caller, permit(caller, "knowledge.domain.version.rollback", second.resource_digest), DOMAIN_ID, "2.0.0", expected_revision=retired.revision, idempotency_key="rollback-retired", correlation_id=identifier("correlation:rollback-retired"))

    def test_breaking_publication_preserves_prior_pointer(self) -> None:
        caller = identity()
        first_material = material()
        breaking_ontology = first_material.ontology.replace(b"wg:BusinessObjective a owl:Class .", b"")
        second_material = material(ontology=breaking_ontology)
        target = service(materials={"1.0.0": first_material, "2.0.0": second_material})
        create_domain(target, caller)
        first = version("1.0.0", semantic_material=first_material)
        create_and_validate_version(target, caller, first, key_suffix="-base")
        approve_and_publish(target, caller, first, key_suffix="-base")
        second = version("2.0.0", semantic_material=second_material)
        create_and_validate_version(target, caller, second, key_suffix="-breaking")
        awaiting = target.request_approval(caller, permit(caller, "knowledge.domain.version.request-approval", second.resource_digest), DOMAIN_ID, "2.0.0", expected_revision=3, idempotency_key="approval-breaking", correlation_id=identifier("correlation:approval-breaking"))
        from planeon_knowledge.domain.contracts import ApprovalAttestation
        approval = ApprovalAttestation(identifier("approval-breaking"), caller.organization_id, DOMAIN_ID, "2.0.0", second.package_digest, Decision.APPROVED, NOW, APPROVER_ID, canonical_digest({"approval": "breaking"}))
        target.record_decision(caller, permit(caller, "knowledge.domain.version.record-decision", second.resource_digest), approval, expected_revision=awaiting.revision, idempotency_key="decision-breaking", correlation_id=identifier("correlation:decision-breaking"))
        before = target.store.snapshot()
        with self.assertRaisesRegex(DomainFailure, "COMPATIBILITY_BLOCKED"):
            target.publish(caller, permit(caller, "knowledge.domain.version.publish", second.resource_digest), DOMAIN_ID, "2.0.0", expected_revision=awaiting.revision, idempotency_key="publish-breaking", correlation_id=identifier("correlation:publish-breaking"))
        after = target.store.snapshot()
        self.assertEqual(after.active_domains, before.active_domains)
        self.assertEqual(after.evidence, before.evidence)
        self.assertEqual(after.events, before.events)


class MappingLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.caller = identity()
        self.supplied = material()
        self.target = service(materials={"1.0.0": self.supplied, "2.0.0": self.supplied})
        create_domain(self.target, self.caller)
        self.first = version("1.0.0", semantic_material=self.supplied)
        create_and_validate_version(self.target, self.caller, self.first, key_suffix="-mapping-domain")
        approve_and_publish(self.target, self.caller, self.first, key_suffix="-mapping-domain")

    def test_mapping_approval_activation_and_domain_supersede(self) -> None:
        value = mapping(self.first.resource_digest)
        validated = self.target.validate_mapping(self.caller, permit(self.caller, "knowledge.domain.mapping.validate", value.resource_digest), value, idempotency_key="mapping-validate", correlation_id=identifier("correlation:mapping-validate"))
        self.assertIs(validated.state, MappingState.VALID)
        awaiting = self.target.request_mapping_approval(self.caller, permit(self.caller, "knowledge.domain.mapping.request-approval", value.resource_digest), value.mapping_id, value.version, expected_revision=3, idempotency_key="mapping-request", correlation_id=identifier("correlation:mapping-request"))
        approval = mapping_approval(value)
        self.target.record_mapping_decision(self.caller, permit(self.caller, "knowledge.domain.mapping.record-decision", value.resource_digest), approval, expected_revision=awaiting.revision, idempotency_key="mapping-decision", correlation_id=identifier("correlation:mapping-decision"))
        active = self.target.activate_mapping(self.caller, permit(self.caller, "knowledge.domain.mapping.activate", value.resource_digest), value.mapping_id, value.version, expected_revision=awaiting.revision, idempotency_key="mapping-activate", correlation_id=identifier("correlation:mapping-activate"))
        self.assertIs(active.state, MappingState.ACTIVE)
        second = version("2.0.0", semantic_material=self.supplied)
        create_and_validate_version(self.target, self.caller, second, key_suffix="-mapping-v2")
        approve_and_publish(self.target, self.caller, second, key_suffix="-mapping-v2")
        state = self.target.store.snapshot()
        self.assertNotIn((self.caller.organization_id, value.mapping_id), state.active_mappings)
        self.assertIs(state.mapping_revisions[(self.caller.organization_id, value.mapping_id, value.version)][-1].state, MappingState.SUPERSEDED)

    def test_mapping_missing_term_and_self_approval_deny(self) -> None:
        invalid = mapping(self.first.resource_digest, unknown_term=True)
        revision = self.target.validate_mapping(self.caller, permit(self.caller, "knowledge.domain.mapping.validate", invalid.resource_digest), invalid, idempotency_key="mapping-invalid", correlation_id=identifier("correlation:mapping-invalid"))
        self.assertIs(revision.state, MappingState.INVALID)
        valid = mapping(self.first.resource_digest, version_text="2.0.0")
        self.target.validate_mapping(self.caller, permit(self.caller, "knowledge.domain.mapping.validate", valid.resource_digest), valid, idempotency_key="mapping-valid-2", correlation_id=identifier("correlation:mapping-valid-2"))
        awaiting = self.target.request_mapping_approval(self.caller, permit(self.caller, "knowledge.domain.mapping.request-approval", valid.resource_digest), valid.mapping_id, valid.version, expected_revision=3, idempotency_key="mapping-request-2", correlation_id=identifier("correlation:mapping-request-2"))
        self_approval = mapping_approval(valid, approver=self.caller.subject_id, suffix="self")
        with self.assertRaisesRegex(DomainFailure, "APPROVAL_MISMATCH"):
            self.target.record_mapping_decision(self.caller, permit(self.caller, "knowledge.domain.mapping.record-decision", valid.resource_digest), self_approval, expected_revision=awaiting.revision, idempotency_key="mapping-self-decision", correlation_id=identifier("correlation:mapping-self-decision"))


if __name__ == "__main__":
    unittest.main()
