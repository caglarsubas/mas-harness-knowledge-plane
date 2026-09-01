from __future__ import annotations

import unittest
from dataclasses import replace
from decimal import Decimal

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.ingestion.contracts import ConnectorKind, public_dict
from planeon_knowledge.ingestion.coverage import CoverageFailure, canonical_decimal, decimal_value
from planeon_knowledge.ingestion.provenance import (
    ProvenanceEdge,
    ProvenanceFailure,
    ProvenanceNode,
    build_graph,
)
from planeon_knowledge.ingestion.readiness import (
    GateStatus,
    ReadinessDecision,
    ReadinessFailure,
    ReadinessThresholds,
    evaluate_readiness,
)
from planeon_knowledge.ingestion.service import IngestionFailure, batch_scope_digest

from tests.connectors.support import identifier, identity, permit
from tests.readiness.support import (
    EVALUATED_AT,
    assess_and_complete,
    changed_observation,
    observation_for,
    policy_for,
    prerequisite_gates,
    staged,
)


class ReadinessContractTests(unittest.TestCase):
    def test_decimal_contract_is_canonical_finite_bounded_and_ordered(self) -> None:
        self.assertEqual(canonical_decimal(Decimal("0.750000")), "0.75")
        for invalid in ("01", "1.0", "NaN", "Infinity", "-0.1", "0.1234567"):
            with self.subTest(value=invalid), self.assertRaises(CoverageFailure):
                decimal_value(invalid, "ratio", maximum=Decimal(1))
        with self.assertRaisesRegex(ReadinessFailure, "THRESHOLD_ORDER_INVALID"):
            ReadinessThresholds("0.7", "0.8", "30", "120", "0.01", "0.05", "0.95", "0.8", "0.95", "0.8").parsed()

    def test_measurement_digest_counts_and_future_time_fail_closed(self) -> None:
        batch = staged()[-1]
        observation = observation_for(batch)
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(observation, observation_digest="sha256:" + "0" * 64)
        with self.assertRaisesRegex(ValueError, "exceeds observations"):
            changed_observation(observation, classified_observation_count=batch.record_count + 1)
        future = changed_observation(observation, latest_source_observation_at="2026-01-01T00:01:00Z")
        with self.assertRaisesRegex(ReadinessFailure, "FUTURE_OBSERVATION"):
            evaluate_readiness(policy=policy_for(batch), observation=future, batch=batch, evaluated_at=EVALUATED_AT)

    def test_public_assessment_and_evidence_are_exact_closed_projections(self) -> None:
        caller, _clock, _ingestion, readiness, _source, _binding, _validated, _lease, batch = staged()
        _work, _claim, assessment = assess_and_complete(caller, readiness, batch)
        document = assessment.public_document()
        self.assertEqual(set(document), {"apiVersion", "kind", "metadata", "spec"})
        self.assertEqual(document["kind"], "DataReadinessAssessment")
        self.assertEqual(set(document["spec"]), {"questionnaireSessionId", "overallStatus", "gateResults", "missingGateIds"})
        snapshot = readiness.store.snapshot()
        graph_id = snapshot.assessment_graph_ids[(caller.organization_id, assessment.assessment_id)]
        evidence_id = snapshot.source_readiness_revisions[(caller.organization_id, batch.source_id)][-1].evidence_id
        graph = snapshot.provenance_graphs[(caller.organization_id, graph_id)]
        evidence = snapshot.readiness_evidence[(caller.organization_id, evidence_id)]
        public = evidence.public_document()
        self.assertEqual(public["spec"]["axis"], "SOURCE")
        self.assertEqual(public["spec"]["recordState"], "VERIFIED")
        self.assertEqual(public["spec"]["producerAuthority"], "PLATFORM")
        self.assertIs(public["spec"]["campaignGenerated"], False)
        self.assertEqual(public["spec"]["provenanceDigest"], graph.graph_digest)
        self.assertNotIn("tenantAcceptance", str(public))

    def test_findings_are_sorted_digest_bound_and_warning_blocks_readiness(self) -> None:
        batch = staged(ConnectorKind.EVENT)[-1]
        observation = observation_for(batch, latest_source_observation_at="2025-12-31T23:00:00Z")
        findings, assessment = evaluate_readiness(
            policy=policy_for(batch), observation=observation, batch=batch, evaluated_at=EVALUATED_AT
        )
        self.assertIs(assessment.decision, ReadinessDecision.WARN)
        self.assertEqual(assessment.overall_status, "BLOCKED")
        self.assertEqual(tuple(item.metric_id for item in findings), tuple(sorted(item.metric_id for item in findings)))
        self.assertIn("data.freshness", assessment.missing_gate_ids)
        with self.assertRaisesRegex(ValueError, "finding digest mismatch"):
            replace(findings[0], finding_digest="sha256:" + "1" * 64)

    def test_missing_prerequisite_blocks_even_when_metrics_pass(self) -> None:
        batch = staged()[-1]
        observation = observation_for(batch, prerequisite_gates=prerequisite_gates(status=GateStatus.BLOCKED))
        _findings, assessment = evaluate_readiness(
            policy=policy_for(batch), observation=observation, batch=batch, evaluated_at=EVALUATED_AT
        )
        self.assertIs(assessment.decision, ReadinessDecision.FAIL)
        self.assertEqual(assessment.missing_gate_ids, ("business.outcome", "business.owner", "data.owner"))

    def test_illustrative_policy_is_parity_only(self) -> None:
        batch = staged()[-1]
        policy = policy_for(batch, illustrative=True)
        observation = observation_for(batch)
        with self.assertRaisesRegex(ReadinessFailure, "POLICY_NOT_TENANT_APPROVED"):
            evaluate_readiness(policy=policy, observation=observation, batch=batch, evaluated_at=EVALUATED_AT)
        _findings, assessment = evaluate_readiness(
            policy=policy,
            observation=observation,
            batch=batch,
            evaluated_at=EVALUATED_AT,
            parity_mode=True,
        )
        self.assertIs(assessment.decision, ReadinessDecision.PASS)

    def test_provenance_is_bounded_sorted_known_and_acyclic(self) -> None:
        digest_a = canonical_digest({"node": "a"})
        digest_b = canonical_digest({"node": "b"})
        graph = build_graph(
            organization_id=identity().organization_id,
            graph_id="provenance.contract-test",
            purpose="ASSESSMENT",
            nodes=(
                ProvenanceNode("source.version", "data.source-version", digest_a),
                ProvenanceNode("batch.staged", "data.staged-batch", digest_b),
            ),
            edges=(ProvenanceEdge("source.version", "batch.staged", "source.produces"),),
            created_at=EVALUATED_AT,
        )
        self.assertEqual(graph.nodes[0].node_id, "batch.staged")
        with self.assertRaisesRegex(ValueError, "kind is invalid"):
            ProvenanceNode("unknown.node", "unknown.kind", digest_a)
        with self.assertRaisesRegex(ProvenanceFailure, "PROVENANCE_CYCLE"):
            build_graph(
                organization_id=identity().organization_id,
                graph_id="provenance.cycle-test",
                purpose="ASSESSMENT",
                nodes=graph.nodes,
                edges=(
                    ProvenanceEdge("source.version", "batch.staged", "source.produces"),
                    ProvenanceEdge("batch.staged", "source.version", "batch.promotes"),
                ),
                created_at=EVALUATED_AT,
            )

    def test_all_new_batches_and_checkpoints_bind_the_exact_partition(self) -> None:
        for kind in ConnectorKind:
            with self.subTest(kind=kind.value):
                *_, readiness, _source, _binding, _validated, lease, batch = staged(kind)
                checkpoint = readiness.store.snapshot().checkpoint_candidates[(batch.organization_id, batch.batch_id)]
                self.assertEqual(batch.partition, lease.partition)
                self.assertEqual(checkpoint.partition, lease.partition)
                self.assertEqual(public_dict(batch)["partition"], "partition-0")
                with self.assertRaisesRegex(ValueError, "staged batch digest mismatch"):
                    replace(batch, partition="partition-1")

    def test_legacy_unbound_batch_remains_readable_but_cannot_assess(self) -> None:
        caller, _clock, ingestion, readiness, _source, _binding, _validated, _lease, batch = staged()
        legacy = replace(batch, partition=None)
        readiness.store.transact(lambda state: state.batches.__setitem__((caller.organization_id, batch.batch_id), legacy))
        readable = ingestion.get_staged_batch(
            caller,
            permit(caller, "knowledge.ingestion.staged-batch.read", batch_scope_digest(caller.organization_id, batch.batch_id)),
            batch.batch_id,
        )
        self.assertIsNone(readable.partition)
        with self.assertRaisesRegex(IngestionFailure, "BATCH_PARTITION_UNBOUND"):
            readiness.request_assessment(
                caller,
                permit(caller, "knowledge.ingestion.staged-batch.assess", batch_scope_digest(caller.organization_id, batch.batch_id)),
                batch.batch_id,
                policy=policy_for(batch),
                observation=observation_for(batch),
                idempotency_key="legacy-assess",
                correlation_id=identifier("correlation:legacy-assess"),
            )


if __name__ == "__main__":
    unittest.main()
