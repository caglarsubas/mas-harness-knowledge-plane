from __future__ import annotations

import json
import unittest
from pathlib import Path

from planeon_knowledge.ingestion.contracts import ConnectorKind
from planeon_knowledge.ingestion.readiness import ReadinessDecision, evaluate_readiness

from tests.readiness.support import EVALUATED_AT, observation_for, policy_for, staged

ROOT = Path(__file__).resolve().parents[2]


class IndependentReadinessParityTests(unittest.TestCase):
    def test_independent_vectors_have_locked_decisions_reasons_and_gate_order(self) -> None:
        document = json.loads((ROOT / "fixtures/readiness/vectors.json").read_text(encoding="utf-8"))
        self.assertEqual(document["authorship"], "INDEPENDENT_SYNTHETIC")
        self.assertEqual(len(document["vectors"]), 8)
        self.assertEqual({item["connectorKind"] for item in document["vectors"]}, {kind.value for kind in ConnectorKind})
        for vector in document["vectors"]:
            with self.subTest(vector=vector["id"]):
                batch = staged(ConnectorKind(vector["connectorKind"]))[-1]
                observation = observation_for(
                    batch,
                    expected_observation_count=vector["expectedCount"],
                    observed_record_count=vector["observedCount"],
                    nonnull_required_field_count=vector["nonnullCount"],
                    duplicate_observation_count=vector["duplicateCount"],
                    classified_observation_count=vector["classifiedCount"],
                    provenanced_observation_count=vector["provenancedCount"],
                    latest_source_observation_at=vector["latestObservationAt"],
                )
                findings, assessment = evaluate_readiness(
                    policy=policy_for(batch),
                    observation=observation,
                    batch=batch,
                    evaluated_at=EVALUATED_AT,
                    parity_mode=vector["observedCount"] != batch.record_count,
                )
                self.assertEqual(assessment.decision.value, vector["decision"])
                self.assertEqual(assessment.overall_status, "READY" if vector["decision"] == "PASS" else "BLOCKED")
                self.assertEqual(
                    tuple(item.gate_id for item in assessment.gate_results),
                    (
                        "business.owner",
                        "business.outcome",
                        "data.owner",
                        "data.quality",
                        "data.completeness",
                        "data.freshness",
                        "data.provenance",
                        "data.classification",
                        "integration.readiness",
                        "autonomy.boundary",
                    ),
                )
                if vector["reasonCode"] is not None:
                    self.assertIn(vector["reasonCode"], {item.reason_code for item in findings})
                if vector["id"] == "missing-file":
                    self.assertEqual(len(findings), 1)
                    self.assertIs(findings[0].decision, ReadinessDecision.FAIL)
                    self.assertEqual(findings[0].observed_value, None)

    def test_locked_public_boundary_is_metadata_only_and_not_approval(self) -> None:
        locks = json.loads((ROOT / "fixtures/readiness/upstream-locks.json").read_text(encoding="utf-8"))
        self.assertEqual(locks["knowledgePlane"]["commit"], "dfa67f06b307e7b47a790cfdb0bc5e63fb13eec9")
        self.assertEqual(locks["contracts"]["dataReadinessAssessmentSha256"], "ffe003a1a7ec0773f49d8f394ac3dd6281114bd4335ff05c87d223412faf92a5")
        self.assertEqual(locks["industryPack"]["warnFreshnessSha256"], "0d57ce6f10cd4040d08861ea9293ee98d25c4e740daed868ad579019b7b24fff")
        evidence = json.loads((ROOT / "fixtures/readiness/evidence-status.json").read_text(encoding="utf-8"))
        self.assertEqual(evidence["ownerApproval"], "PENDING_OWNER_AUTHORITY")
        self.assertEqual(evidence["tenantAcceptance"], "PENDING_TENANT_AUTHORITY")
        for axis in ("postgresql", "sourceConnectivity", "deployment", "runtime", "assurance"):
            self.assertEqual(evidence[axis], "NOT_RUN_ENV_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
