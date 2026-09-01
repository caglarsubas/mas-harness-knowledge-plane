from __future__ import annotations

import json
import unittest

from planeon_knowledge.ingestion.contracts import ConnectorKind
from planeon_knowledge.ingestion.decoder import decode

from tests.connectors.support import (
    FILE_BY_KIND,
    MEDIA_BY_KIND,
    FIXTURE,
    MemoryStagingPort,
    acquire_sample_lease,
    create_and_validate,
    fixture_bytes,
    identity,
    load_manifest,
    sample,
    service,
)


class CleanRoomConnectorParityTests(unittest.TestCase):
    def test_four_independent_white_goods_vectors_decode_and_stage_deterministically(self) -> None:
        manifest = load_manifest()
        self.assertEqual(manifest["authorship"], "INDEPENDENT_SYNTHETIC")
        self.assertEqual(len(manifest["vectors"]), 4)
        expected_kinds = {kind.value for kind in ConnectorKind}
        self.assertEqual({item["connectorKind"] for item in manifest["vectors"]}, expected_kinds)

        for vector in manifest["vectors"]:
            kind = ConnectorKind(vector["connectorKind"])
            with self.subTest(kind=kind):
                payload = fixture_bytes(kind)
                decoded = decode(payload, MEDIA_BY_KIND[kind], max_records=100)
                self.assertEqual(len(decoded), vector["recordCount"])
                self.assertEqual(vector["file"], FILE_BY_KIND[kind])
                self.assertEqual(len({item.record.schema_digest for item in decoded}), 1)

                results = []
                for _ in range(2):
                    caller = identity()
                    target = service()
                    candidate, binding_value, validated = create_and_validate(target, caller, kind)
                    lease = acquire_sample_lease(target, caller, candidate)
                    staging = MemoryStagingPort()
                    batch = sample(target, caller, candidate, binding_value, validated.revision, lease, staging=staging)
                    snapshot = target.store.snapshot()
                    results.append((batch, snapshot.batch_records[(caller.organization_id, batch.batch_id)], snapshot.checkpoint_candidates[(caller.organization_id, batch.batch_id)]))
                    self.assertEqual(len(staging.prepared), 1)
                self.assertEqual(results[0], results[1])

    def test_fixtures_contain_no_readiness_or_predecessor_payload_claims(self) -> None:
        rendered = "\n".join(path.read_text(encoding="utf-8") for path in sorted(FIXTURE.iterdir()) if path.is_file()).casefold()
        for forbidden in (
            "ready_for_approval",
            "tenant_accepted",
            "copy_authorized",
            "data-source-harness",
            "committed_batch",
        ):
            self.assertNotIn(forbidden, rendered)

    def test_public_lock_and_evidence_vectors_are_closed(self) -> None:
        locks = json.loads((FIXTURE.parent / "upstream-locks.json").read_text(encoding="utf-8"))
        self.assertEqual(locks["knowledgePlane"]["commit"], "187a3d6234d7e53392acc6984221fa314d40cf93")
        self.assertEqual(locks["contracts"]["commit"], "2146278a95344cd2a8e22596b2f315b46edffc88")
        self.assertEqual(locks["industryPack"]["commit"], "a4d3df9b169e95c285e22a2fdb2b4c9d711230e2")
        evidence = json.loads((FIXTURE.parent / "evidence-status.json").read_text(encoding="utf-8"))
        for axis in ("postgresql", "sourceConnectivity", "deployment", "runtime", "assurance"):
            self.assertEqual(evidence[axis], "NOT_RUN_ENV_UNAVAILABLE")
        self.assertEqual(evidence["tenantAcceptance"], "PENDING_TENANT_AUTHORITY")
        self.assertNotEqual(evidence["source"], "ACCEPTED")


if __name__ == "__main__":
    unittest.main()
