from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import tomllib
import unittest
from pathlib import Path

from planeon_knowledge.ingestion.asgi import (
    IngestionAsgiApplication,
    ReadinessDependencyBundle,
)
from planeon_knowledge.ingestion.service import work_scope_digest

from tests.connectors.support import identifier, permit
from tests.connectors.test_contract_api import request
from tests.readiness.support import (
    approval_for,
    observation_for,
    policy_for,
    staged,
)

ROOT = Path(__file__).resolve().parents[2]
BASE = "dfa67f06b307e7b47a790cfdb0bc5e63fb13eec9"


class ReadinessApiTests(unittest.TestCase):
    def setUp(self) -> None:
        (
            self.caller,
            self.clock,
            self.ingestion,
            self.readiness,
            self.source,
            self.binding,
            self.validated,
            self.lease,
            self.batch,
        ) = staged()
        self.allowed = True
        self.dependency_calls = 0
        self.dependency_failure = False
        self.approval = None

        def permit_provider(caller, action, resource):
            return permit(caller, action, resource, allowed=self.allowed)

        def connector_dependencies(*_args):
            raise AssertionError("readiness routes must not request connector dependencies")

        def readiness_dependencies(_caller, resource_id, action):
            self.dependency_calls += 1
            if self.dependency_failure:
                raise RuntimeError("private-policy-endpoint-detail")
            if action == "ASSESS":
                self.assertEqual(resource_id, self.batch.batch_id)
                return ReadinessDependencyBundle(
                    policy=policy_for(self.batch),
                    observation=observation_for(self.batch),
                )
            if action == "COMMIT":
                return ReadinessDependencyBundle(approval=self.approval)
            raise AssertionError("unexpected readiness dependency action")

        self.application = IngestionAsgiApplication(
            self.ingestion,
            lambda _scope: self.caller,
            permit_provider,
            connector_dependencies,
            self.readiness,
            readiness_dependencies,
        )

    @staticmethod
    def headers(key: str | None = None, revision: int | None = None):
        values = [(b"x-correlation-id", identifier(f"readiness-api:{key or 'read'}:{revision or 0}").encode("ascii"))]
        if key is not None:
            values.append((b"idempotency-key", key.encode("ascii")))
        if revision is not None:
            values.append((b"if-match", str(revision).encode("ascii")))
        return values

    def test_controller_lifecycle_uses_injected_dependencies_and_exact_public_routes(self) -> None:
        status, work = request(
            self.application,
            "POST",
            f"/knowledge/v1/staged-batches/{self.batch.batch_id}:assess",
            {},
            headers=self.headers("api-assess"),
        )
        self.assertEqual(status, 202)
        self.assertEqual(work["state"], "PENDING")
        claim = self.readiness.claim_assessment_work(
            self.caller,
            permit(self.caller, "knowledge.ingestion.readiness.process", work_scope_digest(self.caller.organization_id, work["workId"])),
            work["workId"],
            expected_revision=work["revision"],
            ttl_seconds=60,
            correlation_id=identifier("correlation:api-worker-claim"),
        )
        assessment = self.readiness.complete_assessment_work(
            self.caller,
            permit(self.caller, "knowledge.ingestion.readiness.process", work_scope_digest(self.caller.organization_id, work["workId"])),
            claim,
            correlation_id=identifier("correlation:api-worker-complete"),
        )
        status, public_assessment = request(
            self.application,
            "GET",
            f"/knowledge/v1/readiness-assessments/{assessment.assessment_id}",
            headers=self.headers(),
        )
        self.assertEqual(status, 200)
        self.assertEqual(public_assessment, assessment.public_document())
        status, readiness_state = request(
            self.application,
            "GET",
            f"/knowledge/v1/sources/{self.source.source_id}/readiness",
            headers=self.headers(),
        )
        self.assertEqual(status, 200)
        self.assertEqual(readiness_state["effectiveState"], "READY_FOR_APPROVAL")

        self.approval = approval_for(self.readiness, self.source, self.batch, assessment)
        status, commit = request(
            self.application,
            "POST",
            f"/knowledge/v1/staged-batches/{self.batch.batch_id}:commit",
            {},
            headers=self.headers("api-commit", 1),
        )
        self.assertEqual(status, 200)
        self.assertEqual(commit["batchId"], self.batch.batch_id)
        status, active = request(
            self.application,
            "GET",
            f"/knowledge/v1/sources/{self.source.source_id}/readiness",
            headers=self.headers(),
        )
        self.assertEqual((status, active["effectiveState"]), (200, "ACTIVE"))
        status, revoked = request(
            self.application,
            "POST",
            f"/knowledge/v1/sources/{self.source.source_id}:revoke",
            {},
            headers=self.headers("api-revoke", 2),
        )
        self.assertEqual((status, revoked["state"]), (200, "REVOKED"))
        self.assertEqual(self.dependency_calls, 2)

    def test_policy_denial_precedes_readiness_dependency_lookup(self) -> None:
        self.allowed = False
        before = self.readiness.store.snapshot()
        status, response = request(
            self.application,
            "POST",
            f"/knowledge/v1/staged-batches/{self.batch.batch_id}:assess",
            {},
            headers=self.headers("denied-assess"),
        )
        self.assertEqual((status, response["code"]), (404, "POLICY_DENIED"))
        self.assertEqual(self.dependency_calls, 0)
        self.assertEqual(self.readiness.store.snapshot(), before)

    def test_dead_letter_read_and_acknowledgement_routes_never_requeue_or_delete(self) -> None:
        status, work = request(
            self.application,
            "POST",
            f"/knowledge/v1/staged-batches/{self.batch.batch_id}:assess",
            {},
            headers=self.headers("dead-letter-assess"),
        )
        self.assertEqual(status, 202)
        process = permit(
            self.caller,
            "knowledge.ingestion.readiness.process",
            work_scope_digest(self.caller.organization_id, work["workId"]),
        )
        claim = self.readiness.claim_assessment_work(
            self.caller,
            process,
            work["workId"],
            expected_revision=work["revision"],
            ttl_seconds=60,
            correlation_id=identifier("correlation:api-dead-letter-claim"),
        )
        terminal, dead_letter = self.readiness.record_assessment_failure(
            self.caller,
            process,
            claim,
            reason_code="POLICY_STALE",
            correlation_id=identifier("correlation:api-dead-letter"),
        )
        self.assertEqual(terminal.state.value, "DEAD_LETTERED")
        status, fetched = request(
            self.application,
            "GET",
            f"/knowledge/v1/dead-letters/{dead_letter.dead_letter_id}",
            headers=self.headers(),
        )
        self.assertEqual((status, fetched["deadLetterId"]), (200, dead_letter.dead_letter_id))
        status, review = request(
            self.application,
            "POST",
            f"/knowledge/v1/dead-letters/{dead_letter.dead_letter_id}:review",
            {"decision": "ACKNOWLEDGED", "reasonCode": "review.accepted"},
            headers=self.headers("api-dead-letter-review"),
        )
        self.assertEqual((status, review["decision"]), (200, "ACKNOWLEDGED"))
        snapshot = self.readiness.store.snapshot()
        self.assertIn((self.caller.organization_id, dead_letter.dead_letter_id), snapshot.dead_letters)
        self.assertEqual(
            snapshot.readiness_work_revisions[(self.caller.organization_id, work["workId"])][-1].state.value,
            "DEAD_LETTERED",
        )

    def test_dependency_exception_and_closed_request_errors_are_non_echoing(self) -> None:
        self.dependency_failure = True
        status, response = request(
            self.application,
            "POST",
            f"/knowledge/v1/staged-batches/{self.batch.batch_id}:assess",
            {},
            headers=self.headers("failed-dependency"),
        )
        self.assertEqual((status, response["code"]), (503, "DEPENDENCY_UNAVAILABLE"))
        self.assertNotIn("private-policy-endpoint-detail", str(response))
        cases = (
            ("POST", f"/knowledge/v1/staged-batches/{self.batch.batch_id}:assess", {"policy": {}}, self.headers("body-policy"), b"", "BODY_INVALID"),
            ("POST", f"/knowledge/v1/staged-batches/{self.batch.batch_id}:commit", {}, self.headers("missing-revision"), b"", "IF_MATCH_INVALID"),
            ("GET", f"/knowledge/v1/sources/{self.source.source_id}/readiness", None, [(b"x-tenant-id", b"other"), *self.headers()], b"", "CALLER_IDENTITY_FORBIDDEN"),
            ("GET", f"/knowledge/v1/sources/{self.source.source_id}/readiness", None, self.headers(), b"tenant=other", "INVALID_REQUEST"),
            ("DELETE", f"/knowledge/v1/staged-batches/{self.batch.batch_id}:commit", None, self.headers(), b"", "ROUTE_NOT_FOUND"),
        )
        self.dependency_failure = False
        for method, path, body, headers, query, code in cases:
            with self.subTest(code=code):
                status, result = request(self.application, method, path, body, headers=headers, query=query)
                self.assertEqual(result["code"], code)
                self.assertEqual(result["message"], "Request could not be processed.")
                self.assertIn(status, {400, 404})


class ReadinessSourceAndMigrationSecurityTests(unittest.TestCase):
    def test_dependency_free_source_has_no_io_process_dynamic_code_or_external_client(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
        self.assertEqual(project["project"]["dependencies"], [])
        self.assertEqual(project["build-system"]["requires"], [])
        self.assertEqual(len(lock["package"]), 1)
        forbidden_imports = {"asyncio.subprocess", "http.client", "os", "requests", "socket", "subprocess", "urllib", "psycopg"}
        forbidden_calls = {"open", "exec", "eval", "compile", "__import__"}
        for relative in (
            "classification.py", "coverage.py", "evidence.py", "freshness.py",
            "provenance.py", "readiness.py", "retries.py",
        ):
            path = ROOT / "src/planeon_knowledge/ingestion" / relative
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            imports = set()
            calls = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imports.add(node.module or "")
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    calls.add(node.func.id)
            self.assertFalse(any(name == prefix or name.startswith(prefix + ".") for name in imports for prefix in forbidden_imports), relative)
            self.assertFalse(calls & forbidden_calls, relative)

    def test_exact_predecessor_and_external_boundary_locks_are_pinned(self) -> None:
        expected = {
            "src/planeon_knowledge/common/canonical.py": "90f000f5a09a12c3cc2f55b659cd1c563751f268fc4173756563b2d6cf46eb7f",
            "src/planeon_knowledge/common/models.py": "c52af1605f0e7c5ee0a0b6734cebe4cf1c46e32db6318fadef733a8e722792f6",
            "src/planeon_knowledge/common/errors.py": "1de5c6a674bc341afe473fcb430a634ffadf1cc4d4b6bbf4e0164968616d0215",
            "src/planeon_knowledge/ingestion/contracts.py": "d6f28dcddebd339541396c09d5242a538e8e1fdfe9702a8bd5d0692b88383d57",
            "src/planeon_knowledge/ingestion/batch.py": "17a82e95fef2552c2f9b8b417ff512cb83a5bf08f803d28ef6b463fe68453368",
            "src/planeon_knowledge/ingestion/store.py": "07bb0ebcada2f0c2346da5d61a5243d91be0ea66a6d552496a5fc83564bbeb8a",
            "src/planeon_knowledge/ingestion/service.py": "d8476c3ed6834f632d029f010571f4401d706e40432713415d033734082a3210",
            "src/planeon_knowledge/ingestion/asgi.py": "c80fe850c4cd2811741431a480eae9248b1462305f664b6515a9225a5d546e13",
            "migrations/ingestion/002_connector_service.sql": "f1d62adc876d761f7cb5f9707a8b1cf18c27d139b1acaf2a36efc6c2c39b944e",
            "Makefile": "af17da2687c3f0684dc4044981c5ea0ead3a9c51d6240a539bf7353402db5f09",
            "ci/run_make_target.py": "29e8cb70e71a3d03f9f50108e28f99d890da6090a680c8de32d6bdcd947be7ea",
            "ci/run_packet_argv.py": "7499ccf15021145c0d6698aa8e1e7d333ab6ccc4d6f1fb397a277b895de6e1f8",
            ".github/workflows/verify.yml": "91090dc69c12837e8b73eb41a868b3afca7dcb34b304c7b409ac716310ddd3a6",
            "ci/zero_bill_scan.py": "cd859d5f3c8aaf1b0a5eee1b3f5f445a471c8749e0507a2749ecbb490371e509",
        }
        for relative, expected_digest in expected.items():
            completed = subprocess.run(
                ["git", "show", f"{BASE}:{relative}"],
                cwd=ROOT,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, relative)
            self.assertEqual(hashlib.sha256(completed.stdout).hexdigest(), expected_digest, relative)
        locks = json.loads((ROOT / "fixtures/readiness/upstream-locks.json").read_text(encoding="utf-8"))
        self.assertEqual(locks["contracts"]["evidenceRecordSha256"], "a80935c2dc5ac4624d972edc3876d301059c74e507ca2be28ea353b1070bdd8c")
        self.assertEqual(locks["trustPlane"]["commit"], "73802adbfa1adf97f20d03026e0b2232691d5392")

    def test_sql_is_additive_tenant_rls_append_only_fenced_and_least_privilege(self) -> None:
        sql = (ROOT / "migrations/ingestion/readiness/003_readiness.sql").read_text(encoding="utf-8")
        tables = (
            "readiness_policy_observation", "measurement_observation", "readiness_work_revision",
            "readiness_work_pointer", "readiness_finding", "readiness_assessment",
            "provenance_graph", "readiness_evidence", "source_readiness_revision",
            "source_readiness_pointer", "batch_commit", "checkpoint_revision",
            "checkpoint_pointer", "dead_letter_record", "dead_letter_review",
            "readiness_event_outbox",
        )
        for table in tables:
            self.assertIn(f"CREATE TABLE ingestion.{table}", sql)
            self.assertIn(f"'{table}'", sql)
        self.assertIn("staged_batch_future_partition_required", sql)
        self.assertIn("CHECK (partition_token IS NOT NULL) NOT VALID", sql)
        self.assertIn("ENABLE ROW LEVEL SECURITY", sql)
        self.assertIn("FORCE ROW LEVEL SECURITY", sql)
        self.assertIn("NULLIF(current_setting('planeon.organization_id', true), '')::uuid", sql)
        for function_name in (
            "compare_and_append_readiness_work",
            "compare_and_append_source_readiness",
            "compare_and_append_checkpoint",
            "commit_readiness_batch",
        ):
            self.assertIn(f"CREATE FUNCTION ingestion.{function_name}", sql)
            self.assertIn(f"REVOKE ALL ON FUNCTION ingestion.{function_name}", sql)
        self.assertEqual(sql.count("SECURITY DEFINER"), 4)
        self.assertIn("stale work revision", sql)
        self.assertIn("revoked source cannot be re-enabled", sql)
        self.assertIn("checkpoint order invalid", sql)
        grant_lines = "\n".join(line for line in sql.splitlines() if line.startswith("GRANT "))
        self.assertNotRegex(grant_lines, r"\b(?:UPDATE|DELETE|TRUNCATE|ALL)\b")
        self.assertNotIn("BYPASSRLS", grant_lines)
        upper = sql.upper()
        for forbidden in ("CREATE DATABASE", "CREATE ROLE", "CREATE EXTENSION", "DROP ", "TRUNCATE ", "ALTER ROLE", "CREATE SECRET"):
            self.assertNotIn(forbidden, upper)
        for forbidden in ("raw_payload", "payload_bytes", "secret_value", "connection_string", "broker_url", "opaque_checkpoint"):
            self.assertNotIn(forbidden, sql.casefold())

    def test_packet_descriptor_is_closed_direct_argv_and_cumulative(self) -> None:
        descriptor = json.loads((ROOT / "ci/targets/kn-data-002.json").read_text(encoding="utf-8"))
        self.assertEqual(descriptor["packetId"], "KN-DATA-002")
        self.assertEqual(
            [item["name"] for item in descriptor["targets"]],
            ["prefetch", "readiness-parity", "readiness-contract", "failure-matrix", "security"],
        )
        rendered = json.dumps(descriptor)
        self.assertNotRegex(rendered, r'"(?:sh|bash|zsh)",\s*"-c"')
        self.assertNotIn("data-source-harness", rendered)
        evidence = json.loads((ROOT / "fixtures/readiness/evidence-status.json").read_text(encoding="utf-8"))
        self.assertEqual(evidence["postgresql"], "NOT_RUN_ENV_UNAVAILABLE")
        self.assertEqual(evidence["tenantAcceptance"], "PENDING_TENANT_AUTHORITY")

    def test_service_composition_exposes_no_readiness_business_route_from_worker(self) -> None:
        controller = (ROOT / "services/connector-controller/app.py").read_text(encoding="utf-8")
        worker = (ROOT / "services/ingest-worker/app.py").read_text(encoding="utf-8")
        self.assertIn("readiness_dependency_provider", controller)
        self.assertIn("create_readiness_worker", worker)
        for method in ("claim_assessment_work", "complete_assessment_work", "record_assessment_failure"):
            self.assertIn(method, worker)
        self.assertNotIn("IngestionAsgiApplication", worker)
        self.assertNotIn("/knowledge/v1/", worker)


if __name__ == "__main__":
    unittest.main()
