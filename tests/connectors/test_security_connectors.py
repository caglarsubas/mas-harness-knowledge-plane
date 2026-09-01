from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from planeon_knowledge.ingestion.contracts import ConnectorKind, SourceState
from planeon_knowledge.ingestion.service import IngestionFailure, source_scope_digest

from tests.connectors.support import (
    FixturePort,
    MemoryStagingPort,
    OTHER_ORGANIZATION_ID,
    acquire_sample_lease,
    create_and_validate,
    identifier,
    identity,
    permit,
    sample,
    service,
    source,
)

ROOT = Path(__file__).resolve().parents[2]


class IsolationAndDisclosureTests(unittest.TestCase):
    def test_policy_denial_occurs_before_owned_store_read(self) -> None:
        caller = identity()
        target = service()
        candidate = source(caller=caller)
        denied = permit(
            caller,
            "knowledge.ingestion.source.read",
            source_scope_digest(caller.organization_id, candidate.source_id),
            allowed=False,
        )
        with patch.object(target.store, "read", side_effect=AssertionError("store read occurred")):
            with self.assertRaisesRegex(IngestionFailure, "POLICY_DENIED"):
                target.get_source(caller, denied, candidate.source_id)

    def test_cross_tenant_read_is_non_disclosing(self) -> None:
        caller = identity()
        target = service()
        candidate, _binding, _validated = create_and_validate(target, caller)
        other = identity(organization_id=OTHER_ORGANIZATION_ID)
        with self.assertRaisesRegex(IngestionFailure, "SOURCE_NOT_FOUND"):
            target.get_source(
                other,
                permit(other, "knowledge.ingestion.source.read", source_scope_digest(other.organization_id, candidate.source_id)),
                candidate.source_id,
            )

    def test_connector_exception_is_bounded_and_persists_no_provider_detail(self) -> None:
        caller = identity()
        target = service()
        candidate, binding_value, validated = create_and_validate(target, caller)
        lease = acquire_sample_lease(target, caller, candidate)
        with self.assertRaisesRegex(IngestionFailure, "CONNECTOR_DEPENDENCY_UNAVAILABLE") as raised:
            sample(
                target,
                caller,
                candidate,
                binding_value,
                validated.revision,
                lease,
                port=FixturePort(candidate.connector_kind, failure=RuntimeError("password=never-store-this")),
            )
        self.assertEqual(str(raised.exception), "CONNECTOR_DEPENDENCY_UNAVAILABLE")
        snapshot = target.store.snapshot()
        self.assertIs(snapshot.source_revisions[(caller.organization_id, candidate.source_id)][-1].state, SourceState.INVALID)
        self.assertNotIn("never-store-this", str(snapshot))
        self.assertEqual(snapshot.batches, {})

    def test_successful_state_contains_digests_not_source_material_or_credentials(self) -> None:
        caller = identity()
        target = service()
        candidate, binding_value, validated = create_and_validate(target, caller, ConnectorKind.POSTGRESQL)
        lease = acquire_sample_lease(target, caller, candidate)
        batch = sample(target, caller, candidate, binding_value, validated.revision, lease, staging=MemoryStagingPort())
        rendered = str((target.store.snapshot(), batch)).casefold()
        for forbidden in (
            "seal-check",
            "noise-check",
            "password",
            "connection_string",
            "select *",
            "api.example.com",
            "white-goods-quality",
            "ankara",
        ):
            self.assertNotIn(forbidden, rendered)


class SourceClosureTests(unittest.TestCase):
    def test_ingestion_source_has_no_external_io_or_process_client(self) -> None:
        root = ROOT / "src/planeon_knowledge/ingestion"
        forbidden_imports = {"asyncio.subprocess", "http.client", "os", "requests", "socket", "subprocess", "urllib", "psycopg"}
        forbidden_calls = {"open", "exec", "eval", "compile", "__import__"}
        for path in sorted(root.rglob("*.py")):
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
            with self.subTest(path=path.name):
                self.assertFalse(any(any(name == prefix or name.startswith(prefix + ".") for prefix in forbidden_imports) for name in imports), imports)
                self.assertFalse(calls & forbidden_calls, calls)

    def test_public_metadata_contract_has_no_material_locator_or_authority_fields(self) -> None:
        source_text = (ROOT / "src/planeon_knowledge/ingestion/contracts.py").read_text(encoding="utf-8").casefold()
        for forbidden in (
            "raw_payload",
            "payload_bytes",
            "secret_value",
            "secret_name",
            "connection_string",
            "sql_text",
            "broker_url",
            "checkpoint_pointer",
            "owner_approval",
        ):
            self.assertNotIn(forbidden, source_text)

    def test_root_dependency_and_predecessor_locks_are_unchanged(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
        self.assertEqual(project["project"]["dependencies"], [])
        self.assertEqual(project["build-system"]["requires"], [])
        self.assertEqual(len(lock["package"]), 1)
        expected = {
            "src/planeon_knowledge/common/canonical.py": "90f000f5a09a12c3cc2f55b659cd1c563751f268fc4173756563b2d6cf46eb7f",
            "src/planeon_knowledge/common/models.py": "c52af1605f0e7c5ee0a0b6734cebe4cf1c46e32db6318fadef733a8e722792f6",
            "src/planeon_knowledge/common/errors.py": "1de5c6a674bc341afe473fcb430a634ffadf1cc4d4b6bbf4e0164968616d0215",
            "src/planeon_knowledge/domain/contracts.py": "c0cfd135f111af966d41b75cfb7f57325c5999a4ccb29019fc1400951db58ef6",
            "src/planeon_knowledge/domain/service.py": "4314af7bd130907f410fa38895b88c74a83dad474ee99b8677a44d8340383648",
            "migrations/ingestion/001_foundation.sql": "8158bc6cdc57a2f3a46493002bbc361c3ebe8842cb684336b058fe385dd52d76",
            "Makefile": "af17da2687c3f0684dc4044981c5ea0ead3a9c51d6240a539bf7353402db5f09",
            "ci/run_make_target.py": "29e8cb70e71a3d03f9f50108e28f99d890da6090a680c8de32d6bdcd947be7ea",
            "ci/run_packet_argv.py": "7499ccf15021145c0d6698aa8e1e7d333ab6ccc4d6f1fb397a277b895de6e1f8",
            "ci/zero_bill_scan.py": "cd859d5f3c8aaf1b0a5eee1b3f5f445a471c8749e0507a2749ecbb490371e509",
        }
        for relative, digest in expected.items():
            with self.subTest(path=relative):
                self.assertEqual(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), digest)


class SqlAndDeploymentContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sql = (ROOT / "migrations/ingestion/002_connector_service.sql").read_text(encoding="utf-8")

    def test_sql_tables_are_tenant_rls_and_immutable(self) -> None:
        tables = (
            "source_definition", "source_revision", "connector_lease_revision",
            "connector_lease_pointer", "staged_batch", "staged_record_digest",
            "ingestion_idempotency", "ingestion_evidence", "ingestion_event_outbox",
        )
        for table in tables:
            with self.subTest(table=table):
                self.assertIn(f"CREATE TABLE ingestion.{table}", self.sql)
                self.assertIn(f"'{table}'", self.sql)
        self.assertIn("ENABLE ROW LEVEL SECURITY", self.sql)
        self.assertIn("FORCE ROW LEVEL SECURITY", self.sql)
        self.assertIn("NULLIF(current_setting('planeon.organization_id', true), '')::uuid", self.sql)
        for table in tables:
            if table != "connector_lease_pointer":
                self.assertIn(f"'{table}'", self.sql[self.sql.index("DO $planeon_append_only$"):])

    def test_sql_functions_are_fenced_and_grants_are_least_privilege(self) -> None:
        self.assertIn("CREATE FUNCTION ingestion.compare_and_append_lease", self.sql)
        self.assertIn("CREATE FUNCTION ingestion.stage_metadata", self.sql)
        self.assertGreaterEqual(self.sql.count("SECURITY DEFINER"), 2)
        self.assertIn("stale lease revision", self.sql)
        self.assertIn("fencing token did not increase", self.sql)
        self.assertIn("stale source revision", self.sql)
        self.assertIn("lease fence mismatch", self.sql)
        grant_lines = "\n".join(line for line in self.sql.splitlines() if line.startswith("GRANT "))
        self.assertNotRegex(grant_lines, r"\b(?:UPDATE|DELETE|TRUNCATE|ALL)\b")
        self.assertNotIn("BYPASSRLS", grant_lines)

    def test_sql_has_no_provisioning_destructive_or_material_columns(self) -> None:
        upper = self.sql.upper()
        for forbidden in ("CREATE DATABASE", "CREATE ROLE", "CREATE EXTENSION", "DROP ", "TRUNCATE ", "DELETE FROM", "ALTER ROLE", "CREATE SECRET"):
            self.assertNotIn(forbidden, upper)
        lowered = self.sql.casefold()
        for forbidden in ("payload", "binary", "secret_value", "url", "hostname", "sql_text", "connection_string", "topic_name", "checkpoint_pointer", "commit_pointer", "retry_queue"):
            self.assertNotIn(forbidden, lowered)

    def test_container_and_charts_are_inert_digest_bound_and_default_deny(self) -> None:
        for name in ("connector-controller", "ingest-worker"):
            with self.subTest(name=name):
                container = (ROOT / f"services/{name}/Containerfile").read_text(encoding="utf-8")
                values = (ROOT / f"deploy/helm/{name}/values.yaml").read_text(encoding="utf-8")
                workload = (ROOT / f"deploy/helm/{name}/templates/workload.yaml").read_text(encoding="utf-8")
                network = (ROOT / f"deploy/helm/{name}/templates/networkpolicy.yaml").read_text(encoding="utf-8")
                self.assertNotRegex(container, r"(?m)^(?:RUN|ADD)\s")
                self.assertIn("ARG BASE_IMAGE", container)
                self.assertIn("USER 65532:65532", container)
                self.assertTrue(values.startswith("enabled: false\n"))
                for key in ("endpointGrants", "credentialReferences", "staging", "sourceNetworkPolicy", "domainBindings"):
                    self.assertIn(f"{key}:", values)
                self.assertIn("@{{ $digest }}", workload)
                self.assertIn("runAsNonRoot: true", workload)
                self.assertIn("readOnlyRootFilesystem: true", workload)
                self.assertNotRegex(workload, r"(?m)^kind:\s*(?:Secret|PersistentVolumeClaim|Route|Namespace)$")
                self.assertIn("policyTypes: [Ingress, Egress]", network)
                self.assertIn("ingress: []", network)
                self.assertIn("egress: []", network)

    def test_packet_target_descriptor_is_direct_argv_and_closed(self) -> None:
        descriptor = json.loads((ROOT / "ci/targets/kn-data-001.json").read_text(encoding="utf-8"))
        self.assertEqual(descriptor["packetId"], "KN-DATA-001")
        self.assertEqual([item["name"] for item in descriptor["targets"]], ["connector-parity", "connector-contract", "security"])
        rendered = json.dumps(descriptor)
        self.assertNotRegex(rendered, r'"(?:sh|bash|zsh)",\s*"-c"')
        self.assertNotIn("prefetch.py", rendered)

    def test_workflow_changes_only_to_full_public_history(self) -> None:
        predecessor = "187a3d6234d7e53392acc6984221fa314d40cf93"
        completed = subprocess.run(
            ["git", "show", f"{predecessor}:.github/workflows/verify.yml"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            shell=False,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        expected = completed.stdout.replace("fetch-depth: 2", "fetch-depth: 0")
        current = (ROOT / ".github/workflows/verify.yml").read_text(encoding="utf-8")
        self.assertEqual(current, expected)
        self.assertIn("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", current)
        self.assertIn("persist-credentials: false", current)
        self.assertIn("runs-on: [self-hosted, harness-engineering, ephemeral, credential-free]", current)
        self.assertNotIn("ubuntu-latest", current)


if __name__ == "__main__":
    unittest.main()
