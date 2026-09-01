from __future__ import annotations

import hashlib
import json
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class SqlContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sql = (ROOT / "migrations/domain/002_semantic_service.sql").read_text(encoding="utf-8")

    def test_owned_tables_are_rls_forced_and_append_only(self) -> None:
        tables = (
            "domain_definition", "domain_version", "domain_version_revision",
            "semantic_mapping", "semantic_mapping_revision", "validation_report",
            "domain_evidence", "domain_event_outbox", "domain_idempotency",
            "active_domain_pointer",
        )
        for table in tables:
            with self.subTest(table=table):
                self.assertIn(f"CREATE TABLE domain.{table}", self.sql)
                self.assertIn(f"ALTER TABLE domain.{table} ENABLE ROW LEVEL SECURITY", self.sql)
                self.assertIn(f"ALTER TABLE domain.{table} FORCE ROW LEVEL SECURITY", self.sql)
        for table in tables[:-1]:
            self.assertIn(f"BEFORE UPDATE OR DELETE ON domain.{table}", self.sql)
        self.assertEqual(self.sql.count("NULLIF(current_setting('planeon.organization_id', true), '')::uuid"), 21)

    def test_runtime_grants_and_activation_boundary_are_least_privilege(self) -> None:
        self.assertIn("CREATE FUNCTION domain.activate_domain_version", self.sql)
        self.assertIn("SECURITY DEFINER", self.sql)
        self.assertIn("SET search_path = pg_catalog", self.sql)
        self.assertIn("p_expected_revision", self.sql)
        self.assertIn("p_idempotency_key", self.sql)
        self.assertIn("idempotency conflict", self.sql)
        self.assertIn("p_approval_evidence_digest", self.sql)
        self.assertIn("p_compatibility_digest", self.sql)
        self.assertIn("'SUPERSEDED'", self.sql)
        self.assertIn("'ACTIVE'", self.sql)
        self.assertIn("GRANT EXECUTE ON FUNCTION domain.activate_domain_version", self.sql)
        grant_lines = "\n".join(line for line in self.sql.splitlines() if line.startswith("GRANT "))
        self.assertNotRegex(grant_lines, r"\b(?:UPDATE|DELETE|TRUNCATE|ALL)\b")
        self.assertNotIn("BYPASSRLS", grant_lines)

    def test_migration_has_no_provisioning_or_destructive_path(self) -> None:
        upper = self.sql.upper()
        for forbidden in ("CREATE DATABASE", "CREATE ROLE", "CREATE EXTENSION", "DROP ", "TRUNCATE ", "DELETE FROM", "ALTER ROLE", "CREATE SECRET"):
            self.assertNotIn(forbidden, upper)
        for content in ("graph_bytes", "shape_bytes", "source_value", "raw_schema", "credential", "token_value", "prompt", "model_output"):
            self.assertNotIn(content, self.sql.casefold())


class PackagingAndDeploymentTests(unittest.TestCase):
    def test_root_project_remains_dependency_free_and_foundation_files_are_unchanged(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
        self.assertEqual(project["project"]["dependencies"], [])
        self.assertEqual(project["build-system"]["requires"], [])
        self.assertEqual(len(lock["package"]), 1)
        self.assertEqual((ROOT / "Makefile").read_text(encoding="utf-8").count("ci/run_make_target.py"), 2)
        self.assertEqual(hashlib.sha256((ROOT / "ci/run_make_target.py").read_bytes()).hexdigest(), "29e8cb70e71a3d03f9f50108e28f99d890da6090a680c8de32d6bdcd947be7ea")

    def test_service_dependency_unit_is_exact_and_install_free(self) -> None:
        lock = json.loads((ROOT / "services/domain-service/dependencies.lock.json").read_text(encoding="utf-8"))
        self.assertEqual(len(lock["packages"]), 8)
        self.assertEqual([item["name"] for item in lock["packages"]], ["html5rdf", "owlrl", "packaging", "prettytable", "pyparsing", "pyshacl", "rdflib", "wcwidth"])
        container = (ROOT / "services/domain-service/Containerfile").read_text(encoding="utf-8")
        self.assertNotRegex(container, r"(?m)^(?:RUN|ADD)\s")
        self.assertIn("USER 65532:65532", container)
        self.assertIn("dependencies.lock.json", container)
        self.assertNotIn("pip install", container.casefold())
        self.assertNotIn("uv sync", container.casefold())

    def test_chart_is_inert_digest_bound_and_default_deny(self) -> None:
        values = (ROOT / "deploy/helm/domain-service/values.yaml").read_text(encoding="utf-8")
        workload = (ROOT / "deploy/helm/domain-service/templates/workload.yaml").read_text(encoding="utf-8")
        network = (ROOT / "deploy/helm/domain-service/templates/networkpolicy.yaml").read_text(encoding="utf-8")
        self.assertTrue(values.startswith("enabled: false\n"))
        self.assertIn('existingConfigMap: ""', values)
        self.assertIn('bundleDigest: ""', values)
        self.assertIn('required "semanticProvider.existingConfigMap is required"', workload)
        self.assertIn('required "semanticProvider.bundleDigest is required"', workload)
        self.assertIn("@{{ $digest }}", workload)
        self.assertIn("runAsNonRoot: true", workload)
        self.assertIn("readOnlyRootFilesystem: true", workload)
        self.assertIn("policyTypes: [Ingress, Egress]", network)
        self.assertIn("ingress: []", network)
        self.assertIn("egress: []", network)

    def test_evidence_axes_never_infer_runtime_or_acceptance(self) -> None:
        axes = json.loads((ROOT / "fixtures/domain/evidence-status.json").read_text(encoding="utf-8"))
        self.assertEqual(axes["postgresql"], "NOT_RUN_ENV_UNAVAILABLE")
        self.assertEqual(axes["deployment"], "NOT_RUN_ENV_UNAVAILABLE")
        self.assertEqual(axes["runtime"], "NOT_RUN_ENV_UNAVAILABLE")
        self.assertEqual(axes["tenantAcceptance"], "PENDING_TENANT_AUTHORITY")
        self.assertNotEqual(axes["source"], "ACCEPTED")


if __name__ == "__main__":
    unittest.main()
