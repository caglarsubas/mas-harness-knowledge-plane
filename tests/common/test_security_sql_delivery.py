from __future__ import annotations

import json
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ("domain", "ingestion", "retrieval", "memory")
SERVICES = ("domain-service", "connector-controller", "ingest-worker", "retrieval-service", "index-worker", "memory-service")
BASE = "f3a3463d2fe04d4b17dc3abbebc6b3375bd6d890"


class SqlContractTests(unittest.TestCase):
    def test_four_isolated_rls_append_only_store_contracts(self) -> None:
        all_text = ""
        for schema in SCHEMAS:
            path = ROOT / f"migrations/{schema}/001_foundation.sql"
            text = path.read_text(encoding="utf-8")
            all_text += text
            owner = f"planeon_kn_{schema}_owner"
            runtime = f"planeon_kn_{schema}_runtime"
            with self.subTest(schema=schema):
                self.assertIn(f"CREATE ROLE {owner} NOLOGIN", text)
                self.assertIn(f"CREATE ROLE {runtime} NOLOGIN", text)
                self.assertIn("NOINHERIT NOBYPASSRLS", text)
                self.assertIn(f"CREATE SCHEMA {schema} AUTHORIZATION {owner}", text)
                for table in ("source_reference", "inbox_event", "outbox_event"):
                    self.assertIn(f"CREATE TABLE {schema}.{table}", text)
                    self.assertIn(f"ALTER TABLE {schema}.{table} ENABLE ROW LEVEL SECURITY", text)
                    self.assertIn(f"ALTER TABLE {schema}.{table} FORCE ROW LEVEL SECURITY", text)
                    self.assertRegex(text, rf"BEFORE UPDATE OR DELETE ON {schema}\.{table}")
                self.assertGreaterEqual(text.count("NULLIF(current_setting('planeon.organization_id', true), '')::uuid"), 6)
                self.assertIn("set_config('planeon.organization_id', value::text, true)", text)
                self.assertIn(f"GRANT SELECT, INSERT ON {schema}.source_reference, {schema}.inbox_event, {schema}.outbox_event TO {runtime}", text)
                self.assertNotRegex(text, rf"GRANT .*\b(UPDATE|DELETE|TRUNCATE|CREATE|ALL)\b.* TO {runtime}")
                for other in set(SCHEMAS) - {schema}:
                    self.assertNotIn(f"{other}.", text)
                for forbidden in ("CREATE USER", "CREATE DATABASE", "CREATE EXTENSION", "DROP ", "ALTER ROLE", "CREATE TABLE public."):
                    self.assertNotIn(forbidden, text)
        roles = re.findall(r"CREATE ROLE (planeon_kn_[a-z]+_(?:owner|runtime))", all_text)
        self.assertEqual(len(roles), 8)
        self.assertEqual(len(set(roles)), 8)

    def test_inbox_outbox_keys_are_tenant_scoped(self) -> None:
        for schema in SCHEMAS:
            text = (ROOT / f"migrations/{schema}/001_foundation.sql").read_text(encoding="utf-8")
            self.assertEqual(text.count("PRIMARY KEY (organization_id, event_id)"), 2)


class DeliverySourceTests(unittest.TestCase):
    def test_six_containerfiles_are_non_root_digest_input_only(self) -> None:
        for service in SERVICES:
            text = (ROOT / f"services/{service}/Containerfile").read_text(encoding="utf-8")
            with self.subTest(service=service):
                self.assertIn("ARG BASE_IMAGE\nFROM ${BASE_IMAGE}", text)
                self.assertIn("USER 65532:65532", text)
                self.assertIn('ENTRYPOINT ["python3"', text)
                self.assertNotRegex(text, r"(?m)^(RUN|ADD)\s")
                self.assertNotRegex(text, r"(?m)^FROM\s+[^$]")

    def test_six_charts_are_inert_bounded_and_default_deny(self) -> None:
        for service in SERVICES:
            chart = ROOT / f"deploy/helm/{service}"
            values = (chart / "values.yaml").read_text(encoding="utf-8")
            workload = (chart / "templates/workload.yaml").read_text(encoding="utf-8")
            network = (chart / "templates/networkpolicy.yaml").read_text(encoding="utf-8")
            combined = values + workload + network
            with self.subTest(service=service):
                self.assertTrue(values.startswith("enabled: false\n"))
                self.assertIn('repository: ""', values)
                self.assertIn('digest: ""', values)
                self.assertIn('image: "{{ $repository }}@{{ $digest }}"', workload)
                for token in ("runAsNonRoot: true", "readOnlyRootFilesystem: true", "allowPrivilegeEscalation: false", 'drop: ["ALL"]', "type: RuntimeDefault", "automountServiceAccountToken: false", "resources:", "/health/live", "/health/ready"):
                    self.assertIn(token, workload)
                self.assertIn("policyTypes: [Ingress, Egress]", network)
                self.assertIn("ingress: []", network)
                self.assertIn("egress: []", network)
                for forbidden in ("kind: Secret", "kind: Namespace", "kind: PersistentVolume", "kind: PersistentVolumeClaim", "kind: Route", "kind: Ingress", "loadBalancer", "nodePort"):
                    self.assertNotIn(forbidden, combined)

    def test_workflow_is_two_step_ephemeral_and_credential_free(self) -> None:
        text = (ROOT / ".github/workflows/verify.yml").read_text(encoding="utf-8")
        self.assertIn("runs-on: [self-hosted, harness-engineering, ephemeral, credential-free]", text)
        self.assertIn("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("fetch-depth: 2", text)
        self.assertEqual(text.count("uses:"), 1)
        self.assertEqual(text.count("run:"), 1)
        self.assertIn("run: /opt/planeon/bin/harness-offline-launch", text)
        for forbidden in ("ubuntu-latest", "upload-artifact", "download-artifact", "actions/cache", "push:", "schedule:", "services:", "container:"):
            self.assertNotIn(forbidden, text)

    def test_changed_paths_are_kn001_owned(self) -> None:
        completed = subprocess.run(["git", "diff", "--name-only", BASE], cwd=ROOT, text=True, capture_output=True, shell=False, check=True)
        allowed = (
            ".github/workflows/verify.yml", "src/planeon_knowledge/common/", "services/", "migrations/",
            "tests/common/", "contract-mocks/", "deploy/helm/", "pyproject.toml", "uv.lock", "Makefile",
            "README.md", "AGENTS.md", "CONTRIBUTING.md", ".gitignore", "LICENSE", "NOTICE", "SECURITY.md",
            "PORTING.yaml", "ci/",
        )
        for path in completed.stdout.splitlines():
            self.assertTrue(any(path == item or (item.endswith("/") and path.startswith(item)) for item in allowed), path)

    def test_porting_ledger_is_exactly_inert(self) -> None:
        self.assertEqual(
            (ROOT / "PORTING.yaml").read_text(encoding="utf-8"),
            "schemaVersion: harness.planeon.ai/porting-ledger/v1alpha1\nstatus: NO_AUTHORIZATION\nauthorizationId: null\nmappings: []\ncopiedFiles: []\nappliedPorts: []\n",
        )

    def test_mock_files_have_no_sensitive_or_source_payload_fields(self) -> None:
        forbidden = {"apiKey", "authorization", "credential", "password", "secret", "token", "uri", "url", "filePath", "query", "payload", "prompt", "embedding", "modelOutput", "sourceContent"}

        def visit(value):
            if isinstance(value, dict):
                self.assertFalse(set(value) & forbidden)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        for path in sorted((ROOT / "contract-mocks").glob("*.json")):
            if path.name != "upstream-locks.json":
                visit(json.loads(path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
