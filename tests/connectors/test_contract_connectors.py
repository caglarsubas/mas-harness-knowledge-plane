from __future__ import annotations

import hashlib
import unittest

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.ingestion.connectors import (
    ConnectorFailure,
    EventBinding,
    FileBinding,
    HttpBinding,
    PostgresBinding,
    execute,
)
from planeon_knowledge.ingestion.contracts import ConnectorKind, ReadPlan
from planeon_knowledge.ingestion.decoder import DecoderFailure, decode

from tests.connectors.support import (
    ATTESTATIONS,
    FixturePort,
    binding,
    fixture_bytes,
    identifier,
    identity,
    profiles,
    source,
)


def plan(kind: ConnectorKind, binding_digest: str) -> ReadPlan:
    candidate = source(kind)
    return ReadPlan(
        candidate.organization_id,
        candidate.source_id,
        candidate.resource_digest,
        kind,
        identifier(f"plan-grant:{kind.value}"),
        binding_digest,
        identifier(f"plan-lease:{kind.value}"),
        1,
        1,
        100,
        1024 * 1024,
        profiles()[kind].max_pages,
        5_000,
        canonical_digest({"request": kind.value}),
    )


class ConnectorContractTests(unittest.TestCase):
    def test_each_connector_reads_only_through_the_injected_port(self) -> None:
        for kind in ConnectorKind:
            with self.subTest(kind=kind):
                binding_value = binding(kind)
                injected = FixturePort(kind)
                pages = execute(
                    plan(kind, binding_value.binding_digest),
                    binding_value,
                    injected,
                    parameters={"plant": "ankara"} if kind is ConnectorKind.POSTGRESQL else None,
                    checkpoint="position-100" if kind is ConnectorKind.EVENT else None,
                )
                self.assertEqual(len(pages), 1)
                self.assertEqual(pages[0].payload, fixture_bytes(kind))
                self.assertEqual(len(injected.calls), 1)
                self.assertEqual(injected.calls[0][2], "position-100" if kind is ConnectorKind.EVENT else None)

    def test_connector_kind_and_attestations_are_closed(self) -> None:
        http = binding(ConnectorKind.HTTP)
        with self.assertRaisesRegex(ConnectorFailure, "CONNECTOR_BINDING_KIND_MISMATCH"):
            execute(plan(ConnectorKind.HTTP, http.binding_digest), binding(ConnectorKind.FILE), FixturePort(ConnectorKind.HTTP))
        with self.assertRaisesRegex(ConnectorFailure, "CONNECTOR_ATTESTATION_MISSING"):
            execute(plan(ConnectorKind.HTTP, http.binding_digest), http, FixturePort(ConnectorKind.HTTP, attestations=frozenset()))

    def test_file_binding_rejects_traversal_absolute_control_and_symlink(self) -> None:
        material = "sha256:" + "1" * 64
        mount = "sha256:" + "2" * 64
        for path in ("../secret", "/etc/passwd", "a//b", "a/./b", "a\\b", "a\x00b"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                FileBinding(path, mount, material, True, True)
        linked = FileBinding("imports/data.csv", mount, material, True, False)
        with self.assertRaisesRegex(ConnectorFailure, "FILE_BINDING_DENIED"):
            execute(plan(ConnectorKind.FILE, linked.binding_digest), linked, FixturePort(ConnectorKind.FILE))

    def test_http_binding_rejects_ssrf_and_next_link_escape(self) -> None:
        for host in ("localhost", "127.0.0.1", "169.254.169.254", "10.0.0.1", "metadata.google.internal", "service.internal"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                HttpBinding("https", host, 443, "/v1", "NONE")
        binding_value = binding(ConnectorKind.HTTP)
        with self.assertRaisesRegex(ConnectorFailure, "HTTP_PAGINATION_DENIED"):
            execute(
                plan(ConnectorKind.HTTP, binding_value.binding_digest),
                binding_value,
                FixturePort(ConnectorKind.HTTP, next_token="https-outside-invalid"),
            )

    def test_postgresql_is_prepared_bounded_and_accepts_no_sql_text(self) -> None:
        with self.assertRaises(ValueError):
            PostgresBinding("statement", "sha256:" + "3" * 64, False, True, 100, 1_000)
        binding_value = binding(ConnectorKind.POSTGRESQL)
        supplied_plan = plan(ConnectorKind.POSTGRESQL, binding_value.binding_digest)
        for parameters in ({"plant": ["ankara"]}, {"plant": 2**80}, {"SELECT * FROM secrets": "x"}):
            with self.subTest(parameters=parameters), self.assertRaises(ConnectorFailure):
                execute(supplied_plan, binding_value, FixturePort(ConnectorKind.POSTGRESQL), parameters=parameters)
        self.assertFalse(hasattr(binding_value, "sql"))
        self.assertFalse(hasattr(binding_value, "connection_string"))

    def test_event_binding_forbids_commit_and_administration(self) -> None:
        digest = "sha256:" + "4" * 64
        for auto_commit, operation in ((True, "POLL"), (False, "ADMIN"), (False, "PRODUCE")):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                EventBinding(digest, digest, 0, auto_commit, operation)
        binding_value = binding(ConnectorKind.EVENT)
        with self.assertRaisesRegex(ConnectorFailure, "EVENT_NEXT_LINK_FORBIDDEN"):
            execute(
                plan(ConnectorKind.EVENT, binding_value.binding_digest),
                binding_value,
                FixturePort(ConnectorKind.EVENT, next_token="other-topic"),
                checkpoint="position-100",
            )


class DecoderContractTests(unittest.TestCase):
    def assert_reason(self, reason: str, payload: bytes, media_type: str = "application/json") -> None:
        with self.assertRaises(DecoderFailure) as raised:
            decode(payload, media_type, max_records=100)
        self.assertEqual(raised.exception.reason_code, reason)

    def test_supported_decoders_are_deterministic_and_digest_only(self) -> None:
        cases = (
            (b'{"a":1}', "application/json"),
            (b'{"a":1}\n{"a":2}\n', "application/x-ndjson"),
            (b"a,b\n1,2\n", "text/csv"),
            (b"plain document", "text/plain"),
            (b"# markdown", "text/markdown"),
        )
        for payload, media_type in cases:
            with self.subTest(media_type=media_type):
                first = decode(payload, media_type, max_records=10)
                second = decode(payload, media_type, max_records=10)
                self.assertEqual(first, second)
                rendered = repr(first)
                self.assertNotIn(payload.decode("utf-8"), rendered)
                self.assertTrue(all(item.record.record_digest.startswith("sha256:") for item in first))

    def test_malformed_oversized_and_executable_formats_fail_closed(self) -> None:
        self.assert_reason("JSON_DUPLICATE_KEY", b'{"a":1,"a":2}')
        self.assert_reason("JSON_NON_FINITE_NUMBER", b'{"a":NaN}')
        self.assert_reason("UTF8_REQUIRED", b"\xff", "text/plain")
        self.assert_reason("NDJSON_LINE_INVALID", b'{"a":1}\n\n{"a":2}', "application/x-ndjson")
        self.assert_reason("CSV_HEADER_INVALID", b"a,a\n1,2\n", "text/csv")
        self.assert_reason("MEDIA_TYPE_UNSUPPORTED", b"<xml/>", "application/xml")
        self.assert_reason("RESPONSE_SIZE_EXCEEDED", b"x" * (2 * 1024 * 1024 + 1), "text/plain")
        deep = b'{"a":' + b"[" * 18 + b"0" + b"]" * 18 + b"}"
        self.assert_reason("VALUE_DEPTH_EXCEEDED", deep)


if __name__ == "__main__":
    unittest.main()
