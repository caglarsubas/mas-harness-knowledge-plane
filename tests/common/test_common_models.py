from __future__ import annotations

import dataclasses
import json
import unittest
from pathlib import Path

from planeon_knowledge.common import (
    IdempotencyState,
    InboxRecord,
    KnowledgeError,
    OutboxRecord,
    SourceReference,
    TenantIdentity,
    canonical_digest,
    canonical_json,
    classify_idempotency,
    parse_closed_json,
)
from planeon_knowledge.common.canonical import CanonicalJsonError
from planeon_knowledge.common.mocks import load_mock

ROOT = Path(__file__).resolve().parents[2]
ORG = "11111111-1111-4111-8111-111111111111"
SOURCE = "44444444-4444-4444-8444-444444444444"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
TIME = "2030-01-01T00:00:00Z"


class CanonicalTests(unittest.TestCase):
    def test_canonical_json_and_digest_are_deterministic(self) -> None:
        self.assertEqual(canonical_json({"b": 2, "a": "ü"}), b'{"a":"\xc3\xbc","b":2}')
        self.assertEqual(canonical_digest({"a": 1}), "sha256:015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862")

    def test_parser_rejects_duplicate_unknown_non_object_and_non_finite(self) -> None:
        for raw in ('{"a":1,"a":2}', '[1]', '{"a":NaN}', '{"a":1,"b":2}'):
            with self.subTest(raw=raw), self.assertRaises(CanonicalJsonError):
                parse_closed_json(raw, allowed_fields={"a"})

    def test_parser_rejects_invalid_utf8_and_oversize(self) -> None:
        with self.assertRaises(CanonicalJsonError):
            parse_closed_json(b"\xff")
        with self.assertRaises(CanonicalJsonError):
            parse_closed_json('{"a":"' + "x" * 65_536 + '"}')


class RecordTests(unittest.TestCase):
    def test_identity_is_closed_and_immutable(self) -> None:
        identity = TenantIdentity(ORG, "synthetic-subject", DIGEST_A)
        self.assertEqual(set(identity.as_dict()), {"schemaVersion", "organizationId", "subjectId", "admissionDigest"})
        with self.assertRaises(dataclasses.FrozenInstanceError):
            identity.subject_id = "changed"  # type: ignore[misc]
        with self.assertRaises(ValueError):
            TenantIdentity("tenant-from-body", "subject", DIGEST_A)

    def test_source_reference_is_metadata_only(self) -> None:
        source = SourceReference(ORG, SOURCE, DIGEST_A, DIGEST_B, DIGEST_A, "application/json", 42, TIME)
        value = source.as_dict()
        self.assertEqual(
            set(value),
            {"schemaVersion", "organizationId", "sourceId", "sourceVersionDigest", "locatorDigest", "contentDigest", "mediaType", "contentBytes", "observedAt"},
        )
        serialized = canonical_json(value).decode("utf-8")
        for forbidden in ("url", "uri", "path", "query", "token", "password", "payload", "prompt", "embedding"):
            self.assertNotIn(forbidden, serialized.casefold())

    def test_source_reference_rejects_bad_scalar_domains(self) -> None:
        invalid = [
            ("not-a-uuid", SOURCE, DIGEST_A, DIGEST_B, DIGEST_A, "application/json", 1, TIME),
            (ORG, SOURCE, "SHA256:" + "a" * 64, DIGEST_B, DIGEST_A, "application/json", 1, TIME),
            (ORG, SOURCE, DIGEST_A, DIGEST_B, DIGEST_A, "bad", 1, TIME),
            (ORG, SOURCE, DIGEST_A, DIGEST_B, DIGEST_A, "application/json", -1, TIME),
            (ORG, SOURCE, DIGEST_A, DIGEST_B, DIGEST_A, "application/json", 1, "2030-01-01T00:00:00+00:00"),
        ]
        for arguments in invalid:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                SourceReference(*arguments)

    def test_inbox_outbox_idempotency_and_append_only_transitions(self) -> None:
        inbox = InboxRecord(ORG, "55555555-5555-4555-8555-555555555555", "knowledge.source.observed", SOURCE, DIGEST_A, TIME)
        outbox = OutboxRecord(ORG, "66666666-6666-4666-8666-666666666666", "knowledge.source.recorded", SOURCE, DIGEST_B, TIME)
        self.assertEqual(inbox.idempotency_key, (ORG, inbox.event_id))
        self.assertEqual(outbox.idempotency_key, (ORG, outbox.event_id))
        self.assertEqual(classify_idempotency(None, DIGEST_A), IdempotencyState.NEW)
        self.assertEqual(classify_idempotency(DIGEST_A, DIGEST_A), IdempotencyState.DUPLICATE)
        self.assertEqual(classify_idempotency(DIGEST_A, DIGEST_B), IdempotencyState.CONFLICT)
        processed = inbox.mark_processed("2030-01-01T00:00:01Z")
        published = outbox.mark_published("2030-01-01T00:00:01Z")
        with self.assertRaises(ValueError):
            processed.mark_processed("2030-01-01T00:00:02Z")
        with self.assertRaises(ValueError):
            published.mark_published("2030-01-01T00:00:02Z")

    def test_error_envelope_never_echoes_rejected_input(self) -> None:
        secret = "sensitive-rejected-input"
        error = KnowledgeError("INVALID_REQUEST", "77777777-7777-4777-8777-777777777777")
        self.assertNotIn(secret, json.dumps(error.as_dict()))
        self.assertEqual(set(error.as_dict()), {"schemaVersion", "code", "correlationId", "message"})


class MockTests(unittest.TestCase):
    def test_source_reference_mock_matches_closed_record(self) -> None:
        path = ROOT / "contract-mocks/source-reference.json"
        value = load_mock(path, allowed_fields={"schemaVersion", "organizationId", "sourceId", "sourceVersionDigest", "locatorDigest", "contentDigest", "mediaType", "contentBytes", "observedAt"})
        source = SourceReference(
            value["organizationId"], value["sourceId"], value["sourceVersionDigest"],
            value["locatorDigest"], value["contentDigest"], value["mediaType"],
            value["contentBytes"], value["observedAt"],
        )
        self.assertEqual(source.as_dict(), value)

    def test_all_synthetic_mocks_are_bounded_content_free_json(self) -> None:
        for path in sorted((ROOT / "contract-mocks").glob("*.json")):
            if path.name == "upstream-locks.json":
                continue
            with self.subTest(path=path.name):
                value = load_mock(path)
                self.assertLessEqual(len(canonical_json(value)), 65_536)

    def test_lifecycle_event_matches_the_pinned_closed_envelope(self) -> None:
        event = load_mock(ROOT / "contract-mocks/lifecycle-event.json")
        self.assertEqual(
            set(event),
            {"specversion", "id", "source", "type", "subject", "time", "datacontenttype", "dataschema", "organizationid", "partitionkey", "sequence", "data"},
        )
        self.assertEqual(event["specversion"], "1.0")
        self.assertEqual(event["type"], "harness.evidence.state.changed.v1")
        self.assertEqual(event["data"]["aggregateKind"], "EvidenceRecord")
        self.assertEqual(
            set(event["data"]),
            {"schemaVersion", "aggregateKind", "aggregateId", "aggregateVersion", "actor", "correlationId", "causationId", "reasonCode", "transition", "resourceRefs", "evidenceRefs"},
        )


if __name__ == "__main__":
    unittest.main()
