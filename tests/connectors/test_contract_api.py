from __future__ import annotations

import asyncio
import json
import unittest

from planeon_knowledge.ingestion.asgi import DependencyBundle, IngestionAsgiApplication
from planeon_knowledge.ingestion.contracts import ConnectorKind
from planeon_knowledge.ingestion.service import source_scope_digest

from tests.connectors.support import (
    FixturePort,
    MemoryStagingPort,
    acquire_sample_lease,
    binding,
    domain,
    endpoint,
    identifier,
    identity,
    permit,
    secret,
    service,
    source,
)


def request(application, method: str, path: str, body: dict | None = None, *, headers=None, query: bytes = b""):
    payload = b"" if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    scope = {"type": "http", "method": method, "path": path, "query_string": query, "headers": headers or []}
    messages = [{"type": "http.request", "body": payload, "more_body": False}]
    sent = []

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    asyncio.run(application(scope, receive, send))
    return sent[0]["status"], json.loads(sent[1]["body"])


def source_body(candidate):
    return {
        "sourceId": candidate.source_id,
        "connectorKind": candidate.connector_kind.value,
        "profileDigest": candidate.profile_digest,
        "endpointRefDigest": candidate.endpoint_ref_digest,
        "credentialRefDigest": candidate.credential_ref_digest,
        "networkPolicyDigest": candidate.network_policy_digest,
        "expectedSchemaDigest": candidate.expected_schema_digest,
        "activeDomainVersionDigest": candidate.active_domain_version_digest,
        "semanticMappingDigest": candidate.semantic_mapping_digest,
        "ownerDigest": candidate.owner_digest,
        "classification": candidate.classification.value,
        "residency": list(candidate.residency),
        "maxRecords": candidate.max_records,
        "maxBytes": candidate.max_bytes,
        "deadlineMs": candidate.deadline_ms,
        "createdAt": candidate.created_at,
    }


class IngestionApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.caller = identity()
        self.target = service()
        self.candidate = source(ConnectorKind.HTTP, caller=self.caller)
        self.binding = binding(ConnectorKind.HTTP)
        self.allowed = True
        self.operation = "VALIDATE"
        self.lease = None
        self.dependency_calls = 0
        self.staging = MemoryStagingPort()

        def permit_provider(caller, action, resource):
            return permit(caller, action, resource, allowed=self.allowed)

        def dependency_provider(_caller, source_value, operation):
            self.dependency_calls += 1
            if self.operation == "FAIL":
                raise RuntimeError("private provider detail")
            if operation == "VALIDATE":
                return DependencyBundle(
                    endpoint(source_value, "VALIDATE", self.binding),
                    secret(source_value, "VALIDATE"),
                    domain(source_value),
                    self.binding,
                )
            return DependencyBundle(
                endpoint(source_value, "SAMPLE", self.binding),
                secret(source_value, "SAMPLE"),
                domain(source_value),
                self.binding,
                self.lease,
                FixturePort(ConnectorKind.HTTP),
                self.staging,
            )

        self.application = IngestionAsgiApplication(self.target, lambda _scope: self.caller, permit_provider, dependency_provider)

    def headers(self, key: str | None = None, revision: int | None = None):
        result = [(b"x-correlation-id", identifier(f"api:{key or 'read'}:{revision or 0}").encode("ascii"))]
        if key is not None:
            result.append((b"idempotency-key", key.encode("ascii")))
        if revision is not None:
            result.append((b"if-match", str(revision).encode("ascii")))
        return result

    def test_exact_api_lifecycle_stops_at_staged(self) -> None:
        status, created = request(self.application, "POST", "/knowledge/v1/sources", source_body(self.candidate), headers=self.headers("api-create"))
        self.assertEqual(status, 201)
        self.assertEqual(created["state"], "DECLARED")

        status, fetched = request(self.application, "GET", f"/knowledge/v1/sources/{self.candidate.source_id}", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertEqual(fetched["source"]["sourceId"], self.candidate.source_id)

        status, validated = request(
            self.application,
            "POST",
            f"/knowledge/v1/sources/{self.candidate.source_id}:validate",
            {},
            headers=self.headers("api-validate", 1),
        )
        self.assertEqual(status, 200)
        self.assertEqual(validated["state"], "VALID")

        self.lease = acquire_sample_lease(self.target, self.caller, self.candidate)
        status, batch = request(
            self.application,
            "POST",
            f"/knowledge/v1/sources/{self.candidate.source_id}:sample",
            {},
            headers=self.headers("api-sample", validated["revision"]),
        )
        self.assertEqual(status, 200)
        self.assertEqual(batch["state"], "STAGED")
        self.assertNotIn("payload", str(batch).casefold())

        status, fetched_batch = request(
            self.application,
            "GET",
            f"/knowledge/v1/staged-batches/{batch['batchId']}",
            headers=self.headers(),
        )
        self.assertEqual(status, 200)
        self.assertEqual(fetched_batch["batchDigest"], batch["batchDigest"])

    def test_closed_routes_identity_headers_and_query_strings_fail(self) -> None:
        cases = (
            ("POST", "/knowledge/v1/sources", {**source_body(self.candidate), "url": "https://outside.invalid"}, self.headers("bad-field"), b"", "BODY_INVALID"),
            ("POST", "/knowledge/v1/sources", source_body(self.candidate), [(b"x-tenant-id", b"other"), *self.headers("bad-identity")], b"", "CALLER_IDENTITY_FORBIDDEN"),
            ("GET", f"/knowledge/v1/sources/{self.candidate.source_id}", None, self.headers(), b"tenant=other", "INVALID_REQUEST"),
            ("DELETE", f"/knowledge/v1/sources/{self.candidate.source_id}", None, self.headers(), b"", "ROUTE_NOT_FOUND"),
        )
        for method, path, body, headers, query, code in cases:
            with self.subTest(code=code):
                status, response = request(self.application, method, path, body, headers=headers, query=query)
                self.assertEqual(status, 400 if code != "ROUTE_NOT_FOUND" else 404)
                self.assertEqual(response["code"], code)
                self.assertEqual(response["message"], "Request could not be processed.")

    def test_policy_denial_precedes_owned_state_and_dependency_access(self) -> None:
        status, _created = request(self.application, "POST", "/knowledge/v1/sources", source_body(self.candidate), headers=self.headers("create-deny-test"))
        self.assertEqual(status, 201)
        self.allowed = False
        before = self.target.store.snapshot()
        status, response = request(
            self.application,
            "POST",
            f"/knowledge/v1/sources/{self.candidate.source_id}:validate",
            {},
            headers=self.headers("denied-validate", 1),
        )
        self.assertEqual(status, 404)
        self.assertEqual(response["code"], "POLICY_DENIED")
        self.assertEqual(self.dependency_calls, 0)
        self.assertEqual(self.target.store.snapshot(), before)

    def test_dependency_exception_is_stable_and_non_echoing(self) -> None:
        status, _created = request(self.application, "POST", "/knowledge/v1/sources", source_body(self.candidate), headers=self.headers("create-provider-test"))
        self.assertEqual(status, 201)
        self.operation = "FAIL"
        status, response = request(
            self.application,
            "POST",
            f"/knowledge/v1/sources/{self.candidate.source_id}:validate",
            {},
            headers=self.headers("provider-fail", 1),
        )
        self.assertEqual(status, 503)
        self.assertEqual(response["code"], "DEPENDENCY_UNAVAILABLE")
        self.assertNotIn("private provider detail", str(response))


if __name__ == "__main__":
    unittest.main()
