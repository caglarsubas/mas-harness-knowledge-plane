from __future__ import annotations

import asyncio
import json
import unittest

from planeon_knowledge.domain.asgi import DomainAsgiApplication

from support import (
    DOMAIN_ID,
    approve_and_publish,
    create_and_validate_version,
    create_domain,
    identifier,
    identity,
    permit,
    service,
    version,
)


def request(application, method: str, path: str, body: dict | None = None, *, headers: list[tuple[bytes, bytes]] | None = None, query: bytes = b""):
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


class DomainApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = identity()
        self.service = service()
        self.allowed = True

        def permit_provider(caller, action, resource):
            return permit(caller, action, resource, allowed=self.allowed)

        self.application = DomainAsgiApplication(self.service, lambda _scope: self.identity, permit_provider)
        self.command_headers = [
            (b"idempotency-key", b"api-command"),
            (b"x-correlation-id", identifier("api-correlation").encode("ascii")),
        ]

    def test_create_domain_and_list_versions(self) -> None:
        body = {
            "domainId": DOMAIN_ID,
            "displayName": "White goods enterprise quality",
            "defaultLanguage": "en",
            "supportedLanguages": ["en", "tr"],
            "businessOwnerIds": ["business-owner"],
            "dataOwnerIds": ["data-owner"],
            "compatibilityMode": "BACKWARD",
            "createdAt": "2026-01-01T00:00:00Z",
        }
        status, response = request(self.application, "POST", "/knowledge/v1/domains", body, headers=self.command_headers)
        self.assertEqual(status, 201)
        self.assertEqual(response["domainId"], DOMAIN_ID)
        resource_headers = [(b"x-correlation-id", identifier("api-list").encode("ascii"))]
        status, response = request(self.application, "GET", f"/knowledge/v1/domains/{DOMAIN_ID}/versions", headers=resource_headers)
        self.assertEqual(status, 200)
        self.assertEqual(response["items"], [])

    def test_resolve_is_a_policy_checked_read_without_mutation_headers(self) -> None:
        create_domain(self.service, self.identity)
        candidate = version()
        create_and_validate_version(self.service, self.identity, candidate)
        approve_and_publish(self.service, self.identity, candidate)
        headers = [(b"x-correlation-id", identifier("api-resolve").encode("ascii"))]
        status, response = request(
            self.application,
            "POST",
            f"/knowledge/v1/domains/{DOMAIN_ID}/versions/1.0.0:resolve",
            {"term": f"urn:planeon:{DOMAIN_ID}:CriticalToQuality"},
            headers=headers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(response["domainVersionDigest"], candidate.resource_digest)

    def test_identity_query_unknown_and_duplicate_input_fail_closed(self) -> None:
        body = {"domainId": DOMAIN_ID}
        cases = [
            ([(b"x-organization-id", self.identity.organization_id.encode("ascii")), *self.command_headers], b"", "CALLER_IDENTITY_FORBIDDEN"),
            (self.command_headers, b"tenant=other", "INVALID_REQUEST"),
            ([*self.command_headers, (b"idempotency-key", b"duplicate")], b"", "DUPLICATE_HEADER"),
        ]
        for headers, query, code in cases:
            with self.subTest(code=code):
                status, response = request(self.application, "POST", "/knowledge/v1/domains", body, headers=headers, query=query)
                self.assertEqual(status, 400)
                self.assertEqual(response["code"], code)
                self.assertNotIn(self.identity.organization_id, str(response))

    def test_policy_deny_is_non_disclosing(self) -> None:
        create_domain(self.service, self.identity)
        self.allowed = False
        headers = [(b"x-correlation-id", identifier("api-deny").encode("ascii"))]
        status, response = request(self.application, "GET", f"/knowledge/v1/domains/{DOMAIN_ID}/versions", headers=headers)
        self.assertEqual(status, 404)
        self.assertEqual(response["code"], "POLICY_DENIED")
        self.assertEqual(response["message"], "Request could not be processed.")

    def test_mapping_assertion_objects_are_closed(self) -> None:
        bad = {
            "mappingId": "white-goods.quality-mapping",
            "version": "1.0.0",
            "domainVersionDigest": "sha256:" + "1" * 64,
            "sourceSchemaDigest": "sha256:" + "2" * 64,
            "assertions": [{
                "sourceFieldDigest": "sha256:" + "3" * 64,
                "targetTerm": f"urn:planeon:{DOMAIN_ID}:CriticalToQuality",
                "transformationKind": "DIRECT",
                "provenanceDigests": ["sha256:" + "4" * 64],
                "rawFieldName": "serial_number",
            }],
            "ownersDigest": "sha256:" + "5" * 64,
            "createdAt": "2026-01-01T00:00:00Z",
        }
        status, response = request(self.application, "POST", "/knowledge/v1/mappings:validate", bad, headers=self.command_headers)
        self.assertEqual(status, 400)
        self.assertEqual(response["code"], "BODY_INVALID")
        self.assertNotIn("serial_number", str(response))


if __name__ == "__main__":
    unittest.main()
