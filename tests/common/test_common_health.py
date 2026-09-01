from __future__ import annotations

import asyncio
import json
import unittest

from planeon_knowledge.common.asgi import create_health_app
from planeon_knowledge.common.health import DependencyHealth, HealthState, evaluate_readiness
from planeon_knowledge.common.services import SERVICE_DESCRIPTORS

TIME = "2030-01-01T00:00:00Z"
NAMES = ("identity-admission", "policy", "contract-mock", "owned-store", "telemetry")


def probes(states: dict[str, HealthState] | None = None):
    configured = states or {}
    return {
        name: (lambda current=name: DependencyHealth(current, configured.get(current, HealthState.READY), TIME, configured.get(current, HealthState.READY).value))
        for name in NAMES
    }


async def request(app, *, path: str, method: str = "GET", body: bytes = b"", query: bytes = b"", headers=()):
    sent: list[dict[str, object]] = []
    delivered = False

    async def receive():
        nonlocal delivered
        if delivered:
            raise RuntimeError("receive called after final body")
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    await app({"type": "http", "path": path, "method": method, "query_string": query, "headers": headers}, receive, send)
    status = sent[0]["status"]
    payload = json.loads(sent[1]["body"])
    return status, payload


class HealthTests(unittest.TestCase):
    def test_six_service_ownership_descriptors_are_closed(self) -> None:
        self.assertEqual(set(SERVICE_DESCRIPTORS), {"domain-service", "connector-controller", "ingest-worker", "retrieval-service", "index-worker", "memory-service"})
        self.assertEqual({item.owned_schema for item in SERVICE_DESCRIPTORS.values()}, {"domain", "ingestion", "retrieval", "memory"})
        self.assertEqual({item.harness_id for item in SERVICE_DESCRIPTORS.values()}, {"knowledge.domain-semantic", "knowledge.data-integration", "knowledge.retrieval-context", "knowledge.memory-state"})

    def test_readiness_required_dependency_fails_closed(self) -> None:
        state = evaluate_readiness(probes({"policy": HealthState.NOT_READY}))
        self.assertEqual(state.state, HealthState.NOT_READY)
        self.assertEqual(evaluate_readiness({}).state, HealthState.NOT_READY)

    def test_optional_telemetry_is_visible_degradation(self) -> None:
        state = evaluate_readiness(probes({"telemetry": HealthState.DEGRADED}))
        self.assertEqual(state.state, HealthState.DEGRADED)

    def test_probe_exception_fails_closed_without_echo(self) -> None:
        configured = probes()
        configured["owned-store"] = lambda: (_ for _ in ()).throw(RuntimeError("sensitive endpoint"))
        result = evaluate_readiness(configured)
        self.assertEqual(result.state, HealthState.NOT_READY)
        self.assertNotIn("sensitive endpoint", json.dumps(result.as_dict()))

    def test_health_only_asgi_contract(self) -> None:
        for descriptor in SERVICE_DESCRIPTORS.values():
            app = create_health_app(descriptor, probes())
            with self.subTest(service=descriptor.service_name):
                status, body = asyncio.run(request(app, path="/health/live"))
                self.assertEqual((status, body["state"]), (200, "LIVE"))
                status, body = asyncio.run(request(app, path="/health/ready"))
                self.assertEqual((status, body["state"]), (200, "READY"))
                status, body = asyncio.run(request(app, path="/knowledge/v1/retrieve"))
                self.assertEqual((status, body["reasonCode"]), (404, "NOT_FOUND"))

    def test_request_identity_body_query_and_method_are_denied(self) -> None:
        app = create_health_app(SERVICE_DESCRIPTORS["domain-service"], probes())
        vectors = [
            {"path": "/health/ready", "method": "POST"},
            {"path": "/health/ready", "body": b'{"organizationId":"attacker"}'},
            {"path": "/health/ready", "query": b"organizationId=attacker"},
            {"path": "/health/ready", "headers": ((b"x-organization-id", b"attacker"),)},
        ]
        for vector in vectors:
            with self.subTest(vector=vector):
                status, body = asyncio.run(request(app, **vector))
                self.assertEqual((status, body["reasonCode"]), (400, "INVALID_REQUEST"))
                self.assertNotIn("attacker", json.dumps(body))


if __name__ == "__main__":
    unittest.main()
