"""Dependency-injected, health-only ASGI application."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from .canonical import canonical_json
from .health import HealthState, Probe, evaluate_readiness
from .services import ServiceDescriptor

Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
CALLER_IDENTITY_HEADERS = {
    b"x-organization-id",
    b"x-tenant-id",
    b"x-subject-id",
    b"x-user-id",
}


async def _body(receive: Receive) -> bytes:
    result = bytearray()
    while True:
        message = await receive()
        if message.get("type") != "http.request":
            raise ValueError("unexpected ASGI message")
        result.extend(message.get("body", b""))
        if len(result) > 65_536:
            raise ValueError("body is oversized")
        if not message.get("more_body", False):
            return bytes(result)


async def _respond(send: Send, status: int, value: Mapping[str, object]) -> None:
    payload = canonical_json(value)
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                [b"content-type", b"application/json"],
                [b"content-length", str(len(payload)).encode("ascii")],
                [b"cache-control", b"no-store"],
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


def create_health_app(descriptor: ServiceDescriptor, probes: Mapping[str, Probe]):
    async def application(scope: dict[str, Any], receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            raise RuntimeError("only HTTP ASGI scopes are supported")
        headers = {bytes(name).lower(): bytes(value) for name, value in scope.get("headers", ())}
        invalid = (
            scope.get("method") != "GET"
            or scope.get("query_string", b"") != b""
            or any(name in headers for name in CALLER_IDENTITY_HEADERS)
        )
        try:
            body = await _body(receive)
        except Exception:
            await _respond(send, 400, {"schemaVersion": "planeon.knowledge.health/v1", "state": "NOT_READY", "reasonCode": "INVALID_REQUEST"})
            return
        if invalid or body:
            await _respond(send, 400, {"schemaVersion": "planeon.knowledge.health/v1", "state": "NOT_READY", "reasonCode": "INVALID_REQUEST"})
            return
        common = {
            "schemaVersion": "planeon.knowledge.health/v1",
            "service": descriptor.service_name,
            "harness": descriptor.harness_id,
        }
        if scope.get("path") == "/health/live":
            await _respond(send, 200, {**common, "state": "LIVE"})
            return
        if scope.get("path") == "/health/ready":
            readiness = evaluate_readiness(probes)
            status = 200 if readiness.state in {HealthState.READY, HealthState.DEGRADED} else 503
            await _respond(send, status, {**common, **readiness.as_dict()})
            return
        await _respond(send, 404, {**common, "state": "NOT_READY", "reasonCode": "NOT_FOUND"})

    return application


def closed_failure_probes() -> dict[str, Probe]:
    """Default service state: no external dependency is assumed available."""

    def unavailable(name: str):
        def probe():
            raise RuntimeError(f"{name} is not injected")

        return probe

    return {
        name: unavailable(name)
        for name in ("identity-admission", "policy", "contract-mock", "owned-store", "telemetry")
    }
