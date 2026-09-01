"""Closed standard-library ASGI adapter for connector declaration and staging."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from planeon_knowledge.common.canonical import canonical_json, parse_closed_json
from planeon_knowledge.common.models import TenantIdentity

from .batch import StagingPort
from .connectors import Binding, ConnectorPort
from .contracts import (
    AccessPermit,
    Classification,
    ConnectorKind,
    DomainBindingObservation,
    EndpointGrant,
    LeaseRevision,
    SecretGrant,
    SourceDefinition,
    public_dict,
)
from .service import IngestionFailure, IngestionService, batch_scope_digest, source_scope_digest

Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
IdentityProvider = Callable[[dict[str, Any]], TenantIdentity]
PermitProvider = Callable[[TenantIdentity, str, str], AccessPermit]
DependencyProvider = Callable[[TenantIdentity, SourceDefinition, str], "DependencyBundle"]
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
SOURCE_PATH = re.compile(rf"^/knowledge/v1/sources/({UUID})(?::(validate|sample))?$")
BATCH_PATH = re.compile(rf"^/knowledge/v1/staged-batches/({UUID})$")
FORBIDDEN_IDENTITY_HEADERS = {b"x-organization-id", b"x-tenant-id", b"x-subject-id", b"x-user-id"}


@dataclass(frozen=True, slots=True)
class DependencyBundle:
    endpoint: EndpointGrant
    secret: SecretGrant | None
    domain: DomainBindingObservation
    binding: Binding
    lease: LeaseRevision | None = None
    port: ConnectorPort | None = None
    staging_port: StagingPort | None = None
    parameters: object | None = None
    checkpoint: str | None = None


async def _read_body(receive: Receive) -> bytes:
    data = bytearray()
    while True:
        message = await receive()
        if message.get("type") != "http.request":
            raise IngestionFailure("INVALID_REQUEST")
        data.extend(message.get("body", b""))
        if len(data) > 65_536:
            raise IngestionFailure("REQUEST_TOO_LARGE")
        if not message.get("more_body", False):
            return bytes(data)


async def _send(send: Send, status: int, body: dict[str, Any]) -> None:
    payload = canonical_json(body)
    await send({"type": "http.response.start", "status": status, "headers": [[b"content-type", b"application/json"], [b"content-length", str(len(payload)).encode("ascii")], [b"cache-control", b"no-store"]]})
    await send({"type": "http.response.body", "body": payload})


def _headers(scope: dict[str, Any]) -> dict[bytes, bytes]:
    result: dict[bytes, bytes] = {}
    for raw_name, raw_value in scope.get("headers", ()):
        name = bytes(raw_name).lower()
        if name in result:
            raise IngestionFailure("DUPLICATE_HEADER")
        result[name] = bytes(raw_value)
    if set(result) & FORBIDDEN_IDENTITY_HEADERS:
        raise IngestionFailure("CALLER_IDENTITY_FORBIDDEN")
    return result


def _text_header(headers: dict[bytes, bytes], name: bytes, *, required: bool = True) -> str | None:
    raw = headers.get(name)
    if raw is None:
        if required:
            raise IngestionFailure("REQUIRED_HEADER_MISSING")
        return None
    try:
        value = raw.decode("ascii", errors="strict")
    except UnicodeError as exc:
        raise IngestionFailure("HEADER_INVALID") from exc
    if not value or len(value) > 128 or any(character in value for character in "\r\n\x00"):
        raise IngestionFailure("HEADER_INVALID")
    return value


def _revision(headers: dict[bytes, bytes]) -> int:
    value = _text_header(headers, b"if-match")
    if value is None or not value.isdigit() or int(value) < 1:
        raise IngestionFailure("IF_MATCH_INVALID")
    return int(value)


def _json(raw: bytes, fields: set[str]) -> dict[str, Any]:
    if not raw:
        if fields:
            raise IngestionFailure("BODY_REQUIRED")
        return {}
    try:
        return parse_closed_json(raw, allowed_fields=fields)
    except ValueError as exc:
        raise IngestionFailure("BODY_INVALID") from exc


class IngestionAsgiApplication:
    def __init__(
        self,
        service: IngestionService,
        identity_provider: IdentityProvider,
        permit_provider: PermitProvider,
        dependency_provider: DependencyProvider,
    ) -> None:
        self.service = service
        self.identity_provider = identity_provider
        self.permit_provider = permit_provider
        self.dependency_provider = dependency_provider

    def _source(self, identity: TenantIdentity, source_id: str) -> SourceDefinition:
        source = self.service.store.read(lambda state: state.sources.get((identity.organization_id, source_id)))
        if source is None:
            raise IngestionFailure("SOURCE_NOT_FOUND")
        return source

    async def __call__(self, scope: dict[str, Any], receive: Receive, send: Send) -> None:
        try:
            if scope.get("type") != "http" or scope.get("query_string", b""):
                raise IngestionFailure("INVALID_REQUEST")
            headers = _headers(scope)
            identity = self.identity_provider(scope)
            method = scope.get("method")
            path = scope.get("path", "")
            body = await _read_body(receive)
            correlation_id = _text_header(headers, b"x-correlation-id")
            idempotency_key = _text_header(headers, b"idempotency-key", required=False)

            if method == "POST" and path == "/knowledge/v1/sources":
                if idempotency_key is None:
                    raise IngestionFailure("IDEMPOTENCY_KEY_REQUIRED")
                value = _json(body, {
                    "sourceId", "connectorKind", "profileDigest", "endpointRefDigest",
                    "credentialRefDigest", "networkPolicyDigest", "expectedSchemaDigest",
                    "activeDomainVersionDigest", "semanticMappingDigest", "ownerDigest",
                    "classification", "residency", "maxRecords", "maxBytes",
                    "deadlineMs", "createdAt",
                })
                if not isinstance(value["residency"], list):
                    raise IngestionFailure("BODY_INVALID")
                source = SourceDefinition(
                    identity.organization_id,
                    value["sourceId"],
                    ConnectorKind(value["connectorKind"]),
                    value["profileDigest"],
                    value["endpointRefDigest"],
                    value["credentialRefDigest"],
                    value["networkPolicyDigest"],
                    value["expectedSchemaDigest"],
                    value["activeDomainVersionDigest"],
                    value["semanticMappingDigest"],
                    value["ownerDigest"],
                    Classification(value["classification"]),
                    tuple(value["residency"]),
                    value["maxRecords"],
                    value["maxBytes"],
                    value["deadlineMs"],
                    value["createdAt"],
                    identity.subject_id,
                )
                permit = self.permit_provider(identity, "knowledge.ingestion.source.create", source.resource_digest)
                result = self.service.create_source(identity, permit, source, idempotency_key=idempotency_key, correlation_id=correlation_id)
                await _send(send, 201, public_dict(result))
                return

            source_match = SOURCE_PATH.fullmatch(path)
            if source_match:
                source_id, action = source_match.groups()
                scope_digest = source_scope_digest(identity.organization_id, source_id)
                if method == "GET" and action is None:
                    if body:
                        raise IngestionFailure("BODY_FORBIDDEN")
                    permit = self.permit_provider(identity, "knowledge.ingestion.source.read", scope_digest)
                    source, revision = self.service.get_source(identity, permit, source_id)
                    await _send(send, 200, {"schemaVersion": "planeon.knowledge.ingestion/v1", "source": public_dict(source), "revision": public_dict(revision)})
                    return
                if method != "POST" or action not in {"validate", "sample"}:
                    raise IngestionFailure("ROUTE_NOT_FOUND")
                if idempotency_key is None:
                    raise IngestionFailure("IDEMPOTENCY_KEY_REQUIRED")
                _json(body, set())
                expected_revision = _revision(headers)
                action_name = f"knowledge.ingestion.source.{action}"
                permit = self.permit_provider(identity, action_name, scope_digest)
                self.service.authorize_scope(identity, permit, action_name, scope_digest)
                source = self._source(identity, source_id)
                dependencies = self.dependency_provider(identity, source, action.upper())
                if action == "validate":
                    result = self.service.validate_source(
                        identity,
                        permit,
                        source_id,
                        expected_revision=expected_revision,
                        endpoint=dependencies.endpoint,
                        secret=dependencies.secret,
                        domain=dependencies.domain,
                        binding=dependencies.binding,
                        idempotency_key=idempotency_key,
                        correlation_id=correlation_id,
                    )
                    await _send(send, 200, public_dict(result))
                    return
                if dependencies.lease is None or dependencies.port is None or dependencies.staging_port is None:
                    raise IngestionFailure("DEPENDENCY_UNAVAILABLE")
                result = self.service.sample_source(
                    identity,
                    permit,
                    source_id,
                    expected_revision=expected_revision,
                    endpoint=dependencies.endpoint,
                    secret=dependencies.secret,
                    domain=dependencies.domain,
                    binding=dependencies.binding,
                    lease=dependencies.lease,
                    port=dependencies.port,
                    staging_port=dependencies.staging_port,
                    parameters=dependencies.parameters,
                    checkpoint=dependencies.checkpoint,
                    idempotency_key=idempotency_key,
                    correlation_id=correlation_id,
                )
                await _send(send, 200, public_dict(result))
                return

            batch_match = BATCH_PATH.fullmatch(path)
            if batch_match and method == "GET":
                if body:
                    raise IngestionFailure("BODY_FORBIDDEN")
                batch_id = batch_match.group(1)
                permit = self.permit_provider(identity, "knowledge.ingestion.staged-batch.read", batch_scope_digest(identity.organization_id, batch_id))
                result = self.service.get_staged_batch(identity, permit, batch_id)
                await _send(send, 200, public_dict(result))
                return
            raise IngestionFailure("ROUTE_NOT_FOUND")
        except IngestionFailure as exc:
            status = 404 if exc.reason_code in {"POLICY_DENIED", "SOURCE_NOT_FOUND", "STAGED_BATCH_NOT_FOUND", "ROUTE_NOT_FOUND"} else 409 if exc.reason_code in {"STALE_REVISION", "IDEMPOTENCY_CONFLICT", "TRANSITION_FORBIDDEN", "DUPLICATE_STAGED_BATCH"} else 503 if exc.reason_code in {"DEPENDENCY_UNAVAILABLE", "CONNECTOR_DEPENDENCY_UNAVAILABLE"} else 400
            await _send(send, status, {"schemaVersion": "planeon.knowledge.error/v1", "code": exc.reason_code, "message": "Request could not be processed."})
        except (KeyError, TypeError, ValueError):
            await _send(send, 400, {"schemaVersion": "planeon.knowledge.error/v1", "code": "CONTRACT_INVALID", "message": "Request could not be processed."})
        except Exception:
            await _send(send, 503, {"schemaVersion": "planeon.knowledge.error/v1", "code": "DEPENDENCY_UNAVAILABLE", "message": "Request could not be processed."})
