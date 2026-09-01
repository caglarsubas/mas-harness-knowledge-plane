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
from .readiness import MeasurementObservation, OwnerApprovalAttestation, ReadinessPolicyObservation
from .service import (
    IngestionFailure,
    IngestionService,
    ReadinessService,
    assessment_scope_digest,
    batch_scope_digest,
    dead_letter_scope_digest,
    readiness_scope_digest,
    source_scope_digest,
)

Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
IdentityProvider = Callable[[dict[str, Any]], TenantIdentity]
PermitProvider = Callable[[TenantIdentity, str, str], AccessPermit]
DependencyProvider = Callable[[TenantIdentity, SourceDefinition, str], "DependencyBundle"]
ReadinessDependencyProvider = Callable[[TenantIdentity, str, str], "ReadinessDependencyBundle"]
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
STABLE_ID = r"[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+"
SOURCE_PATH = re.compile(rf"^/knowledge/v1/sources/({UUID})(?::(validate|sample|revoke))?$")
SOURCE_READINESS_PATH = re.compile(rf"^/knowledge/v1/sources/({UUID})/readiness$")
BATCH_PATH = re.compile(rf"^/knowledge/v1/staged-batches/({UUID})(?::(assess|commit))?$")
ASSESSMENT_PATH = re.compile(rf"^/knowledge/v1/readiness-assessments/({STABLE_ID})$")
DEAD_LETTER_PATH = re.compile(rf"^/knowledge/v1/dead-letters/({UUID})(?::(review))?$")
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


@dataclass(frozen=True, slots=True)
class ReadinessDependencyBundle:
    policy: ReadinessPolicyObservation | None = None
    observation: MeasurementObservation | None = None
    approval: OwnerApprovalAttestation | None = None


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
    value = _text_header(headers, b"if-match", required=False)
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
        readiness_service: ReadinessService | None = None,
        readiness_dependency_provider: ReadinessDependencyProvider | None = None,
    ) -> None:
        self.service = service
        self.identity_provider = identity_provider
        self.permit_provider = permit_provider
        self.dependency_provider = dependency_provider
        self.readiness_service = readiness_service
        self.readiness_dependency_provider = readiness_dependency_provider

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
                if method == "POST" and action == "revoke":
                    if self.readiness_service is None:
                        raise IngestionFailure("DEPENDENCY_UNAVAILABLE")
                    if idempotency_key is None:
                        raise IngestionFailure("IDEMPOTENCY_KEY_REQUIRED")
                    _json(body, set())
                    expected_revision = _revision(headers)
                    action_name = "knowledge.ingestion.source.revoke"
                    scope_digest = readiness_scope_digest(identity.organization_id, source_id)
                    permit = self.permit_provider(identity, action_name, scope_digest)
                    result = self.readiness_service.revoke_source(
                        identity,
                        permit,
                        source_id,
                        expected_readiness_revision=expected_revision,
                        idempotency_key=idempotency_key,
                        correlation_id=correlation_id,
                    )
                    await _send(send, 200, public_dict(result))
                    return
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

            source_readiness_match = SOURCE_READINESS_PATH.fullmatch(path)
            if source_readiness_match:
                if method != "GET" or body:
                    raise IngestionFailure("BODY_FORBIDDEN" if method == "GET" else "ROUTE_NOT_FOUND")
                if self.readiness_service is None:
                    raise IngestionFailure("DEPENDENCY_UNAVAILABLE")
                source_id = source_readiness_match.group(1)
                action_name = "knowledge.ingestion.readiness.read"
                scope_digest = readiness_scope_digest(identity.organization_id, source_id)
                permit = self.permit_provider(identity, action_name, scope_digest)
                effective_state, revision = self.readiness_service.get_source_readiness(
                    identity,
                    permit,
                    source_id,
                )
                await _send(
                    send,
                    200,
                    {
                        "schemaVersion": "planeon.knowledge.ingestion.readiness/v1",
                        "effectiveState": effective_state,
                        "revision": None if revision is None else public_dict(revision),
                    },
                )
                return

            batch_match = BATCH_PATH.fullmatch(path)
            if batch_match:
                batch_id, action = batch_match.groups()
                if method == "GET" and action is None:
                    if body:
                        raise IngestionFailure("BODY_FORBIDDEN")
                    permit = self.permit_provider(identity, "knowledge.ingestion.staged-batch.read", batch_scope_digest(identity.organization_id, batch_id))
                    result = self.service.get_staged_batch(identity, permit, batch_id)
                    await _send(send, 200, public_dict(result))
                    return
                if method != "POST" or action not in {"assess", "commit"}:
                    raise IngestionFailure("ROUTE_NOT_FOUND")
                if self.readiness_service is None or self.readiness_dependency_provider is None:
                    raise IngestionFailure("DEPENDENCY_UNAVAILABLE")
                if idempotency_key is None:
                    raise IngestionFailure("IDEMPOTENCY_KEY_REQUIRED")
                _json(body, set())
                if action == "assess":
                    action_name = "knowledge.ingestion.staged-batch.assess"
                    scope_digest = batch_scope_digest(identity.organization_id, batch_id)
                    permit = self.permit_provider(identity, action_name, scope_digest)
                    self.readiness_service.authorize_scope(identity, permit, action_name, scope_digest)
                    dependencies = self.readiness_dependency_provider(identity, batch_id, "ASSESS")
                    if dependencies.policy is None or dependencies.observation is None:
                        raise IngestionFailure("DEPENDENCY_UNAVAILABLE")
                    result = self.readiness_service.request_assessment(
                        identity,
                        permit,
                        batch_id,
                        policy=dependencies.policy,
                        observation=dependencies.observation,
                        idempotency_key=idempotency_key,
                        correlation_id=correlation_id,
                    )
                    await _send(send, 202, public_dict(result))
                    return
                expected_revision = _revision(headers)
                action_name = "knowledge.ingestion.batch.commit"
                scope_digest = batch_scope_digest(identity.organization_id, batch_id)
                permit = self.permit_provider(identity, action_name, scope_digest)
                self.readiness_service.authorize_scope(identity, permit, action_name, scope_digest)
                dependencies = self.readiness_dependency_provider(identity, batch_id, "COMMIT")
                if dependencies.approval is None:
                    raise IngestionFailure("DEPENDENCY_UNAVAILABLE")
                result = self.readiness_service.commit_batch(
                    identity,
                    permit,
                    batch_id,
                    expected_readiness_revision=expected_revision,
                    approval=dependencies.approval,
                    idempotency_key=idempotency_key,
                    correlation_id=correlation_id,
                )
                await _send(send, 200, public_dict(result))
                return

            assessment_match = ASSESSMENT_PATH.fullmatch(path)
            if assessment_match:
                if method != "GET" or body:
                    raise IngestionFailure("BODY_FORBIDDEN" if method == "GET" else "ROUTE_NOT_FOUND")
                if self.readiness_service is None:
                    raise IngestionFailure("DEPENDENCY_UNAVAILABLE")
                assessment_id = assessment_match.group(1)
                action_name = "knowledge.ingestion.readiness.read"
                scope_digest = assessment_scope_digest(identity.organization_id, assessment_id)
                permit = self.permit_provider(identity, action_name, scope_digest)
                result = self.readiness_service.get_assessment(identity, permit, assessment_id)
                await _send(send, 200, result.public_document())
                return

            dead_letter_match = DEAD_LETTER_PATH.fullmatch(path)
            if dead_letter_match:
                if self.readiness_service is None:
                    raise IngestionFailure("DEPENDENCY_UNAVAILABLE")
                dead_letter_id, action = dead_letter_match.groups()
                scope_digest = dead_letter_scope_digest(identity.organization_id, dead_letter_id)
                if method == "GET" and action is None:
                    if body:
                        raise IngestionFailure("BODY_FORBIDDEN")
                    action_name = "knowledge.ingestion.dead-letter.read"
                    permit = self.permit_provider(identity, action_name, scope_digest)
                    result = self.readiness_service.get_dead_letter(identity, permit, dead_letter_id)
                    await _send(send, 200, public_dict(result))
                    return
                if method != "POST" or action != "review":
                    raise IngestionFailure("ROUTE_NOT_FOUND")
                if idempotency_key is None:
                    raise IngestionFailure("IDEMPOTENCY_KEY_REQUIRED")
                value = _json(body, {"decision", "reasonCode"})
                if set(value) != {"decision", "reasonCode"}:
                    raise IngestionFailure("BODY_INVALID")
                action_name = "knowledge.ingestion.dead-letter.review"
                permit = self.permit_provider(identity, action_name, scope_digest)
                result = self.readiness_service.review_dead_letter(
                    identity,
                    permit,
                    dead_letter_id,
                    decision=value["decision"],
                    reason_code=value["reasonCode"],
                    idempotency_key=idempotency_key,
                    correlation_id=correlation_id,
                )
                await _send(send, 200, public_dict(result))
                return

            raise IngestionFailure("ROUTE_NOT_FOUND")
        except IngestionFailure as exc:
            status = (
                404
                if exc.reason_code
                in {
                    "POLICY_DENIED",
                    "SOURCE_NOT_FOUND",
                    "STAGED_BATCH_NOT_FOUND",
                    "ASSESSMENT_NOT_FOUND",
                    "DEAD_LETTER_NOT_FOUND",
                    "WORK_NOT_FOUND",
                    "ROUTE_NOT_FOUND",
                }
                else 409
                if exc.reason_code
                in {
                    "STALE_REVISION",
                    "WORK_STALE_REVISION",
                    "WORK_FENCE_MISMATCH",
                    "IDEMPOTENCY_CONFLICT",
                    "TRANSITION_FORBIDDEN",
                    "DUPLICATE_STAGED_BATCH",
                    "BATCH_ALREADY_COMMITTED",
                    "BATCH_STATE_CHANGED",
                    "SOURCE_NOT_READY_FOR_APPROVAL",
                    "SOURCE_REVOKED",
                }
                else 503
                if exc.reason_code
                in {
                    "DEPENDENCY_UNAVAILABLE",
                    "CONNECTOR_DEPENDENCY_UNAVAILABLE",
                    "POLICY_DEPENDENCY_UNAVAILABLE",
                    "MEASUREMENT_DEPENDENCY_UNAVAILABLE",
                }
                else 400
            )
            await _send(send, status, {"schemaVersion": "planeon.knowledge.error/v1", "code": exc.reason_code, "message": "Request could not be processed."})
        except (KeyError, TypeError, ValueError):
            await _send(send, 400, {"schemaVersion": "planeon.knowledge.error/v1", "code": "CONTRACT_INVALID", "message": "Request could not be processed."})
        except Exception:
            await _send(send, 503, {"schemaVersion": "planeon.knowledge.error/v1", "code": "DEPENDENCY_UNAVAILABLE", "message": "Request could not be processed."})
