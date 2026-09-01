"""Closed standard-library ASGI adapter for the domain service."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from typing import Any

from planeon_knowledge.common.canonical import canonical_digest, canonical_json, parse_closed_json
from planeon_knowledge.common.models import TenantIdentity

from .contracts import (
    ApprovalAttestation,
    CompatibilityMode,
    Decision,
    DomainDefinition,
    DomainVersion,
    MappingAssertion,
    PolicyPermit,
    SemanticMapping,
    TransformationKind,
    public_dict,
)
from .service import DomainFailure, DomainService

Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
IdentityProvider = Callable[[dict[str, Any]], TenantIdentity]
PermitProvider = Callable[[TenantIdentity, str, str], PolicyPermit]
VERSION_PATH = re.compile(r"^/knowledge/v1/domains/([a-z][a-z0-9.-]{2,127})/versions/([^/:]+)(?::(validate|request-approval|record-decision|publish|rollback|resolve)|/(report))?$")
LIST_PATH = re.compile(r"^/knowledge/v1/domains/([a-z][a-z0-9.-]{2,127})/versions$")
FORBIDDEN_IDENTITY_HEADERS = {b"x-organization-id", b"x-tenant-id", b"x-subject-id", b"x-user-id"}


async def _read_body(receive: Receive) -> bytes:
    data = bytearray()
    while True:
        message = await receive()
        if message.get("type") != "http.request":
            raise DomainFailure("INVALID_REQUEST")
        data.extend(message.get("body", b""))
        if len(data) > 65_536:
            raise DomainFailure("REQUEST_TOO_LARGE")
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
            raise DomainFailure("DUPLICATE_HEADER")
        result[name] = bytes(raw_value)
    if set(result) & FORBIDDEN_IDENTITY_HEADERS:
        raise DomainFailure("CALLER_IDENTITY_FORBIDDEN")
    return result


def _text_header(headers: dict[bytes, bytes], name: bytes, *, required: bool = True) -> str | None:
    raw = headers.get(name)
    if raw is None:
        if required:
            raise DomainFailure("REQUIRED_HEADER_MISSING")
        return None
    try:
        value = raw.decode("ascii", errors="strict")
    except UnicodeError as exc:
        raise DomainFailure("HEADER_INVALID") from exc
    if not value or len(value) > 128 or any(character in value for character in "\r\n\x00"):
        raise DomainFailure("HEADER_INVALID")
    return value


def _revision(headers: dict[bytes, bytes]) -> int:
    value = _text_header(headers, b"if-match")
    if value is None or not value.isdigit() or int(value) < 1:
        raise DomainFailure("IF_MATCH_INVALID")
    return int(value)


def _json(raw: bytes, fields: set[str]) -> dict[str, Any]:
    if not raw:
        if fields:
            raise DomainFailure("BODY_REQUIRED")
        return {}
    try:
        return parse_closed_json(raw, allowed_fields=fields)
    except ValueError as exc:
        raise DomainFailure("BODY_INVALID") from exc


def _mapping_assertions(value: object) -> tuple[MappingAssertion, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= 512:
        raise DomainFailure("BODY_INVALID")
    assertions: list[MappingAssertion] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"sourceFieldDigest", "targetTerm", "transformationKind", "provenanceDigests"}:
            raise DomainFailure("BODY_INVALID")
        provenance = item["provenanceDigests"]
        if not isinstance(provenance, list):
            raise DomainFailure("BODY_INVALID")
        assertions.append(MappingAssertion(item["sourceFieldDigest"], item["targetTerm"], TransformationKind(item["transformationKind"]), tuple(sorted(provenance))))
    return tuple(sorted(assertions, key=lambda item: (item.source_field_digest, item.target_term, item.transformation_kind.value, item.provenance_digests)))


class DomainAsgiApplication:
    def __init__(self, service: DomainService, identity_provider: IdentityProvider, permit_provider: PermitProvider) -> None:
        self.service = service
        self.identity_provider = identity_provider
        self.permit_provider = permit_provider

    def _version_resource(self, identity: TenantIdentity, domain_id: str, version_text: str) -> str:
        version = self.service.store.read(lambda state: state.versions.get((identity.organization_id, domain_id, version_text)))
        if version is None:
            raise DomainFailure("VERSION_NOT_FOUND")
        return version.resource_digest

    async def __call__(self, scope: dict[str, Any], receive: Receive, send: Send) -> None:
        try:
            if scope.get("type") != "http" or scope.get("query_string", b""):
                raise DomainFailure("INVALID_REQUEST")
            headers = _headers(scope)
            identity = self.identity_provider(scope)
            method = scope.get("method")
            path = scope.get("path", "")
            body = await _read_body(receive)
            correlation_id = _text_header(headers, b"x-correlation-id")
            idempotency_key = _text_header(headers, b"idempotency-key", required=False)

            if method == "POST" and path == "/knowledge/v1/domains":
                if idempotency_key is None:
                    raise DomainFailure("IDEMPOTENCY_KEY_REQUIRED")
                value = _json(body, {"domainId", "displayName", "defaultLanguage", "supportedLanguages", "businessOwnerIds", "dataOwnerIds", "compatibilityMode", "createdAt"})
                definition = DomainDefinition(identity.organization_id, value["domainId"], value["displayName"], value["defaultLanguage"], tuple(value["supportedLanguages"]), tuple(value["businessOwnerIds"]), tuple(value["dataOwnerIds"]), CompatibilityMode(value["compatibilityMode"]), value["createdAt"], identity.subject_id)
                request_digest = canonical_digest(public_dict(definition))
                result = self.service.create_domain(identity, self.permit_provider(identity, "knowledge.domain.create", request_digest), definition, idempotency_key=idempotency_key, correlation_id=correlation_id)
                await _send(send, 201, public_dict(result))
                return

            list_match = LIST_PATH.fullmatch(path)
            if list_match and method == "GET":
                if body:
                    raise DomainFailure("BODY_FORBIDDEN")
                domain_id = list_match.group(1)
                resource = canonical_digest({"organizationId": identity.organization_id, "domainId": domain_id})
                result = self.service.list_versions(identity, self.permit_provider(identity, "knowledge.domain.read", resource), domain_id)
                await _send(send, 200, {"schemaVersion": "planeon.knowledge.domain/v1", "items": [public_dict(item) for item in result]})
                return
            if list_match and method == "POST":
                if idempotency_key is None:
                    raise DomainFailure("IDEMPOTENCY_KEY_REQUIRED")
                domain_id = list_match.group(1)
                value = _json(body, {"version", "packageDigest", "ontologyDigest", "shapesDigest", "importManifestDigest", "ownersDigest", "createdAt"})
                version = DomainVersion(identity.organization_id, domain_id, value["version"], value["packageDigest"], value["ontologyDigest"], value["shapesDigest"], value["importManifestDigest"], value["ownersDigest"], value["createdAt"], identity.subject_id)
                result = self.service.create_version(identity, self.permit_provider(identity, "knowledge.domain.version.create", version.resource_digest), version, idempotency_key=idempotency_key, correlation_id=correlation_id)
                await _send(send, 201, public_dict(result))
                return

            version_match = VERSION_PATH.fullmatch(path)
            if version_match:
                domain_id, version_text, action, report_suffix = version_match.groups()
                resource = self._version_resource(identity, domain_id, version_text)
                if method == "GET" and report_suffix == "report":
                    if body:
                        raise DomainFailure("BODY_FORBIDDEN")
                    result = self.service.report(identity, self.permit_provider(identity, "knowledge.domain.read", resource), domain_id, version_text)
                    await _send(send, 200, public_dict(result))
                    return
                if method != "POST" or action is None:
                    raise DomainFailure("ROUTE_NOT_FOUND")
                if action == "resolve":
                    value = _json(body, {"term"})
                    result = self.service.resolve(identity, self.permit_provider(identity, "knowledge.domain.resolve", resource), domain_id, version_text, value["term"])
                    await _send(send, 200, result)
                    return
                if idempotency_key is None:
                    raise DomainFailure("IDEMPOTENCY_KEY_REQUIRED")
                expected_revision = _revision(headers)
                action_name = f"knowledge.domain.version.{action}"
                permit = self.permit_provider(identity, action_name, resource)
                if action == "validate":
                    _json(body, set())
                    result = self.service.validate_version(identity, permit, domain_id, version_text, expected_revision=expected_revision, idempotency_key=idempotency_key, correlation_id=correlation_id)
                elif action == "request-approval":
                    _json(body, set())
                    result = self.service.request_approval(identity, permit, domain_id, version_text, expected_revision=expected_revision, idempotency_key=idempotency_key, correlation_id=correlation_id)
                elif action == "record-decision":
                    value = _json(body, {"approvalId", "packageDigest", "decision", "decidedAt", "approverSubjectId", "evidenceDigest"})
                    attestation = ApprovalAttestation(value["approvalId"], identity.organization_id, domain_id, version_text, value["packageDigest"], Decision(value["decision"]), value["decidedAt"], value["approverSubjectId"], value["evidenceDigest"])
                    result = self.service.record_decision(identity, permit, attestation, expected_revision=expected_revision, idempotency_key=idempotency_key, correlation_id=correlation_id)
                elif action == "publish":
                    _json(body, set())
                    result = self.service.publish(identity, permit, domain_id, version_text, expected_revision=expected_revision, idempotency_key=idempotency_key, correlation_id=correlation_id)
                elif action == "rollback":
                    _json(body, set())
                    result = self.service.rollback(identity, permit, domain_id, version_text, expected_revision=expected_revision, idempotency_key=idempotency_key, correlation_id=correlation_id)
                else:
                    raise DomainFailure("ROUTE_NOT_FOUND")
                await _send(send, 200, result if isinstance(result, dict) else public_dict(result))
                return

            if method == "POST" and path == "/knowledge/v1/mappings:validate":
                if idempotency_key is None:
                    raise DomainFailure("IDEMPOTENCY_KEY_REQUIRED")
                value = _json(body, {"mappingId", "version", "domainVersionDigest", "sourceSchemaDigest", "assertions", "ownersDigest", "createdAt"})
                assertions = _mapping_assertions(value["assertions"])
                mapping = SemanticMapping(identity.organization_id, value["mappingId"], value["version"], value["domainVersionDigest"], value["sourceSchemaDigest"], assertions, value["ownersDigest"], value["createdAt"], identity.subject_id)
                result = self.service.validate_mapping(identity, self.permit_provider(identity, "knowledge.domain.mapping.validate", mapping.resource_digest), mapping, idempotency_key=idempotency_key, correlation_id=correlation_id)
                await _send(send, 200, {"schemaVersion": "planeon.knowledge.domain/v1", "state": result.state.value, "revision": result.revision, "mappingDigest": mapping.resource_digest})
                return
            raise DomainFailure("ROUTE_NOT_FOUND")
        except DomainFailure as exc:
            status = 404 if exc.reason_code in {"POLICY_DENIED", "DOMAIN_NOT_FOUND", "VERSION_NOT_FOUND", "REPORT_NOT_FOUND", "TERM_NOT_RESOLVABLE", "ROUTE_NOT_FOUND"} else 409 if exc.reason_code in {"STALE_REVISION", "IDEMPOTENCY_CONFLICT", "TRANSITION_FORBIDDEN", "COMPATIBILITY_BLOCKED"} else 400
            await _send(send, status, {"schemaVersion": "planeon.knowledge.error/v1", "code": exc.reason_code, "message": "Request could not be processed."})
        except (KeyError, TypeError, ValueError):
            await _send(send, 400, {"schemaVersion": "planeon.knowledge.error/v1", "code": "CONTRACT_INVALID", "message": "Request could not be processed."})
        except Exception:
            await _send(send, 503, {"schemaVersion": "planeon.knowledge.error/v1", "code": "DEPENDENCY_UNAVAILABLE", "message": "Request could not be processed."})
