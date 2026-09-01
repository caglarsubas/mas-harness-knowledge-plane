"""Closed KN-001 foundation contracts."""

from .canonical import canonical_digest, canonical_json, parse_closed_json
from .errors import KnowledgeError
from .health import DependencyHealth, HealthState, Readiness
from .models import IdempotencyState, InboxRecord, OutboxRecord, SourceReference, TenantIdentity, classify_idempotency
from .services import SERVICE_DESCRIPTORS, ServiceDescriptor

__all__ = [
    "DependencyHealth",
    "HealthState",
    "InboxRecord",
    "IdempotencyState",
    "KnowledgeError",
    "OutboxRecord",
    "Readiness",
    "SERVICE_DESCRIPTORS",
    "ServiceDescriptor",
    "SourceReference",
    "TenantIdentity",
    "canonical_digest",
    "canonical_json",
    "classify_idempotency",
    "parse_closed_json",
]
