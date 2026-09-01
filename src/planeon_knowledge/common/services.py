"""Immutable service ownership map."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ServiceDescriptor:
    service_name: str
    harness_id: str
    owned_schema: str
    policy_action_prefix: str


SERVICE_DESCRIPTORS = {
    "domain-service": ServiceDescriptor("domain-service", "knowledge.domain-semantic", "domain", "knowledge.domain"),
    "connector-controller": ServiceDescriptor("connector-controller", "knowledge.data-integration", "ingestion", "knowledge.ingestion.connector"),
    "ingest-worker": ServiceDescriptor("ingest-worker", "knowledge.data-integration", "ingestion", "knowledge.ingestion.worker"),
    "retrieval-service": ServiceDescriptor("retrieval-service", "knowledge.retrieval-context", "retrieval", "knowledge.retrieval"),
    "index-worker": ServiceDescriptor("index-worker", "knowledge.retrieval-context", "retrieval", "knowledge.index"),
    "memory-service": ServiceDescriptor("memory-service", "knowledge.memory-state", "memory", "knowledge.memory"),
}
