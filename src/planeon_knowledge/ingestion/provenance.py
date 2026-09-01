"""Bounded immutable digest-only provenance DAGs for readiness and commit."""

from __future__ import annotations

from dataclasses import dataclass

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.common.validation import digest, token, utc_seconds, uuid_text

from .contracts import stable_id

ALLOWED_PURPOSES = frozenset({"ASSESSMENT", "COMMIT"})
ALLOWED_KINDS = frozenset(
    {
        "data.checkpoint-candidate",
        "data.checkpoint-revision",
        "data.committed-batch",
        "data.lease-binding",
        "data.material",
        "data.record-set",
        "data.source-version",
        "data.staged-batch",
        "domain.semantic-mapping",
        "domain.version",
        "readiness.assessment",
        "readiness.finding",
        "readiness.measurement",
        "readiness.owner-approval",
        "readiness.policy",
        "readiness.provenance",
    }
)
ALLOWED_RELATIONSHIPS = frozenset(
    {
        "approval.authorizes",
        "assessment.authorizes",
        "batch.measured-by",
        "batch.promotes",
        "checkpoint.binds",
        "commit.advances",
        "domain.binds",
        "finding.supports",
        "lease.fences",
        "mapping.binds",
        "material.binds",
        "measurement.supports",
        "measurement.yields",
        "policy.governs",
        "records.bind",
        "source.produces",
    }
)


class ProvenanceFailure(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class ProvenanceNode:
    node_id: str
    kind: str
    subject_digest: str

    def __post_init__(self) -> None:
        stable_id(self.node_id, "nodeId")
        stable_id(self.kind, "kind")
        if self.kind not in ALLOWED_KINDS:
            raise ValueError("provenance kind is invalid")
        digest(self.subject_digest, "subjectDigest")


@dataclass(frozen=True, slots=True)
class ProvenanceEdge:
    source_node_id: str
    target_node_id: str
    relationship: str

    def __post_init__(self) -> None:
        stable_id(self.source_node_id, "sourceNodeId")
        stable_id(self.target_node_id, "targetNodeId")
        stable_id(self.relationship, "relationship")
        if self.relationship not in ALLOWED_RELATIONSHIPS:
            raise ValueError("provenance relationship is invalid")
        if self.source_node_id == self.target_node_id:
            raise ValueError("provenance self-edge is forbidden")


@dataclass(frozen=True, slots=True)
class ProvenanceGraph:
    organization_id: str
    graph_id: str
    purpose: str
    nodes: tuple[ProvenanceNode, ...]
    edges: tuple[ProvenanceEdge, ...]
    created_at: str
    graph_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        stable_id(self.graph_id, "graphId")
        token(self.purpose, "purpose")
        if self.purpose not in ALLOWED_PURPOSES:
            raise ValueError("provenance purpose is invalid")
        utc_seconds(self.created_at, "createdAt")
        digest(self.graph_digest, "graphDigest")
        _validate(self.nodes, self.edges)
        if self.graph_digest != _graph_digest(
            self.organization_id,
            self.graph_id,
            self.purpose,
            self.nodes,
            self.edges,
            self.created_at,
        ):
            raise ValueError("provenance graph digest mismatch")


def _node_value(node: ProvenanceNode) -> dict[str, str]:
    return {"nodeId": node.node_id, "kind": node.kind, "subjectDigest": node.subject_digest}


def _edge_value(edge: ProvenanceEdge) -> dict[str, str]:
    return {
        "sourceNodeId": edge.source_node_id,
        "targetNodeId": edge.target_node_id,
        "relationship": edge.relationship,
    }


def _graph_digest(
    organization_id: str,
    graph_id: str,
    purpose: str,
    nodes: tuple[ProvenanceNode, ...],
    edges: tuple[ProvenanceEdge, ...],
    created_at: str,
) -> str:
    return canonical_digest(
        {
            "organizationId": organization_id,
            "graphId": graph_id,
            "purpose": purpose,
            "nodes": [_node_value(node) for node in nodes],
            "edges": [_edge_value(edge) for edge in edges],
            "createdAt": created_at,
        }
    )


def _validate(nodes: tuple[ProvenanceNode, ...], edges: tuple[ProvenanceEdge, ...]) -> None:
    if not 1 <= len(nodes) <= 32 or len(edges) > 64:
        raise ProvenanceFailure("PROVENANCE_LIMIT_EXCEEDED")
    node_order = tuple((node.node_id, node.kind, node.subject_digest) for node in nodes)
    if node_order != tuple(sorted(node_order)) or len({node.node_id for node in nodes}) != len(nodes):
        raise ProvenanceFailure("PROVENANCE_NODE_INVALID")
    if len({(node.kind, node.subject_digest) for node in nodes}) != len(nodes):
        raise ProvenanceFailure("PROVENANCE_NODE_DUPLICATE")
    edge_order = tuple((edge.source_node_id, edge.target_node_id, edge.relationship) for edge in edges)
    if edge_order != tuple(sorted(set(edge_order))):
        raise ProvenanceFailure("PROVENANCE_EDGE_INVALID")
    node_ids = {node.node_id for node in nodes}
    if any(edge.source_node_id not in node_ids or edge.target_node_id not in node_ids for edge in edges):
        raise ProvenanceFailure("PROVENANCE_EDGE_DANGLING")

    incoming = {node_id: 0 for node_id in node_ids}
    outgoing: dict[str, list[str]] = {node_id: [] for node_id in node_ids}
    for edge in edges:
        outgoing[edge.source_node_id].append(edge.target_node_id)
        incoming[edge.target_node_id] += 1
    ready = sorted(node_id for node_id, count in incoming.items() if count == 0)
    visited = 0
    while ready:
        current = ready.pop(0)
        visited += 1
        for target in sorted(outgoing[current]):
            incoming[target] -= 1
            if incoming[target] == 0:
                ready.append(target)
                ready.sort()
    if visited != len(nodes):
        raise ProvenanceFailure("PROVENANCE_CYCLE")


def build_graph(
    *,
    organization_id: str,
    graph_id: str,
    purpose: str,
    nodes: tuple[ProvenanceNode, ...],
    edges: tuple[ProvenanceEdge, ...],
    created_at: str,
) -> ProvenanceGraph:
    sorted_nodes = tuple(sorted(nodes, key=lambda item: (item.node_id, item.kind, item.subject_digest)))
    sorted_edges = tuple(
        sorted(edges, key=lambda item: (item.source_node_id, item.target_node_id, item.relationship))
    )
    graph_digest = _graph_digest(
        organization_id,
        graph_id,
        purpose,
        sorted_nodes,
        sorted_edges,
        created_at,
    )
    return ProvenanceGraph(
        organization_id,
        graph_id,
        purpose,
        sorted_nodes,
        sorted_edges,
        created_at,
        graph_digest,
    )
