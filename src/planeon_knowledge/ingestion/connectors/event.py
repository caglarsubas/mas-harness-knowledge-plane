"""Bounded event polling with no broker discovery, administration, or commit."""

from __future__ import annotations

from dataclasses import dataclass

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.common.validation import digest

from ..contracts import ReadPlan
from .base import ConnectorFailure, ConnectorPage, ConnectorPort, enforce_page, require_attestations


@dataclass(frozen=True, slots=True)
class EventBinding:
    subscription_digest: str
    topic_digest: str
    partition: int
    auto_commit: bool
    operation: str

    def __post_init__(self) -> None:
        digest(self.subscription_digest, "subscriptionDigest")
        digest(self.topic_digest, "topicDigest")
        if not isinstance(self.partition, int) or isinstance(self.partition, bool) or not 0 <= self.partition <= 1_000_000:
            raise ValueError("event partition is invalid")
        if self.auto_commit is not False or self.operation != "POLL":
            raise ValueError("event binding permits only non-committing poll")

    @property
    def binding_digest(self) -> str:
        return canonical_digest({
            "subscriptionDigest": self.subscription_digest,
            "topicDigest": self.topic_digest,
            "partition": self.partition,
            "autoCommit": self.auto_commit,
            "operation": self.operation,
        })


def read_event(plan: ReadPlan, binding: EventBinding, port: ConnectorPort, checkpoint: str | None) -> tuple[ConnectorPage, ...]:
    if binding.binding_digest != plan.binding_digest:
        raise ConnectorFailure("EVENT_BINDING_DENIED")
    page = port(plan, binding, checkpoint, None)
    enforce_page(plan, page)
    require_attestations(page, frozenset({"DEADLINE_BOUND", "NO_AUTO_COMMIT", "POLL_ONLY", "READ_ONLY", "TOPIC_PARTITION_MATCH"}))
    if page.next_token is not None:
        raise ConnectorFailure("EVENT_NEXT_LINK_FORBIDDEN")
    return (page,)
