"""Copy-on-commit in-memory reference store for deterministic acceptance."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from threading import RLock
from typing import Callable, TypeVar

from .contracts import (
    ApprovalAttestation,
    DomainDefinition,
    DomainEvidence,
    DomainEvent,
    DomainVersion,
    MappingApprovalAttestation,
    MappingRevision,
    SemanticMapping,
    ValidationReport,
    VersionRevision,
)
from .semantic import SemanticSnapshot

VersionKey = tuple[str, str, str]
MappingKey = tuple[str, str, str]
T = TypeVar("T")


class StoreFailure(RuntimeError):
    pass


@dataclass
class StoreState:
    definitions: dict[tuple[str, str], DomainDefinition] = field(default_factory=dict)
    versions: dict[VersionKey, DomainVersion] = field(default_factory=dict)
    version_revisions: dict[VersionKey, list[VersionRevision]] = field(default_factory=dict)
    reports: dict[VersionKey, ValidationReport] = field(default_factory=dict)
    snapshots: dict[VersionKey, SemanticSnapshot] = field(default_factory=dict)
    approvals: dict[VersionKey, ApprovalAttestation] = field(default_factory=dict)
    active_domains: dict[tuple[str, str], str] = field(default_factory=dict)
    mappings: dict[MappingKey, SemanticMapping] = field(default_factory=dict)
    mapping_revisions: dict[MappingKey, list[MappingRevision]] = field(default_factory=dict)
    mapping_validation_digests: dict[MappingKey, str] = field(default_factory=dict)
    mapping_approvals: dict[MappingKey, MappingApprovalAttestation] = field(default_factory=dict)
    active_mappings: dict[tuple[str, str], str] = field(default_factory=dict)
    evidence: list[DomainEvidence] = field(default_factory=list)
    events: list[DomainEvent] = field(default_factory=list)
    idempotency: dict[tuple[str, str], tuple[str, object]] = field(default_factory=dict)


class InMemoryDomainStore:
    def __init__(self) -> None:
        self._state = StoreState()
        self._lock = RLock()
        self._fail_next_commit = False

    def inject_commit_failure(self) -> None:
        with self._lock:
            self._fail_next_commit = True

    def transact(self, operation: Callable[[StoreState], T]) -> T:
        with self._lock:
            candidate = deepcopy(self._state)
            result = operation(candidate)
            if self._fail_next_commit:
                self._fail_next_commit = False
                raise StoreFailure("atomic store commit failed")
            self._state = candidate
            return deepcopy(result)

    def read(self, operation: Callable[[StoreState], T]) -> T:
        with self._lock:
            return deepcopy(operation(self._state))

    def snapshot(self) -> StoreState:
        return self.read(lambda state: state)
