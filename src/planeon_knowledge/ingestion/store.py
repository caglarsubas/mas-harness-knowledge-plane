"""Copy-on-commit in-memory connector store for deterministic acceptance."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from threading import RLock
from typing import Callable, TypeVar

from .contracts import (
    CheckpointCandidate,
    IngestionEvidence,
    IngestionEvent,
    LeaseRevision,
    SourceDefinition,
    SourceRevision,
    StagedBatch,
    StagedRecordDigest,
)
from .evidence import ReadinessEvidenceRecord, ReadinessEvent
from .provenance import ProvenanceGraph
from .readiness import (
    BatchCommit,
    CheckpointRevision,
    DataReadinessAssessment,
    MeasurementObservation,
    ReadinessFinding,
    ReadinessPolicyObservation,
    SourceReadinessRevision,
)
from .retries import DeadLetterRecord, DeadLetterReview, ReadinessWorkRevision

SourceKey = tuple[str, str]
LeaseKey = tuple[str, str, str]
BatchKey = tuple[str, str]
T = TypeVar("T")


class StoreFailure(RuntimeError):
    pass


@dataclass
class StoreState:
    sources: dict[SourceKey, SourceDefinition] = field(default_factory=dict)
    source_revisions: dict[SourceKey, list[SourceRevision]] = field(default_factory=dict)
    lease_revisions: dict[LeaseKey, list[LeaseRevision]] = field(default_factory=dict)
    batches: dict[BatchKey, StagedBatch] = field(default_factory=dict)
    batch_records: dict[BatchKey, tuple[StagedRecordDigest, ...]] = field(default_factory=dict)
    checkpoint_candidates: dict[BatchKey, CheckpointCandidate] = field(default_factory=dict)
    evidence: list[IngestionEvidence] = field(default_factory=list)
    events: list[IngestionEvent] = field(default_factory=list)
    idempotency: dict[tuple[str, str], tuple[str, object]] = field(default_factory=dict)
    readiness_policies: dict[tuple[str, str, str], ReadinessPolicyObservation] = field(default_factory=dict)
    measurement_observations: dict[tuple[str, str, str], MeasurementObservation] = field(default_factory=dict)
    readiness_work_revisions: dict[tuple[str, str], list[ReadinessWorkRevision]] = field(default_factory=dict)
    readiness_findings: dict[tuple[str, str], tuple[ReadinessFinding, ...]] = field(default_factory=dict)
    readiness_assessments: dict[tuple[str, str], DataReadinessAssessment] = field(default_factory=dict)
    assessment_graph_ids: dict[tuple[str, str], str] = field(default_factory=dict)
    provenance_graphs: dict[tuple[str, str], ProvenanceGraph] = field(default_factory=dict)
    readiness_evidence: dict[tuple[str, str], ReadinessEvidenceRecord] = field(default_factory=dict)
    source_readiness_revisions: dict[SourceKey, list[SourceReadinessRevision]] = field(default_factory=dict)
    batch_commits: dict[BatchKey, BatchCommit] = field(default_factory=dict)
    checkpoint_revisions: dict[tuple[str, str, str], list[CheckpointRevision]] = field(default_factory=dict)
    dead_letters: dict[tuple[str, str], DeadLetterRecord] = field(default_factory=dict)
    dead_letter_reviews: dict[tuple[str, str], list[DeadLetterReview]] = field(default_factory=dict)
    readiness_events: list[ReadinessEvent] = field(default_factory=list)


class InMemoryIngestionStore:
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
                raise StoreFailure("atomic ingestion store commit failed")
            self._state = candidate
            return deepcopy(result)

    def read(self, operation: Callable[[StoreState], T]) -> T:
        with self._lock:
            return deepcopy(operation(self._state))

    def snapshot(self) -> StoreState:
        return self.read(lambda state: state)
