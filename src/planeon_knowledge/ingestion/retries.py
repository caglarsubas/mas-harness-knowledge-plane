"""Fenced three-attempt readiness work and append-only dead-letter contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.common.validation import digest, token, utc_seconds, uuid_text

from .contracts import positive_int

RETRYABLE_REASONS = frozenset(
    {"DEPENDENCY_UNAVAILABLE", "EVIDENCE_PUBLISH_UNAVAILABLE", "STORE_TRANSIENT", "CLAIM_EXPIRED"}
)
RETRY_DELAYS = {1: 1, 2: 4}


class RetryFailure(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


class WorkState(StrEnum):
    PENDING = "PENDING"
    CLAIMED = "CLAIMED"
    RETRY_SCHEDULED = "RETRY_SCHEDULED"
    SUCCEEDED = "SUCCEEDED"
    DEAD_LETTERED = "DEAD_LETTERED"


def _time(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise RetryFailure("WORK_TIME_INVALID") from exc


def _format(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True, slots=True)
class ReadinessWorkRevision:
    organization_id: str
    work_id: str
    source_id: str
    batch_id: str
    batch_digest: str
    policy_digest: str
    observation_digest: str
    revision: int
    attempt: int
    fencing_token: int
    state: WorkState
    worker_id: str | None
    eligible_at: str
    claim_expires_at: str | None
    reason_code: str
    occurred_at: str
    correlation_id: str
    work_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.work_id, "workId")
        uuid_text(self.source_id, "sourceId")
        uuid_text(self.batch_id, "batchId")
        for field, value in (
            ("batchDigest", self.batch_digest),
            ("policyDigest", self.policy_digest),
            ("observationDigest", self.observation_digest),
            ("workDigest", self.work_digest),
        ):
            digest(value, field)
        positive_int(self.revision, "revision", 2**63 - 1)
        if not isinstance(self.attempt, int) or isinstance(self.attempt, bool) or not 0 <= self.attempt <= 3:
            raise ValueError("work attempt is invalid")
        if not isinstance(self.fencing_token, int) or isinstance(self.fencing_token, bool) or self.fencing_token < 0:
            raise ValueError("work fencing token is invalid")
        if not isinstance(self.state, WorkState):
            raise ValueError("work state is invalid")
        if self.worker_id is not None:
            token(self.worker_id, "workerId")
        utc_seconds(self.eligible_at, "eligibleAt")
        if self.claim_expires_at is not None:
            utc_seconds(self.claim_expires_at, "claimExpiresAt")
        token(self.reason_code, "reasonCode")
        utc_seconds(self.occurred_at, "occurredAt")
        uuid_text(self.correlation_id, "correlationId")
        if self.state is WorkState.PENDING:
            if self.revision != 1 or self.attempt != 0 or self.fencing_token != 0 or self.worker_id is not None:
                raise ValueError("pending work state is invalid")
        if self.state is WorkState.CLAIMED:
            if self.attempt < 1 or self.fencing_token < 1 or self.worker_id is None or self.claim_expires_at is None:
                raise ValueError("claimed work state is invalid")
            claim_lifetime = _time(self.claim_expires_at) - _time(self.occurred_at)
            if not 0 < claim_lifetime.total_seconds() <= 300:
                raise ValueError("claimed work ttl is invalid")
        if self.state is not WorkState.CLAIMED and self.claim_expires_at is not None:
            raise ValueError("only claimed work may have a claim expiry")
        if self.state is not WorkState.PENDING:
            if self.attempt < 1 or self.fencing_token != self.attempt or self.worker_id is None:
                raise ValueError("post-claim work state is invalid")
        if self.state is WorkState.RETRY_SCHEDULED and self.attempt >= 3:
            raise ValueError("third attempt cannot be rescheduled")
        if self.work_digest != canonical_digest(self.digest_body()):
            raise ValueError("work digest mismatch")

    def digest_body(self) -> dict[str, object]:
        return {
            "organizationId": self.organization_id,
            "workId": self.work_id,
            "sourceId": self.source_id,
            "batchId": self.batch_id,
            "batchDigest": self.batch_digest,
            "policyDigest": self.policy_digest,
            "observationDigest": self.observation_digest,
            "revision": self.revision,
            "attempt": self.attempt,
            "fencingToken": self.fencing_token,
            "state": self.state.value,
            "workerId": self.worker_id,
            "eligibleAt": self.eligible_at,
            "claimExpiresAt": self.claim_expires_at,
            "reasonCode": self.reason_code,
            "occurredAt": self.occurred_at,
            "correlationId": self.correlation_id,
        }


@dataclass(frozen=True, slots=True)
class DeadLetterRecord:
    organization_id: str
    dead_letter_id: str
    work_id: str
    source_id: str
    batch_id: str
    batch_digest: str
    attempt: int
    fencing_token: int
    reason_code: str
    dead_lettered_at: str
    record_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.dead_letter_id, "deadLetterId")
        uuid_text(self.work_id, "workId")
        uuid_text(self.source_id, "sourceId")
        uuid_text(self.batch_id, "batchId")
        digest(self.batch_digest, "batchDigest")
        positive_int(self.attempt, "attempt", 3)
        positive_int(self.fencing_token, "fencingToken", 2**63 - 1)
        token(self.reason_code, "reasonCode")
        utc_seconds(self.dead_lettered_at, "deadLetteredAt")
        digest(self.record_digest, "recordDigest")
        if self.record_digest != canonical_digest(self.digest_body()):
            raise ValueError("dead-letter record digest mismatch")

    def digest_body(self) -> dict[str, object]:
        return {
            "organizationId": self.organization_id,
            "deadLetterId": self.dead_letter_id,
            "workId": self.work_id,
            "sourceId": self.source_id,
            "batchId": self.batch_id,
            "batchDigest": self.batch_digest,
            "attempt": self.attempt,
            "fencingToken": self.fencing_token,
            "reasonCode": self.reason_code,
            "deadLetteredAt": self.dead_lettered_at,
        }


@dataclass(frozen=True, slots=True)
class DeadLetterReview:
    organization_id: str
    review_id: str
    dead_letter_id: str
    decision: str
    reason_code: str
    reviewer_subject_id: str
    reviewed_at: str
    correlation_id: str
    review_digest: str

    def __post_init__(self) -> None:
        uuid_text(self.organization_id, "organizationId")
        uuid_text(self.review_id, "reviewId")
        uuid_text(self.dead_letter_id, "deadLetterId")
        if self.decision != "ACKNOWLEDGED":
            raise ValueError("dead-letter review decision is invalid")
        token(self.reason_code, "reasonCode")
        token(self.reviewer_subject_id, "reviewerSubjectId")
        utc_seconds(self.reviewed_at, "reviewedAt")
        uuid_text(self.correlation_id, "correlationId")
        digest(self.review_digest, "reviewDigest")
        if self.review_digest != canonical_digest(self.digest_body()):
            raise ValueError("dead-letter review digest mismatch")

    def digest_body(self) -> dict[str, object]:
        return {
            "organizationId": self.organization_id,
            "reviewId": self.review_id,
            "deadLetterId": self.dead_letter_id,
            "decision": self.decision,
            "reasonCode": self.reason_code,
            "reviewerSubjectId": self.reviewer_subject_id,
            "reviewedAt": self.reviewed_at,
            "correlationId": self.correlation_id,
        }


def _work(
    *,
    template: ReadinessWorkRevision | None,
    organization_id: str,
    work_id: str,
    source_id: str,
    batch_id: str,
    batch_digest: str,
    policy_digest: str,
    observation_digest: str,
    revision: int,
    attempt: int,
    fencing_token: int,
    state: WorkState,
    worker_id: str | None,
    eligible_at: str,
    claim_expires_at: str | None,
    reason_code: str,
    occurred_at: str,
    correlation_id: str,
) -> ReadinessWorkRevision:
    body = {
        "organizationId": organization_id,
        "workId": work_id,
        "sourceId": source_id,
        "batchId": batch_id,
        "batchDigest": batch_digest,
        "policyDigest": policy_digest,
        "observationDigest": observation_digest,
        "revision": revision,
        "attempt": attempt,
        "fencingToken": fencing_token,
        "state": state.value,
        "workerId": worker_id,
        "eligibleAt": eligible_at,
        "claimExpiresAt": claim_expires_at,
        "reasonCode": reason_code,
        "occurredAt": occurred_at,
        "correlationId": correlation_id,
    }
    return ReadinessWorkRevision(
        organization_id,
        work_id,
        source_id,
        batch_id,
        batch_digest,
        policy_digest,
        observation_digest,
        revision,
        attempt,
        fencing_token,
        state,
        worker_id,
        eligible_at,
        claim_expires_at,
        reason_code,
        occurred_at,
        correlation_id,
        canonical_digest(body),
    )


def new_work(
    *,
    organization_id: str,
    work_id: str,
    source_id: str,
    batch_id: str,
    batch_digest: str,
    policy_digest: str,
    observation_digest: str,
    now: str,
    correlation_id: str,
) -> ReadinessWorkRevision:
    return _work(
        template=None,
        organization_id=organization_id,
        work_id=work_id,
        source_id=source_id,
        batch_id=batch_id,
        batch_digest=batch_digest,
        policy_digest=policy_digest,
        observation_digest=observation_digest,
        revision=1,
        attempt=0,
        fencing_token=0,
        state=WorkState.PENDING,
        worker_id=None,
        eligible_at=now,
        claim_expires_at=None,
        reason_code="WORK_PENDING",
        occurred_at=now,
        correlation_id=correlation_id,
    )


def claim_work(
    current: ReadinessWorkRevision,
    *,
    worker_id: str,
    ttl_seconds: int,
    now: str,
    correlation_id: str,
) -> ReadinessWorkRevision:
    positive_int(ttl_seconds, "ttlSeconds", 300)
    timestamp = _time(now)
    if current.state not in {WorkState.PENDING, WorkState.RETRY_SCHEDULED}:
        raise RetryFailure("WORK_NOT_CLAIMABLE")
    if _time(current.eligible_at) > timestamp or current.attempt >= 3:
        raise RetryFailure("WORK_NOT_ELIGIBLE")
    return _work(
        template=current,
        organization_id=current.organization_id,
        work_id=current.work_id,
        source_id=current.source_id,
        batch_id=current.batch_id,
        batch_digest=current.batch_digest,
        policy_digest=current.policy_digest,
        observation_digest=current.observation_digest,
        revision=current.revision + 1,
        attempt=current.attempt + 1,
        fencing_token=current.fencing_token + 1,
        state=WorkState.CLAIMED,
        worker_id=worker_id,
        eligible_at=now,
        claim_expires_at=_format(timestamp + timedelta(seconds=ttl_seconds)),
        reason_code="WORK_CLAIMED",
        occurred_at=now,
        correlation_id=correlation_id,
    )


def assert_current_claim(
    current: ReadinessWorkRevision,
    supplied: ReadinessWorkRevision,
    *,
    worker_id: str,
    now: str,
) -> None:
    if current.state is not WorkState.CLAIMED:
        raise RetryFailure("WORK_NOT_CLAIMED")
    if (
        current.work_id,
        current.revision,
        current.attempt,
        current.fencing_token,
        current.worker_id,
    ) != (
        supplied.work_id,
        supplied.revision,
        supplied.attempt,
        supplied.fencing_token,
        worker_id,
    ):
        raise RetryFailure("WORK_FENCE_MISMATCH")
    if current.claim_expires_at is None or _time(current.claim_expires_at) <= _time(now):
        raise RetryFailure("CLAIM_EXPIRED")


def finish_work(
    current: ReadinessWorkRevision,
    *,
    worker_id: str,
    now: str,
    correlation_id: str,
) -> ReadinessWorkRevision:
    assert_current_claim(current, current, worker_id=worker_id, now=now)
    return _work(
        template=current,
        organization_id=current.organization_id,
        work_id=current.work_id,
        source_id=current.source_id,
        batch_id=current.batch_id,
        batch_digest=current.batch_digest,
        policy_digest=current.policy_digest,
        observation_digest=current.observation_digest,
        revision=current.revision + 1,
        attempt=current.attempt,
        fencing_token=current.fencing_token,
        state=WorkState.SUCCEEDED,
        worker_id=current.worker_id,
        eligible_at=current.eligible_at,
        claim_expires_at=None,
        reason_code="WORK_SUCCEEDED",
        occurred_at=now,
        correlation_id=correlation_id,
    )


def fail_work(
    current: ReadinessWorkRevision,
    *,
    worker_id: str,
    reason_code: str,
    now: str,
    correlation_id: str,
    allow_expired_claim: bool = False,
) -> ReadinessWorkRevision:
    if allow_expired_claim and reason_code == "CLAIM_EXPIRED":
        if current.state is not WorkState.CLAIMED or current.worker_id != worker_id:
            raise RetryFailure("WORK_FENCE_MISMATCH")
        if current.claim_expires_at is None or _time(current.claim_expires_at) > _time(now):
            raise RetryFailure("CLAIM_NOT_EXPIRED")
    else:
        assert_current_claim(current, current, worker_id=worker_id, now=now)
    token(reason_code, "reasonCode")
    retryable = reason_code in RETRYABLE_REASONS
    terminal = not retryable or current.attempt >= 3
    state = WorkState.DEAD_LETTERED if terminal else WorkState.RETRY_SCHEDULED
    eligible_at = now if terminal else _format(_time(now) + timedelta(seconds=RETRY_DELAYS[current.attempt]))
    return _work(
        template=current,
        organization_id=current.organization_id,
        work_id=current.work_id,
        source_id=current.source_id,
        batch_id=current.batch_id,
        batch_digest=current.batch_digest,
        policy_digest=current.policy_digest,
        observation_digest=current.observation_digest,
        revision=current.revision + 1,
        attempt=current.attempt,
        fencing_token=current.fencing_token,
        state=state,
        worker_id=current.worker_id,
        eligible_at=eligible_at,
        claim_expires_at=None,
        reason_code=reason_code,
        occurred_at=now,
        correlation_id=correlation_id,
    )


def build_dead_letter(
    *,
    dead_letter_id: str,
    work: ReadinessWorkRevision,
) -> DeadLetterRecord:
    if work.state is not WorkState.DEAD_LETTERED:
        raise RetryFailure("WORK_NOT_DEAD_LETTERED")
    body = {
        "organizationId": work.organization_id,
        "deadLetterId": dead_letter_id,
        "workId": work.work_id,
        "sourceId": work.source_id,
        "batchId": work.batch_id,
        "batchDigest": work.batch_digest,
        "attempt": work.attempt,
        "fencingToken": work.fencing_token,
        "reasonCode": work.reason_code,
        "deadLetteredAt": work.occurred_at,
    }
    return DeadLetterRecord(
        work.organization_id,
        dead_letter_id,
        work.work_id,
        work.source_id,
        work.batch_id,
        work.batch_digest,
        work.attempt,
        work.fencing_token,
        work.reason_code,
        work.occurred_at,
        canonical_digest(body),
    )


def build_review(
    *,
    organization_id: str,
    review_id: str,
    dead_letter_id: str,
    reason_code: str,
    reviewer_subject_id: str,
    reviewed_at: str,
    correlation_id: str,
) -> DeadLetterReview:
    body = {
        "organizationId": organization_id,
        "reviewId": review_id,
        "deadLetterId": dead_letter_id,
        "decision": "ACKNOWLEDGED",
        "reasonCode": reason_code,
        "reviewerSubjectId": reviewer_subject_id,
        "reviewedAt": reviewed_at,
        "correlationId": correlation_id,
    }
    return DeadLetterReview(
        organization_id,
        review_id,
        dead_letter_id,
        "ACKNOWLEDGED",
        reason_code,
        reviewer_subject_id,
        reviewed_at,
        correlation_id,
        canonical_digest(body),
    )
