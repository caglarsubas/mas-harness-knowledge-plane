"""Append-only tenant lease state machine with monotonic fencing tokens."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .contracts import LeaseRevision, LeaseState, positive_int


class LeaseFailure(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def parse_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _active(state: LeaseState) -> bool:
    return state in {LeaseState.ACQUIRED, LeaseState.RENEWED}


def acquire(
    history: tuple[LeaseRevision, ...],
    *,
    organization_id: str,
    source_id: str,
    source_version_digest: str,
    partition: str,
    owner_worker_id: str,
    ttl_seconds: int,
    now: str,
    lease_id: str,
    correlation_id: str,
) -> tuple[LeaseRevision, ...]:
    positive_int(ttl_seconds, "ttlSeconds", 300)
    timestamp = parse_time(now)
    additions: list[LeaseRevision] = []
    if history:
        current = history[-1]
        if (current.organization_id, current.source_id, current.source_version_digest, current.partition) != (organization_id, source_id, source_version_digest, partition):
            raise LeaseFailure("LEASE_SCOPE_MISMATCH")
        if _active(current.state) and parse_time(current.expires_at) > timestamp:
            raise LeaseFailure("LEASE_ALREADY_HELD")
        if _active(current.state):
            additions.append(LeaseRevision(
                organization_id, source_id, source_version_digest, partition, current.lease_id,
                current.revision + 1, current.fencing_token, current.owner_worker_id,
                LeaseState.EXPIRED, now, current.expires_at, "LEASE_EXPIRED", correlation_id,
            ))
    revision = history[-1].revision + len(additions) + 1 if history else 1
    fencing_token = max((item.fencing_token for item in history), default=0) + 1
    expires_at = format_time(timestamp + timedelta(seconds=ttl_seconds))
    additions.append(LeaseRevision(
        organization_id, source_id, source_version_digest, partition, lease_id, revision, fencing_token,
        owner_worker_id, LeaseState.ACQUIRED, now, expires_at, "LEASE_ACQUIRED",
        correlation_id,
    ))
    return tuple(additions)


def renew(
    current: LeaseRevision,
    *,
    expected_revision: int,
    lease_id: str,
    owner_worker_id: str,
    fencing_token: int,
    ttl_seconds: int,
    now: str,
    correlation_id: str,
) -> LeaseRevision:
    positive_int(ttl_seconds, "ttlSeconds", 300)
    if current.revision != expected_revision:
        raise LeaseFailure("LEASE_STALE_REVISION")
    if not _active(current.state):
        raise LeaseFailure("LEASE_TERMINAL")
    if (current.lease_id, current.owner_worker_id, current.fencing_token) != (lease_id, owner_worker_id, fencing_token):
        raise LeaseFailure("LEASE_FENCE_MISMATCH")
    timestamp = parse_time(now)
    if parse_time(current.expires_at) <= timestamp:
        raise LeaseFailure("LEASE_EXPIRED")
    return LeaseRevision(
        current.organization_id, current.source_id, current.source_version_digest, current.partition,
        current.lease_id, current.revision + 1, current.fencing_token,
        current.owner_worker_id, LeaseState.RENEWED, now,
        format_time(timestamp + timedelta(seconds=ttl_seconds)), "LEASE_RENEWED",
        correlation_id,
    )


def release(
    current: LeaseRevision,
    *,
    expected_revision: int,
    lease_id: str,
    owner_worker_id: str,
    fencing_token: int,
    now: str,
    correlation_id: str,
) -> LeaseRevision:
    if current.revision != expected_revision:
        raise LeaseFailure("LEASE_STALE_REVISION")
    if not _active(current.state):
        raise LeaseFailure("LEASE_TERMINAL")
    if (current.lease_id, current.owner_worker_id, current.fencing_token) != (lease_id, owner_worker_id, fencing_token):
        raise LeaseFailure("LEASE_FENCE_MISMATCH")
    if parse_time(current.expires_at) <= parse_time(now):
        raise LeaseFailure("LEASE_EXPIRED")
    return LeaseRevision(
        current.organization_id, current.source_id, current.source_version_digest, current.partition,
        current.lease_id, current.revision + 1, current.fencing_token,
        current.owner_worker_id, LeaseState.RELEASED, now, current.expires_at,
        "LEASE_RELEASED", correlation_id,
    )


def assert_current(
    current: LeaseRevision | None,
    supplied: LeaseRevision,
    *,
    organization_id: str,
    source_id: str,
    source_version_digest: str,
    now: str,
) -> None:
    if current is None:
        raise LeaseFailure("LEASE_NOT_FOUND")
    if (current.organization_id, current.source_id, current.source_version_digest) != (organization_id, source_id, source_version_digest):
        raise LeaseFailure("LEASE_SCOPE_MISMATCH")
    if (
        current.lease_id,
        current.revision,
        current.fencing_token,
        current.owner_worker_id,
        current.partition,
    ) != (
        supplied.lease_id,
        supplied.revision,
        supplied.fencing_token,
        supplied.owner_worker_id,
        supplied.partition,
    ):
        raise LeaseFailure("LEASE_FENCE_MISMATCH")
    if not _active(current.state) or parse_time(current.expires_at) <= parse_time(now):
        raise LeaseFailure("LEASE_EXPIRED")
