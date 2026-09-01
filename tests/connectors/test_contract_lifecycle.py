from __future__ import annotations

import unittest

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.ingestion.contracts import ConnectorKind, LeaseState, SourceState
from planeon_knowledge.ingestion.service import IngestionFailure, source_scope_digest

from tests.connectors.support import (
    Clock,
    FixturePort,
    MemoryStagingPort,
    acquire_sample_lease,
    binding,
    create_and_validate,
    domain,
    endpoint,
    identifier,
    identity,
    permit,
    sample,
    secret,
    service,
    source,
)


class SourceLifecycleTests(unittest.TestCase):
    def test_declare_validate_sample_is_append_only_and_never_claims_readiness(self) -> None:
        caller = identity()
        target = service()
        candidate, binding_value, validated = create_and_validate(target, caller)
        lease = acquire_sample_lease(target, caller, candidate)
        batch = sample(target, caller, candidate, binding_value, validated.revision, lease)
        snapshot = target.store.snapshot()
        states = [item.state for item in snapshot.source_revisions[(caller.organization_id, candidate.source_id)]]
        self.assertEqual(states, [SourceState.DECLARED, SourceState.VALIDATING, SourceState.VALID, SourceState.SAMPLING, SourceState.SAMPLED])
        self.assertEqual(batch.state.value, "STAGED")
        self.assertEqual(batch.record_count, 4)
        self.assertEqual(len(snapshot.batch_records[(caller.organization_id, batch.batch_id)]), 4)
        self.assertIn((caller.organization_id, batch.batch_id), snapshot.checkpoint_candidates)
        event_types = [item.event_type for item in snapshot.events]
        self.assertEqual(event_types, ["data.source.declared.v1", "data.source.validated.v1", "data.source.sample-staged.v1"])
        rendered = str((snapshot, batch)).casefold()
        for forbidden in ("ready_for_approval", "committed", "accepted", "activated", "tenant_accepted"):
            self.assertNotIn(forbidden, rendered)

    def test_idempotent_replay_and_conflict_are_tenant_scoped(self) -> None:
        caller = identity()
        target = service()
        candidate = source(caller=caller)
        allowed = permit(caller, "knowledge.ingestion.source.create", candidate.resource_digest)
        first = target.create_source(caller, allowed, candidate, idempotency_key="same-command", correlation_id=identifier("idem:first"))
        replay = target.create_source(caller, allowed, candidate, idempotency_key="same-command", correlation_id=identifier("idem:replay"))
        self.assertEqual(replay, first)
        changed = source(ConnectorKind.EVENT, caller=caller)
        with self.assertRaisesRegex(IngestionFailure, "IDEMPOTENCY_CONFLICT"):
            target.create_source(
                caller,
                permit(caller, "knowledge.ingestion.source.create", changed.resource_digest),
                changed,
                idempotency_key="same-command",
                correlation_id=identifier("idem:conflict"),
            )
        snapshot = target.store.snapshot()
        self.assertEqual(len(snapshot.sources), 1)
        self.assertEqual(len(snapshot.events), 1)

    def test_validation_requires_current_domain_endpoint_and_secret_grants(self) -> None:
        caller = identity()
        target = service()
        candidate = source(caller=caller)
        created = target.create_source(
            caller,
            permit(caller, "knowledge.ingestion.source.create", candidate.resource_digest),
            candidate,
            idempotency_key="create-dependency-test",
            correlation_id=identifier("dependency:create"),
        )
        binding_value = binding(candidate.connector_kind)
        source_permit = permit(caller, "knowledge.ingestion.source.validate", source_scope_digest(caller.organization_id, candidate.source_id))
        cases = (
            (endpoint(candidate, "VALIDATE", binding_value, allowed=False), secret(candidate, "VALIDATE"), domain(candidate), "ENDPOINT_GRANT_DENIED"),
            (endpoint(candidate, "VALIDATE", binding_value), secret(candidate, "VALIDATE", expires_at="2025-01-01T00:00:00Z"), domain(candidate), "SECRET_GRANT_DENIED"),
            (endpoint(candidate, "VALIDATE", binding_value), secret(candidate, "VALIDATE"), domain(candidate, active=False), "DOMAIN_BINDING_DENIED"),
        )
        for index, (endpoint_grant, secret_grant, observation, reason) in enumerate(cases):
            with self.subTest(reason=reason), self.assertRaisesRegex(IngestionFailure, reason):
                target.validate_source(
                    caller,
                    source_permit,
                    candidate.source_id,
                    expected_revision=created.revision,
                    endpoint=endpoint_grant,
                    secret=secret_grant,
                    domain=observation,
                    binding=binding_value,
                    idempotency_key=f"dependency-{index}",
                    correlation_id=identifier(f"dependency:{index}"),
                )
        self.assertEqual(target.store.snapshot().source_revisions[(caller.organization_id, candidate.source_id)], [created])


class LeaseTests(unittest.TestCase):
    def test_renew_release_and_reacquire_preserve_monotonic_fencing(self) -> None:
        clock = Clock()
        caller = identity()
        target = service(clock=clock)
        candidate, _binding, _validated = create_and_validate(target, caller)
        lease = acquire_sample_lease(target, caller, candidate)
        scope = source_scope_digest(caller.organization_id, candidate.source_id)
        renewed = target.renew_lease(
            caller,
            permit(caller, "knowledge.ingestion.lease.renew", scope),
            lease,
            ttl_seconds=180,
            endpoint=endpoint(candidate, "LEASE", _binding),
            secret=secret(candidate, "LEASE"),
            domain=domain(candidate),
            binding=_binding,
            idempotency_key="renew-lease",
            correlation_id=identifier("lease:renew"),
        )
        self.assertIs(renewed.state, LeaseState.RENEWED)
        self.assertEqual(renewed.fencing_token, lease.fencing_token)
        released = target.release_lease(
            caller,
            permit(caller, "knowledge.ingestion.lease.release", scope),
            renewed,
            idempotency_key="release-lease",
            correlation_id=identifier("lease:release"),
        )
        self.assertIs(released.state, LeaseState.RELEASED)
        replacement = target.acquire_lease(
            caller,
            permit(caller, "knowledge.ingestion.lease.acquire", scope),
            candidate.source_id,
            partition="partition-0",
            owner_worker_id="worker-2",
            ttl_seconds=60,
            endpoint=endpoint(candidate, "LEASE", _binding),
            secret=secret(candidate, "LEASE"),
            domain=domain(candidate),
            binding=_binding,
            idempotency_key="replacement-lease",
            correlation_id=identifier("lease:replacement"),
        )
        self.assertGreater(replacement.fencing_token, released.fencing_token)
        self.assertGreater(replacement.revision, released.revision)

    def test_stale_expired_and_foreign_fences_cannot_stage(self) -> None:
        clock = Clock()
        caller = identity()
        target = service(clock=clock)
        candidate, binding_value, validated = create_and_validate(target, caller)
        lease = acquire_sample_lease(target, caller, candidate)
        clock.value = "2026-01-01T00:03:00Z"
        before = target.store.snapshot()
        with self.assertRaisesRegex(IngestionFailure, "LEASE_EXPIRED"):
            sample(target, caller, candidate, binding_value, validated.revision, lease)
        after = target.store.snapshot()
        self.assertEqual(after, before)
        forged = type(lease)(
            lease.organization_id,
            lease.source_id,
            lease.source_version_digest,
            lease.partition,
            lease.lease_id,
            lease.revision,
            lease.fencing_token + 1,
            lease.owner_worker_id,
            lease.state,
            lease.issued_at,
            lease.expires_at,
            lease.reason_code,
            lease.correlation_id,
        )
        clock.value = "2026-01-01T00:00:30Z"
        with self.assertRaisesRegex(IngestionFailure, "LEASE_FENCE_MISMATCH"):
            sample(target, caller, candidate, binding_value, validated.revision, forged, key="forged-fence")


class AtomicStagingTests(unittest.TestCase):
    def test_sink_failure_or_receipt_mismatch_leaves_no_owned_state(self) -> None:
        for staging, reason in (
            (MemoryStagingPort(fail=True), "STAGING_SINK_UNAVAILABLE"),
            (MemoryStagingPort(mismatch=True), "STAGING_RECEIPT_MISMATCH"),
        ):
            with self.subTest(reason=reason):
                caller = identity()
                target = service()
                candidate, binding_value, validated = create_and_validate(target, caller)
                lease = acquire_sample_lease(target, caller, candidate)
                before = target.store.snapshot()
                with self.assertRaisesRegex(IngestionFailure, reason):
                    sample(target, caller, candidate, binding_value, validated.revision, lease, staging=staging)
                self.assertEqual(target.store.snapshot(), before)

    def test_metadata_commit_failure_aborts_prepared_material_and_is_atomic(self) -> None:
        caller = identity()
        target = service()
        candidate, binding_value, validated = create_and_validate(target, caller)
        lease = acquire_sample_lease(target, caller, candidate)
        staging = MemoryStagingPort()
        before = target.store.snapshot()
        target.store.inject_commit_failure()
        with self.assertRaisesRegex(RuntimeError, "atomic ingestion store commit failed"):
            sample(target, caller, candidate, binding_value, validated.revision, lease, staging=staging)
        self.assertEqual(target.store.snapshot(), before)
        self.assertEqual(len(staging.aborted), 1)

    def test_stale_revision_denies_before_connector_and_idempotent_replay_skips_connector(self) -> None:
        caller = identity()
        target = service()
        candidate, binding_value, validated = create_and_validate(target, caller)
        lease = acquire_sample_lease(target, caller, candidate)
        stale_port = FixturePort(candidate.connector_kind)
        with self.assertRaisesRegex(IngestionFailure, "STALE_REVISION"):
            sample(
                target,
                caller,
                candidate,
                binding_value,
                validated.revision + 1,
                lease,
                port=stale_port,
                key="stale-sample",
            )
        self.assertEqual(stale_port.calls, [])
        first = sample(target, caller, candidate, binding_value, validated.revision, lease)
        replay_port = FixturePort(candidate.connector_kind)
        replay = sample(target, caller, candidate, binding_value, validated.revision, lease, port=replay_port)
        self.assertEqual(replay, first)
        self.assertEqual(replay_port.calls, [])


if __name__ == "__main__":
    unittest.main()
