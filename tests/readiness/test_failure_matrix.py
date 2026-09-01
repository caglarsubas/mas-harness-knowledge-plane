from __future__ import annotations

import unittest

from planeon_knowledge.common.canonical import canonical_digest
from planeon_knowledge.ingestion.readiness import SourceReadinessState
from planeon_knowledge.ingestion.retries import WorkState
from planeon_knowledge.ingestion.service import (
    IngestionFailure,
    batch_scope_digest,
    dead_letter_scope_digest,
    readiness_scope_digest,
    work_scope_digest,
)
from planeon_knowledge.ingestion.store import StoreFailure

from tests.connectors.support import (
    OTHER_ORGANIZATION_ID,
    identifier,
    identity,
    permit,
    sample,
)
from tests.readiness.support import (
    EVALUATED_AT,
    VALID_UNTIL,
    approval_for,
    assess_and_complete,
    observation_for,
    policy_for,
    staged,
)


class ReadinessFailureMatrixTests(unittest.TestCase):
    def _request_and_claim(self):
        caller, clock, _ingestion, readiness, _source, _binding, _validated, _lease, batch = staged()
        work = readiness.request_assessment(
            caller,
            permit(caller, "knowledge.ingestion.staged-batch.assess", batch_scope_digest(caller.organization_id, batch.batch_id)),
            batch.batch_id,
            policy=policy_for(batch),
            observation=observation_for(batch),
            idempotency_key="failure-assess",
            correlation_id=identifier("correlation:failure-assess"),
        )
        claim = readiness.claim_assessment_work(
            caller,
            permit(caller, "knowledge.ingestion.readiness.process", work_scope_digest(caller.organization_id, work.work_id)),
            work.work_id,
            expected_revision=work.revision,
            ttl_seconds=60,
            correlation_id=identifier("correlation:failure-claim-1"),
        )
        return caller, clock, readiness, batch, work, claim

    def test_work_retries_use_exact_one_and_four_second_metadata_then_dead_letter(self) -> None:
        caller, clock, readiness, _batch, work, claim = self._request_and_claim()
        process_permit = lambda: permit(
            caller,
            "knowledge.ingestion.readiness.process",
            work_scope_digest(caller.organization_id, work.work_id),
        )
        retry_one, dead_letter = readiness.record_assessment_failure(
            caller,
            process_permit(),
            claim,
            reason_code="DEPENDENCY_UNAVAILABLE",
            correlation_id=identifier("correlation:failure-1"),
        )
        self.assertIsNone(dead_letter)
        self.assertIs(retry_one.state, WorkState.RETRY_SCHEDULED)
        self.assertEqual(retry_one.eligible_at, "2026-01-01T00:00:01Z")
        clock.value = retry_one.eligible_at
        claim_two = readiness.claim_assessment_work(
            caller,
            process_permit(),
            work.work_id,
            expected_revision=retry_one.revision,
            ttl_seconds=60,
            correlation_id=identifier("correlation:failure-claim-2"),
        )
        self.assertEqual((claim_two.attempt, claim_two.fencing_token), (2, 2))
        retry_two, dead_letter = readiness.record_assessment_failure(
            caller,
            process_permit(),
            claim_two,
            reason_code="STORE_TRANSIENT",
            correlation_id=identifier("correlation:failure-2"),
        )
        self.assertIsNone(dead_letter)
        self.assertEqual(retry_two.eligible_at, "2026-01-01T00:00:05Z")
        clock.value = retry_two.eligible_at
        claim_three = readiness.claim_assessment_work(
            caller,
            process_permit(),
            work.work_id,
            expected_revision=retry_two.revision,
            ttl_seconds=60,
            correlation_id=identifier("correlation:failure-claim-3"),
        )
        terminal, dead_letter = readiness.record_assessment_failure(
            caller,
            process_permit(),
            claim_three,
            reason_code="EVIDENCE_PUBLISH_UNAVAILABLE",
            correlation_id=identifier("correlation:failure-3"),
        )
        self.assertIs(terminal.state, WorkState.DEAD_LETTERED)
        self.assertIsNotNone(dead_letter)
        self.assertEqual((dead_letter.attempt, dead_letter.fencing_token), (3, 3))
        snapshot = readiness.store.snapshot()
        self.assertEqual(len(snapshot.dead_letters), 1)
        self.assertIs(snapshot.source_readiness_revisions[(caller.organization_id, terminal.source_id)][-1].state, SourceReadinessState.DEGRADED)

    def test_non_retryable_failure_dead_letters_on_first_attempt_and_review_is_append_only(self) -> None:
        caller, _clock, readiness, _batch, work, claim = self._request_and_claim()
        process = permit(caller, "knowledge.ingestion.readiness.process", work_scope_digest(caller.organization_id, work.work_id))
        terminal, dead_letter = readiness.record_assessment_failure(
            caller,
            process,
            claim,
            reason_code="POLICY_STALE",
            correlation_id=identifier("correlation:terminal-failure"),
        )
        self.assertIs(terminal.state, WorkState.DEAD_LETTERED)
        self.assertEqual(terminal.attempt, 1)
        review_permit = permit(
            caller,
            "knowledge.ingestion.dead-letter.review",
            dead_letter_scope_digest(caller.organization_id, dead_letter.dead_letter_id),
        )
        review = readiness.review_dead_letter(
            caller,
            review_permit,
            dead_letter.dead_letter_id,
            decision="ACKNOWLEDGED",
            reason_code="review.accepted",
            idempotency_key="review-dead-letter",
            correlation_id=identifier("correlation:review-dead-letter"),
        )
        replay = readiness.review_dead_letter(
            caller,
            review_permit,
            dead_letter.dead_letter_id,
            decision="ACKNOWLEDGED",
            reason_code="review.accepted",
            idempotency_key="review-dead-letter",
            correlation_id=identifier("correlation:review-dead-letter"),
        )
        self.assertEqual(review, replay)
        snapshot = readiness.store.snapshot()
        self.assertIn((caller.organization_id, dead_letter.dead_letter_id), snapshot.dead_letters)
        self.assertEqual(len(snapshot.dead_letter_reviews[(caller.organization_id, dead_letter.dead_letter_id)]), 1)
        self.assertIs(snapshot.readiness_work_revisions[(caller.organization_id, work.work_id)][-1].state, WorkState.DEAD_LETTERED)

    def test_expired_claim_requires_explicit_recovery_and_preserves_fence(self) -> None:
        caller, clock, readiness, _batch, work, claim = self._request_and_claim()
        clock.value = claim.claim_expires_at
        process = permit(caller, "knowledge.ingestion.readiness.process", work_scope_digest(caller.organization_id, work.work_id))
        with self.assertRaisesRegex(IngestionFailure, "CLAIM_EXPIRED"):
            readiness.record_assessment_failure(
                caller,
                process,
                claim,
                reason_code="CLAIM_EXPIRED",
                correlation_id=identifier("correlation:expired-denied"),
            )
        recovered, dead_letter = readiness.record_assessment_failure(
            caller,
            process,
            claim,
            reason_code="CLAIM_EXPIRED",
            correlation_id=identifier("correlation:expired-recovered"),
            recover_expired=True,
        )
        self.assertIsNone(dead_letter)
        self.assertIs(recovered.state, WorkState.RETRY_SCHEDULED)
        self.assertEqual(recovered.fencing_token, claim.fencing_token)

    def test_stale_wrong_tenant_and_superseded_claims_cannot_publish(self) -> None:
        caller, _clock, readiness, _batch, work, claim = self._request_and_claim()
        other = identity(organization_id=OTHER_ORGANIZATION_ID)
        with self.assertRaisesRegex(IngestionFailure, "WORK_FENCE_MISMATCH"):
            readiness.complete_assessment_work(
                other,
                permit(other, "knowledge.ingestion.readiness.process", work_scope_digest(other.organization_id, work.work_id)),
                claim,
                correlation_id=identifier("correlation:cross-tenant-publish"),
            )
        process = permit(caller, "knowledge.ingestion.readiness.process", work_scope_digest(caller.organization_id, work.work_id))
        readiness.record_assessment_failure(
            caller,
            process,
            claim,
            reason_code="DEPENDENCY_UNAVAILABLE",
            correlation_id=identifier("correlation:supersede-claim"),
        )
        with self.assertRaisesRegex(IngestionFailure, "WORK_FENCE_MISMATCH"):
            readiness.complete_assessment_work(
                caller,
                process,
                claim,
                correlation_id=identifier("correlation:stale-publish"),
            )

    def test_assessment_store_failure_is_atomic_and_original_claim_can_retry(self) -> None:
        caller, _clock, readiness, _batch, work, claim = self._request_and_claim()
        before = readiness.store.snapshot()
        readiness.store.inject_commit_failure()
        process = permit(caller, "knowledge.ingestion.readiness.process", work_scope_digest(caller.organization_id, work.work_id))
        with self.assertRaises(StoreFailure):
            readiness.complete_assessment_work(
                caller,
                process,
                claim,
                correlation_id=identifier("correlation:atomic-failure"),
            )
        self.assertEqual(readiness.store.snapshot(), before)
        assessment = readiness.complete_assessment_work(
            caller,
            process,
            claim,
            correlation_id=identifier("correlation:atomic-retry"),
        )
        self.assertEqual(assessment.overall_status, "READY")

    def test_assessment_idempotency_conflict_and_superseded_pointer_fail_closed(self) -> None:
        caller, _clock, ingestion, readiness, source, binding, _validated, lease, first = staged()
        policy = policy_for(first)
        observation = observation_for(first)
        first_work = readiness.request_assessment(
            caller,
            permit(caller, "knowledge.ingestion.staged-batch.assess", batch_scope_digest(caller.organization_id, first.batch_id)),
            first.batch_id,
            policy=policy,
            observation=observation,
            idempotency_key="assessment-conflict",
            correlation_id=identifier("correlation:assessment-conflict"),
        )
        changed = observation_for(first, latest_source_observation_at="2025-12-31T23:40:00Z")
        with self.assertRaisesRegex(IngestionFailure, "IDEMPOTENCY_CONFLICT"):
            readiness.request_assessment(
                caller,
                permit(caller, "knowledge.ingestion.staged-batch.assess", batch_scope_digest(caller.organization_id, first.batch_id)),
                first.batch_id,
                policy=policy,
                observation=changed,
                idempotency_key="assessment-conflict",
                correlation_id=identifier("correlation:assessment-conflict"),
            )
        claim = readiness.claim_assessment_work(
            caller,
            permit(caller, "knowledge.ingestion.readiness.process", work_scope_digest(caller.organization_id, first_work.work_id)),
            first_work.work_id,
            expected_revision=first_work.revision,
            ttl_seconds=60,
            correlation_id=identifier("correlation:first-superseded-claim"),
        )
        first_assessment = readiness.complete_assessment_work(
            caller,
            permit(caller, "knowledge.ingestion.readiness.process", work_scope_digest(caller.organization_id, first_work.work_id)),
            claim,
            correlation_id=identifier("correlation:first-superseded-complete"),
        )
        first_approval = approval_for(readiness, source, first, first_assessment)
        current_source_revision = ingestion.store.snapshot().source_revisions[(caller.organization_id, source.source_id)][-1]
        second = sample(
            ingestion,
            caller,
            source,
            binding,
            current_source_revision.revision,
            lease,
            key="sample-superseding-batch",
        )
        assess_and_complete(caller, readiness, second)
        before = readiness.store.snapshot()
        with self.assertRaisesRegex(IngestionFailure, "READINESS_SCOPE_MISMATCH"):
            readiness.commit_batch(
                caller,
                permit(caller, "knowledge.ingestion.batch.commit", batch_scope_digest(caller.organization_id, first.batch_id)),
                first.batch_id,
                expected_readiness_revision=2,
                approval=first_approval,
                idempotency_key="commit-superseded",
                correlation_id=identifier("correlation:commit-superseded"),
            )
        self.assertEqual(readiness.store.snapshot(), before)

    def test_commit_requires_independent_exact_owner_approval_and_is_atomic(self) -> None:
        caller, _clock, _ingestion, readiness, source, _binding, _validated, _lease, batch = staged()
        _work, _claim, assessment = assess_and_complete(caller, readiness, batch)
        action_scope = batch_scope_digest(caller.organization_id, batch.batch_id)
        commit_permit = permit(caller, "knowledge.ingestion.batch.commit", action_scope)
        wrong_owner = approval_for(
            readiness,
            source,
            batch,
            assessment,
            owner_digest=canonical_digest({"owner": "not-the-source-owner"}),
        )
        before = readiness.store.snapshot()
        with self.assertRaisesRegex(IngestionFailure, "OWNER_APPROVAL_MISMATCH"):
            readiness.commit_batch(
                caller,
                commit_permit,
                batch.batch_id,
                expected_readiness_revision=1,
                approval=wrong_owner,
                idempotency_key="commit-wrong-owner",
                correlation_id=identifier("correlation:commit-wrong-owner"),
            )
        self.assertEqual(readiness.store.snapshot(), before)

        approval = approval_for(readiness, source, batch, assessment)
        readiness.store.inject_commit_failure()
        with self.assertRaises(StoreFailure):
            readiness.commit_batch(
                caller,
                commit_permit,
                batch.batch_id,
                expected_readiness_revision=1,
                approval=approval,
                idempotency_key="commit-atomic",
                correlation_id=identifier("correlation:commit-atomic"),
            )
        self.assertEqual(readiness.store.snapshot(), before)
        commit = readiness.commit_batch(
            caller,
            commit_permit,
            batch.batch_id,
            expected_readiness_revision=1,
            approval=approval,
            idempotency_key="commit-atomic",
            correlation_id=identifier("correlation:commit-atomic"),
        )
        replay = readiness.commit_batch(
            caller,
            commit_permit,
            batch.batch_id,
            expected_readiness_revision=1,
            approval=approval,
            idempotency_key="commit-atomic",
            correlation_id=identifier("correlation:commit-atomic"),
        )
        self.assertEqual(commit, replay)
        snapshot = readiness.store.snapshot()
        self.assertEqual(len(snapshot.batch_commits), 1)
        self.assertEqual(len(snapshot.checkpoint_revisions[(caller.organization_id, batch.source_id, batch.partition)]), 1)
        self.assertIs(snapshot.source_readiness_revisions[(caller.organization_id, batch.source_id)][-1].state, SourceReadinessState.ACTIVE)
        self.assertEqual([item.event_type for item in snapshot.readiness_events][-2:], ["data.batch.committed.v1", "data.source.activated.v1"])

    def test_stale_approval_and_effective_expiry_degrade_without_history_rewrite(self) -> None:
        caller, clock, _ingestion, readiness, source, _binding, _validated, _lease, batch = staged()
        _work, _claim, assessment = assess_and_complete(caller, readiness, batch)
        stale = approval_for(
            readiness,
            source,
            batch,
            assessment,
            issued_at="2025-12-31T23:00:00Z",
            expires_at=EVALUATED_AT,
        )
        with self.assertRaisesRegex(IngestionFailure, "OWNER_APPROVAL_STALE"):
            readiness.commit_batch(
                caller,
                permit(caller, "knowledge.ingestion.batch.commit", batch_scope_digest(caller.organization_id, batch.batch_id)),
                batch.batch_id,
                expected_readiness_revision=1,
                approval=stale,
                idempotency_key="commit-stale-approval",
                correlation_id=identifier("correlation:commit-stale-approval"),
            )
        approval = approval_for(readiness, source, batch, assessment)
        readiness.commit_batch(
            caller,
            permit(caller, "knowledge.ingestion.batch.commit", batch_scope_digest(caller.organization_id, batch.batch_id)),
            batch.batch_id,
            expected_readiness_revision=1,
            approval=approval,
            idempotency_key="commit-before-expiry",
            correlation_id=identifier("correlation:commit-before-expiry"),
        )
        history_before = readiness.store.snapshot().source_readiness_revisions[(caller.organization_id, source.source_id)]
        clock.value = VALID_UNTIL
        state, _revision = readiness.get_source_readiness(
            caller,
            permit(caller, "knowledge.ingestion.readiness.read", readiness_scope_digest(caller.organization_id, source.source_id), expires_at="2030-01-01T00:00:00Z"),
            source.source_id,
        )
        self.assertEqual(state, "DEGRADED")
        self.assertEqual(readiness.store.snapshot().source_readiness_revisions[(caller.organization_id, source.source_id)], history_before)

    def test_equal_fence_replacement_commit_is_denied_without_moving_checkpoint(self) -> None:
        caller, _clock, ingestion, readiness, source, binding, _validated, lease, first = staged()
        _work, _claim, first_assessment = assess_and_complete(caller, readiness, first)
        first_approval = approval_for(readiness, source, first, first_assessment)
        readiness.commit_batch(
            caller,
            permit(caller, "knowledge.ingestion.batch.commit", batch_scope_digest(caller.organization_id, first.batch_id)),
            first.batch_id,
            expected_readiness_revision=1,
            approval=first_approval,
            idempotency_key="commit-first",
            correlation_id=identifier("correlation:commit-first"),
        )
        current_source_revision = ingestion.store.snapshot().source_revisions[(caller.organization_id, source.source_id)][-1]
        second = sample(
            ingestion,
            caller,
            source,
            binding,
            current_source_revision.revision,
            lease,
            key="sample-replacement",
        )
        _work, _claim, second_assessment = assess_and_complete(caller, readiness, second)
        second_approval = approval_for(readiness, source, second, second_assessment)
        before = readiness.store.snapshot()
        with self.assertRaisesRegex(IngestionFailure, "CHECKPOINT_ORDER_INVALID"):
            readiness.commit_batch(
                caller,
                permit(caller, "knowledge.ingestion.batch.commit", batch_scope_digest(caller.organization_id, second.batch_id)),
                second.batch_id,
                expected_readiness_revision=3,
                approval=second_approval,
                idempotency_key="commit-equal-fence",
                correlation_id=identifier("correlation:commit-equal-fence"),
            )
        after = readiness.store.snapshot()
        self.assertEqual(after.batch_commits, before.batch_commits)
        self.assertEqual(after.checkpoint_revisions, before.checkpoint_revisions)
        self.assertEqual(after.source_readiness_revisions, before.source_readiness_revisions)

    def test_revocation_is_dominant_and_cannot_be_reenabled(self) -> None:
        caller, _clock, ingestion, readiness, source, binding, _validated, lease, first = staged()
        _work, _claim, assessment = assess_and_complete(caller, readiness, first)
        approval = approval_for(readiness, source, first, assessment)
        readiness.commit_batch(
            caller,
            permit(caller, "knowledge.ingestion.batch.commit", batch_scope_digest(caller.organization_id, first.batch_id)),
            first.batch_id,
            expected_readiness_revision=1,
            approval=approval,
            idempotency_key="commit-before-revoke",
            correlation_id=identifier("correlation:commit-before-revoke"),
        )
        current_source_revision = ingestion.store.snapshot().source_revisions[(caller.organization_id, source.source_id)][-1]
        replacement = sample(
            ingestion,
            caller,
            source,
            binding,
            current_source_revision.revision,
            lease,
            key="sample-before-revoke",
        )
        revoked = readiness.revoke_source(
            caller,
            permit(caller, "knowledge.ingestion.source.revoke", readiness_scope_digest(caller.organization_id, source.source_id)),
            source.source_id,
            expected_readiness_revision=2,
            idempotency_key="revoke-source",
            correlation_id=identifier("correlation:revoke-source"),
        )
        self.assertIs(revoked.state, SourceReadinessState.REVOKED)
        with self.assertRaisesRegex(IngestionFailure, "SOURCE_REVOKED"):
            readiness.request_assessment(
                caller,
                permit(caller, "knowledge.ingestion.staged-batch.assess", batch_scope_digest(caller.organization_id, replacement.batch_id)),
                replacement.batch_id,
                policy=policy_for(replacement),
                observation=observation_for(replacement),
                idempotency_key="assess-after-revoke",
                correlation_id=identifier("correlation:assess-after-revoke"),
            )
        state, _revision = readiness.get_source_readiness(
            caller,
            permit(caller, "knowledge.ingestion.readiness.read", readiness_scope_digest(caller.organization_id, source.source_id)),
            source.source_id,
        )
        self.assertEqual(state, "REVOKED")


if __name__ == "__main__":
    unittest.main()
