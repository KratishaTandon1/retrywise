from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from retrywise.services.control_plane.outbox import (
    BackoffPolicy,
    OutboxJob,
    OutboxLeaseError,
    OutboxNotReady,
    OutboxState,
    OutboxTransitionError,
    OutboxVersionConflict,
    RetryMode,
)

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


def pending(*, max_attempts: int = 3, available_at: datetime | None = None) -> OutboxJob:
    return OutboxJob.create(
        job_id="job_1",
        action_key="act_1",
        payload_digest="a" * 64,
        now=NOW,
        max_attempts=max_attempts,
        available_at=available_at,
    )


class OutboxJobTests(unittest.TestCase):
    def test_transitions_are_immutable_fenced_and_completion_is_idempotent(self) -> None:
        original = pending()
        leased = original.claim(
            worker_id="worker_a",
            now=NOW,
            lease_duration=timedelta(seconds=30),
            expected_version=0,
        )

        self.assertEqual(OutboxState.PENDING, original.state)
        self.assertEqual(0, original.version)
        self.assertEqual(OutboxState.LEASED, leased.state)
        self.assertEqual(1, leased.version)
        self.assertEqual(1, leased.attempts)
        self.assertTrue(leased.lease_token.startswith("lease_"))

        with self.assertRaises(OutboxVersionConflict):
            leased.complete(
                worker_id="worker_a",
                lease_token=leased.lease_token,
                now=NOW + timedelta(seconds=1),
                expected_version=0,
                result_reference="plink_1",
            )
        with self.assertRaises(OutboxLeaseError):
            leased.complete(
                worker_id="worker_b",
                lease_token=leased.lease_token,
                now=NOW + timedelta(seconds=1),
                expected_version=1,
                result_reference="plink_1",
            )

        completed = leased.complete(
            worker_id="worker_a",
            lease_token=leased.lease_token,
            now=NOW + timedelta(seconds=1),
            expected_version=1,
            result_reference="plink_1",
        )
        replayed = completed.complete(
            worker_id="worker_a",
            lease_token="lease_old_ack",
            now=NOW + timedelta(minutes=1),
            expected_version=1,
            result_reference="plink_1",
        )
        self.assertIs(completed, replayed)
        self.assertEqual(OutboxState.COMPLETED, completed.state)
        with self.assertRaises(OutboxTransitionError):
            completed.complete(
                worker_id="worker_a",
                lease_token="lease_old_ack",
                now=NOW + timedelta(minutes=1),
                expected_version=completed.version,
                result_reference="plink_different",
            )
        with self.assertRaises(OutboxTransitionError):
            completed.claim(
                worker_id="worker_a",
                now=NOW + timedelta(minutes=1),
                lease_duration=timedelta(seconds=30),
                expected_version=completed.version,
            )

    def test_exact_expiry_reclaims_with_new_fence_and_reconcile_only_mode(self) -> None:
        first = pending().claim(
            worker_id="worker_a",
            now=NOW,
            lease_duration=timedelta(seconds=10),
            expected_version=0,
        )
        reclaimed = first.claim(
            worker_id="worker_b",
            now=NOW + timedelta(seconds=10),
            lease_duration=timedelta(seconds=20),
            expected_version=first.version,
        )

        self.assertEqual(2, reclaimed.attempts)
        self.assertEqual(RetryMode.RECONCILE_ONLY, reclaimed.retry_mode)
        self.assertNotEqual(first.lease_token, reclaimed.lease_token)
        with self.assertRaises(OutboxLeaseError):
            reclaimed.complete(
                worker_id="worker_a",
                lease_token=first.lease_token,
                now=NOW + timedelta(seconds=11),
                expected_version=reclaimed.version,
                result_reference="plink_1",
            )
        with self.assertRaises(OutboxLeaseError):
            first.complete(
                worker_id="worker_a",
                lease_token=first.lease_token,
                now=NOW + timedelta(seconds=10),
                expected_version=first.version,
                result_reference="plink_1",
            )

    def test_retry_schedule_is_deterministic_bounded_and_final_failure_dead_letters(self) -> None:
        backoff = BackoffPolicy(
            base_delay=timedelta(seconds=2),
            maximum_delay=timedelta(seconds=5),
        )
        self.assertEqual(timedelta(seconds=2), backoff.delay_after(1))
        self.assertEqual(timedelta(seconds=4), backoff.delay_after(2))
        self.assertEqual(timedelta(seconds=5), backoff.delay_after(3))
        self.assertEqual(timedelta(seconds=5), backoff.delay_after(10_000))

        first = pending(max_attempts=3).claim(
            worker_id="worker",
            now=NOW,
            lease_duration=timedelta(minutes=1),
            expected_version=0,
        )
        retry_one = first.requeue(
            worker_id="worker",
            lease_token=first.lease_token,
            now=NOW + timedelta(seconds=1),
            expected_version=first.version,
            reason="provider_unavailable",
            backoff=backoff,
            retry_mode=RetryMode.RETRY_SAME_EFFECT,
        )
        self.assertEqual(NOW + timedelta(seconds=3), retry_one.available_at)

        second = retry_one.claim(
            worker_id="worker",
            now=retry_one.available_at,
            lease_duration=timedelta(minutes=1),
            expected_version=retry_one.version,
        )
        retry_two = second.requeue(
            worker_id="worker",
            lease_token=second.lease_token,
            now=second.updated_at + timedelta(seconds=1),
            expected_version=second.version,
            reason="provider_unavailable",
            backoff=backoff,
            retry_mode=RetryMode.RETRY_SAME_EFFECT,
        )
        self.assertEqual(second.updated_at + timedelta(seconds=5), retry_two.available_at)

        third = retry_two.claim(
            worker_id="worker",
            now=retry_two.available_at,
            lease_duration=timedelta(minutes=1),
            expected_version=retry_two.version,
        )
        exhausted = third.requeue(
            worker_id="worker",
            lease_token=third.lease_token,
            now=third.updated_at + timedelta(seconds=1),
            expected_version=third.version,
            reason="provider_unavailable",
            backoff=backoff,
            retry_mode=RetryMode.RETRY_SAME_EFFECT,
        )
        self.assertEqual(OutboxState.DEAD_LETTER, exhausted.state)
        self.assertEqual(
            "max_attempts_exhausted:provider_unavailable",
            exhausted.dead_letter_reason,
        )

    def test_pending_and_live_leases_cannot_be_claimed_early(self) -> None:
        later = pending(available_at=NOW + timedelta(seconds=5))
        with self.assertRaises(OutboxNotReady):
            later.claim(
                worker_id="worker",
                now=NOW,
                lease_duration=timedelta(seconds=10),
                expected_version=0,
            )
        leased = pending().claim(
            worker_id="worker_a",
            now=NOW,
            lease_duration=timedelta(seconds=10),
            expected_version=0,
        )
        with self.assertRaises(OutboxLeaseError):
            leased.claim(
                worker_id="worker_b",
                now=NOW + timedelta(seconds=9),
                lease_duration=timedelta(seconds=10),
                expected_version=leased.version,
            )


if __name__ == "__main__":
    unittest.main()
