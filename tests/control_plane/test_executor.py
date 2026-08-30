from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from retrywise.packages.domain import (
    ActionProposal,
    ActionType,
    CanonicalPaymentState,
    DeterministicGate,
    GateContext,
    GatePolicy,
    GateReason,
    IncidentState,
    Money,
    Probability,
    ProviderSnapshot,
    RecoveryState,
)
from retrywise.packages.razorpay import (
    PaymentLinkLookupResult,
    StandardPaymentLinkRequest,
)
from retrywise.services.control_plane.executor import (
    CreatePaymentLinkCommand,
    CreatePaymentLinkExecutor,
    DurableActionIntent,
    ExecutionDisposition,
    ProviderCreateOutcome,
)
from retrywise.services.control_plane.outbox import (
    BackoffPolicy,
    OutboxJob,
    OutboxState,
    RetryMode,
)

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
WORKER = "worker_1"
PROVIDER_ACCOUNT = "provider_account_1"
REFERENCE = "rtw_case1_abcdefghijklmnopqrstuv"


def policy() -> GatePolicy:
    return GatePolicy(
        version="policy-v1",
        allowed_actions=frozenset(ActionType),
        provider_snapshot_max_age=timedelta(seconds=30),
        incident_health_max_age=timedelta(seconds=60),
        max_attempts=5,
        max_contacts_in_window=2,
        approval_threshold=Money(500_000, "INR"),
        min_confidence=Probability("0.75"),
    )


def proposal() -> ActionProposal:
    return ActionProposal(
        proposal_id="proposal_1",
        merchant_id="merchant_1",
        case_id="case_1",
        decision_version=1,
        action_type=ActionType.CREATE_STANDARD_PAYMENT_LINK,
        created_at=NOW - timedelta(minutes=10),
        expires_at=NOW + timedelta(minutes=50),
        amount=Money(129_900, "INR"),
        payment_method="upi",
        expected_value_minor=30_000,
        model_confidence=Probability("0.90"),
    )


def snapshot(
    *,
    observed_at: datetime,
    payment_state: CanonicalPaymentState = CanonicalPaymentState.UNPAID,
    active_instrument_count: int = 0,
) -> ProviderSnapshot:
    return ProviderSnapshot(
        payment_state=payment_state,
        amount_due=Money(129_900, "INR"),
        payment_method="upi",
        observed_at=observed_at,
        active_instrument_count=active_instrument_count,
        incident_state=IncidentState.NORMAL,
        method_health_observed_at=observed_at,
    )


def planning_context() -> GateContext:
    evaluated_at = NOW - timedelta(minutes=9)
    return GateContext(
        merchant_id="merchant_1",
        case_id="case_1",
        evaluated_at=evaluated_at,
        aggregate_version=3,
        expected_aggregate_version=3,
        recovery_state=RecoveryState.ASSESSING,
        snapshot=snapshot(observed_at=evaluated_at - timedelta(seconds=1)),
        environment_effects_enabled=True,
        observation_deadline=evaluated_at - timedelta(seconds=1),
    )


def request(*, amount_minor: int = 129_900) -> StandardPaymentLinkRequest:
    return StandardPaymentLinkRequest(
        amount_minor=amount_minor,
        currency="INR",
        reference_id=REFERENCE,
        description="Retry payment for order ORD-1042",
        expire_by_epoch=int((NOW + timedelta(hours=1)).timestamp()),
        notes={"recovery_case_id": "case_1", "merchant_order_id": "ORD-1042"},
    )


def command(*, payment_request: StandardPaymentLinkRequest | None = None):
    candidate = proposal()
    gate = DeterministicGate(policy())
    plan = gate.evaluate_policy(candidate, planning_context())
    assert plan.allowed
    return gate, CreatePaymentLinkCommand(
        proposal=candidate,
        prior_plan=plan,
        request=payment_request or request(),
        provider_account_id=PROVIDER_ACCOUNT,
    )


def leased_job(
    effect_command: CreatePaymentLinkCommand,
    *,
    max_attempts: int = 3,
    created_at: datetime = NOW,
) -> OutboxJob:
    return OutboxJob.create(
        job_id="job_1",
        action_key=effect_command.proposal.action_key,
        payload_digest=effect_command.payload_digest,
        now=created_at,
        max_attempts=max_attempts,
    ).claim(
        worker_id=WORKER,
        now=created_at,
        lease_duration=timedelta(minutes=5),
        expected_version=0,
    )


class IntentReader:
    def __init__(self, intent: DurableActionIntent | None) -> None:
        self.intent = intent
        self.calls = 0

    def load_durable_intent(self, *, action_key: str, provider_account_id: str):
        self.calls += 1
        return self.intent


class ContextReader:
    def __init__(
        self,
        *,
        payment_state: CanonicalPaymentState = CanonicalPaymentState.UNPAID,
        active_instrument_count: int = 0,
    ) -> None:
        self.payment_state = payment_state
        self.active_instrument_count = active_instrument_count
        self.calls = 0

    def load_fresh_gate_context(
        self, *, proposal, provider_account_id: str, evaluated_at: datetime
    ) -> GateContext:
        self.calls += 1
        observed_at = evaluated_at - timedelta(seconds=1)
        return GateContext(
            merchant_id=proposal.merchant_id,
            case_id=proposal.case_id,
            evaluated_at=evaluated_at,
            aggregate_version=4,
            expected_aggregate_version=4,
            recovery_state=RecoveryState.ACTION_QUEUED,
            snapshot=snapshot(
                observed_at=observed_at,
                payment_state=self.payment_state,
                active_instrument_count=self.active_instrument_count,
            ),
            environment_effects_enabled=True,
            observation_deadline=evaluated_at - timedelta(seconds=1),
        )


class DelayedContextReader(ContextReader):
    """Return evidence observed after the executor's initial lease check."""

    def load_fresh_gate_context(
        self, *, proposal, provider_account_id: str, evaluated_at: datetime
    ) -> GateContext:
        self.calls += 1
        observed_at = evaluated_at + timedelta(seconds=9)
        return GateContext(
            merchant_id=proposal.merchant_id,
            case_id=proposal.case_id,
            evaluated_at=evaluated_at,
            aggregate_version=4,
            expected_aggregate_version=4,
            recovery_state=RecoveryState.ACTION_QUEUED,
            snapshot=snapshot(observed_at=observed_at),
            environment_effects_enabled=True,
            observation_deadline=evaluated_at - timedelta(seconds=1),
        )


class Provider:
    def __init__(
        self,
        *,
        outcome: ProviderCreateOutcome | None = None,
        lookup: PaymentLinkLookupResult | None = None,
    ) -> None:
        self.outcome = outcome or ProviderCreateOutcome.succeeded("plink_created")
        self.lookup = lookup or PaymentLinkLookupResult(completed=True)
        self.create_calls: list[tuple[StandardPaymentLinkRequest, str]] = []
        self.lookup_calls: list[tuple[str, str]] = []
        self.trace: list[str] = []

    def create_standard_payment_link(self, payment_request, *, provider_account_id):
        self.trace.append("provider_create")
        self.create_calls.append((payment_request, provider_account_id))
        return self.outcome

    def lookup_payment_links(self, *, reference_id, provider_account_id):
        self.trace.append("provider_lookup")
        self.lookup_calls.append((reference_id, provider_account_id))
        return self.lookup


class AuthorizationRecorder:
    def __init__(self, trace: list[str]) -> None:
        self.trace = trace
        self.calls = 0

    def record_effect_authorization(self, **_kwargs: object) -> None:
        self.calls += 1
        self.trace.append("authorization_committed")


def candidate(
    *, amount_minor: int = 129_900, payment_link_id: str = "plink_existing"
) -> dict[str, object]:
    return {
        "id": payment_link_id,
        "reference_id": REFERENCE,
        "amount": amount_minor,
        "currency": "INR",
        "accept_partial": False,
        "upi_link": False,
        "status": "created",
    }


def executor(
    *,
    gate: DeterministicGate,
    effect_command: CreatePaymentLinkCommand,
    provider: Provider,
    contexts: ContextReader | None = None,
    intent: DurableActionIntent | object | None = ...,  # sentinel means valid
    now: datetime = NOW,
    authorization_recorder: object | None = None,
) -> tuple[CreatePaymentLinkExecutor, IntentReader, ContextReader]:
    durable_intent = (
        DurableActionIntent.record(effect_command, recorded_at=NOW) if intent is ... else intent
    )
    intent_reader = IntentReader(durable_intent)  # type: ignore[arg-type]
    context_reader = contexts or ContextReader()
    service = CreatePaymentLinkExecutor(
        gate=gate,
        intents=intent_reader,
        contexts=context_reader,
        provider=provider,
        clock=lambda: now,
        backoff=BackoffPolicy(
            base_delay=timedelta(seconds=2),
            maximum_delay=timedelta(seconds=30),
        ),
        authorization_recorder=authorization_recorder,  # type: ignore[arg-type]
    )
    return service, intent_reader, context_reader


class CreatePaymentLinkExecutorTests(unittest.TestCase):
    def test_effect_timestamp_is_recaptured_after_slow_fresh_reads(self) -> None:
        gate, effect_command = command()
        provider = Provider()
        contexts = DelayedContextReader()
        times = iter((NOW, NOW + timedelta(seconds=10)))
        intent = DurableActionIntent.record(effect_command, recorded_at=NOW)
        service = CreatePaymentLinkExecutor(
            gate=gate,
            intents=IntentReader(intent),
            contexts=contexts,
            provider=provider,
            clock=lambda: next(times),
        )

        result = service.execute(
            job=leased_job(effect_command),
            command=effect_command,
            worker_id=WORKER,
        )

        self.assertEqual(ExecutionDisposition.CREATED, result.disposition)
        self.assertEqual(1, contexts.calls)
        self.assertEqual(1, len(provider.create_calls))

    def test_effect_authorization_is_committed_before_the_provider_create(self) -> None:
        gate, effect_command = command()
        provider = Provider()
        recorder = AuthorizationRecorder(provider.trace)
        service, _, _ = executor(
            gate=gate,
            effect_command=effect_command,
            provider=provider,
            authorization_recorder=recorder,
        )

        result = service.execute(
            job=leased_job(effect_command),
            command=effect_command,
            worker_id=WORKER,
        )

        self.assertEqual(ExecutionDisposition.CREATED, result.disposition)
        self.assertEqual(1, recorder.calls)
        self.assertEqual(["authorization_committed", "provider_create"], provider.trace)

    def test_suppression_does_not_record_effect_authorization(self) -> None:
        gate, effect_command = command()
        provider = Provider()
        recorder = AuthorizationRecorder(provider.trace)
        service, _, _ = executor(
            gate=gate,
            effect_command=effect_command,
            provider=provider,
            contexts=ContextReader(payment_state=CanonicalPaymentState.PAID),
            authorization_recorder=recorder,
        )

        result = service.execute(
            job=leased_job(effect_command),
            command=effect_command,
            worker_id=WORKER,
        )

        self.assertEqual(ExecutionDisposition.SUPPRESSED, result.disposition)
        self.assertEqual(0, recorder.calls)
        self.assertEqual([], provider.trace)

    def test_certain_success_completes_after_exactly_one_create(self) -> None:
        gate, effect_command = command()
        provider = Provider(outcome=ProviderCreateOutcome.succeeded("plink_confirmed"))
        service, _, _ = executor(gate=gate, effect_command=effect_command, provider=provider)

        result = service.execute(
            job=leased_job(effect_command),
            command=effect_command,
            worker_id=WORKER,
        )

        self.assertEqual(ExecutionDisposition.CREATED, result.disposition)
        self.assertEqual(OutboxState.COMPLETED, result.job.state)
        self.assertEqual("plink_confirmed", result.job.completion_reference)
        self.assertEqual(1, len(provider.create_calls))
        self.assertEqual([], provider.lookup_calls)

    def test_certain_fail_safe_outcome_requeues_with_bounded_backoff(self) -> None:
        gate, effect_command = command()
        provider = Provider(
            outcome=ProviderCreateOutcome.failed_safely("provider_rejected_before_create")
        )
        service, _, _ = executor(gate=gate, effect_command=effect_command, provider=provider)

        result = service.execute(
            job=leased_job(effect_command),
            command=effect_command,
            worker_id=WORKER,
        )

        self.assertEqual(ExecutionDisposition.REQUEUED, result.disposition)
        self.assertEqual(OutboxState.PENDING, result.job.state)
        self.assertEqual(RetryMode.RETRY_SAME_EFFECT, result.job.retry_mode)
        self.assertEqual(NOW + timedelta(seconds=2), result.job.available_at)
        self.assertEqual(1, len(provider.create_calls))
        self.assertEqual([], provider.lookup_calls)

    def test_fresh_paid_truth_blocks_before_provider_create_or_lookup(self) -> None:
        gate, effect_command = command()
        provider = Provider()
        contexts = ContextReader(payment_state=CanonicalPaymentState.PAID)
        service, intents, _ = executor(
            gate=gate,
            effect_command=effect_command,
            provider=provider,
            contexts=contexts,
        )

        result = service.execute(
            job=leased_job(effect_command),
            command=effect_command,
            worker_id=WORKER,
        )

        self.assertEqual(ExecutionDisposition.SUPPRESSED, result.disposition)
        self.assertEqual(OutboxState.COMPLETED, result.job.state)
        self.assertIn(GateReason.PAYMENT_TRUTH_NOT_UNPAID, result.effect_decision.reasons)
        self.assertEqual(1, contexts.calls)
        self.assertEqual(1, intents.calls)
        self.assertEqual([], provider.create_calls)
        self.assertEqual([], provider.lookup_calls)

    def test_missing_durable_intent_fails_closed_at_effect_gate(self) -> None:
        gate, effect_command = command()
        provider = Provider()
        service, _, _ = executor(
            gate=gate,
            effect_command=effect_command,
            provider=provider,
            intent=None,
        )

        result = service.execute(
            job=leased_job(effect_command),
            command=effect_command,
            worker_id=WORKER,
        )

        self.assertEqual(ExecutionDisposition.ESCALATED, result.disposition)
        self.assertEqual(OutboxState.DEAD_LETTER, result.job.state)
        self.assertIn(GateReason.DURABLE_INTENT_MISSING, result.effect_decision.reasons)
        self.assertEqual([], provider.create_calls)
        self.assertEqual([], provider.lookup_calls)

    def test_crash_lease_recovery_reconciles_before_any_new_create(self) -> None:
        gate, effect_command = command()
        initial = OutboxJob.create(
            job_id="job_1",
            action_key=effect_command.proposal.action_key,
            payload_digest=effect_command.payload_digest,
            now=NOW - timedelta(minutes=3),
            max_attempts=3,
        ).claim(
            worker_id="crashed_worker",
            now=NOW - timedelta(minutes=2),
            lease_duration=timedelta(seconds=30),
            expected_version=0,
        )
        recovered = initial.claim(
            worker_id=WORKER,
            now=NOW,
            lease_duration=timedelta(minutes=1),
            expected_version=initial.version,
        )
        provider = Provider(
            lookup=PaymentLinkLookupResult(completed=True, candidates=[candidate()])
        )
        service, _, _ = executor(gate=gate, effect_command=effect_command, provider=provider)

        result = service.execute(job=recovered, command=effect_command, worker_id=WORKER)

        self.assertEqual(RetryMode.RECONCILE_ONLY, recovered.retry_mode)
        self.assertEqual(ExecutionDisposition.ADOPTED, result.disposition)
        self.assertEqual("plink_existing", result.payment_link_id)
        self.assertEqual([], provider.create_calls)
        self.assertEqual([(REFERENCE, PROVIDER_ACCOUNT)], provider.lookup_calls)

    def test_accepted_but_response_lost_adopts_matching_existing_link(self) -> None:
        gate, effect_command = command()
        provider = Provider(
            outcome=ProviderCreateOutcome.ambiguous("transport_timeout"),
            lookup=PaymentLinkLookupResult(completed=True, candidates=[candidate()]),
        )
        service, _, _ = executor(gate=gate, effect_command=effect_command, provider=provider)

        result = service.execute(
            job=leased_job(effect_command),
            command=effect_command,
            worker_id=WORKER,
        )

        self.assertEqual(ExecutionDisposition.ADOPTED, result.disposition)
        self.assertEqual(OutboxState.COMPLETED, result.job.state)
        self.assertEqual("plink_existing", result.job.completion_reference)
        self.assertEqual(1, len(provider.create_calls))
        self.assertIs(effect_command.request, provider.create_calls[0][0])
        self.assertEqual([(REFERENCE, PROVIDER_ACCOUNT)], provider.lookup_calls)

    def test_completed_empty_lookup_requeues_the_same_key_request_and_reference(self) -> None:
        gate, effect_command = command()
        provider = Provider(
            outcome=ProviderCreateOutcome.ambiguous("response_lost"),
            lookup=PaymentLinkLookupResult(completed=True),
        )
        service, _, _ = executor(gate=gate, effect_command=effect_command, provider=provider)
        leased = leased_job(effect_command)

        result = service.execute(job=leased, command=effect_command, worker_id=WORKER)

        self.assertEqual(ExecutionDisposition.REQUEUED, result.disposition)
        self.assertEqual(OutboxState.PENDING, result.job.state)
        self.assertEqual(RetryMode.RETRY_SAME_EFFECT, result.job.retry_mode)
        self.assertEqual(leased.action_key, result.job.action_key)
        self.assertEqual(leased.payload_digest, result.job.payload_digest)
        self.assertEqual(REFERENCE, result.reference_id)
        self.assertEqual("completed_lookup_found_no_link", result.job.last_error)
        self.assertEqual(1, len(provider.create_calls))
        self.assertEqual(1, len(provider.lookup_calls))

    def test_conflicting_lookup_candidate_escalates_without_new_reference(self) -> None:
        gate, effect_command = command()
        provider = Provider(
            outcome=ProviderCreateOutcome.ambiguous("malformed_response"),
            lookup=PaymentLinkLookupResult(
                completed=True,
                candidates=[candidate(amount_minor=129_901)],
            ),
        )
        service, _, _ = executor(gate=gate, effect_command=effect_command, provider=provider)

        result = service.execute(
            job=leased_job(effect_command),
            command=effect_command,
            worker_id=WORKER,
        )

        self.assertEqual(ExecutionDisposition.ESCALATED, result.disposition)
        self.assertEqual(OutboxState.DEAD_LETTER, result.job.state)
        self.assertIn("provider_candidate_conflicts_with_command", result.reason_code)
        self.assertEqual(REFERENCE, result.reference_id)
        self.assertEqual(1, len(provider.create_calls))
        self.assertEqual([(REFERENCE, PROVIDER_ACCOUNT)], provider.lookup_calls)

    def test_request_proposal_binding_mismatch_never_reaches_provider(self) -> None:
        gate, effect_command = command(payment_request=request(amount_minor=129_901))
        provider = Provider()
        service, _, _ = executor(gate=gate, effect_command=effect_command, provider=provider)

        result = service.execute(
            job=leased_job(effect_command),
            command=effect_command,
            worker_id=WORKER,
        )

        self.assertEqual(ExecutionDisposition.ESCALATED, result.disposition)
        self.assertIn("proposal_request_amount_mismatch", result.reason_code)
        self.assertEqual([], provider.create_calls)
        self.assertEqual([], provider.lookup_calls)

    def test_incomplete_lookup_persists_lookup_only_mode(self) -> None:
        gate, effect_command = command()
        provider = Provider(
            outcome=ProviderCreateOutcome.ambiguous("transport_timeout"),
            lookup=PaymentLinkLookupResult(completed=False),
        )
        service, _, _ = executor(gate=gate, effect_command=effect_command, provider=provider)

        result = service.execute(
            job=leased_job(effect_command),
            command=effect_command,
            worker_id=WORKER,
        )

        self.assertEqual(ExecutionDisposition.REQUERY_REQUIRED, result.disposition)
        self.assertEqual(RetryMode.RECONCILE_ONLY, result.job.retry_mode)
        self.assertEqual("lookup_not_completed", result.job.last_error)
        self.assertEqual(1, len(provider.create_calls))
        self.assertEqual(1, len(provider.lookup_calls))


if __name__ == "__main__":
    unittest.main()
