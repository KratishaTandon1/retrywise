from __future__ import annotations

import unittest
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

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
from retrywise.packages.razorpay import make_recovery_reference_id
from retrywise.services.control_plane.cancellation import (
    CancellationDisposition,
    CancellationTarget,
    CancelPaymentLinkCommand,
    CancelPaymentLinkExecutor,
    DurableInstrumentBinding,
    DurableInstrumentStatus,
    ProviderCancellationResult,
    ProviderCancellationStatus,
    ProviderPaymentLinkStatus,
    ProviderPaymentLinkTruth,
)
from retrywise.services.control_plane.outbox import OutboxJob, OutboxState, RetryMode

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
WORKER = "worker_1"
PAYMENT_LINK_ID = "plink_ExjpAUN3gVHrPJ"
PROVIDER_ACCOUNT = "provider_account_1"
REFERENCE_ID = make_recovery_reference_id(
    "case_1",
    provider_account_id=PROVIDER_ACCOUNT,
)


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
        proposal_id="proposal_cancel_1",
        merchant_id="merchant_1",
        case_id="case_1",
        decision_version=2,
        action_type=ActionType.CANCEL_PAYMENT_LINK,
        created_at=NOW - timedelta(minutes=10),
        expires_at=NOW + timedelta(minutes=50),
        instrument_reference=PAYMENT_LINK_ID,
    )


def snapshot(*, active_instrument_count: int = 1) -> ProviderSnapshot:
    observed_at = NOW - timedelta(seconds=1)
    return ProviderSnapshot(
        payment_state=CanonicalPaymentState.UNPAID,
        amount_due=Money(129_900, "INR"),
        payment_method="upi",
        observed_at=observed_at,
        active_instrument_count=active_instrument_count,
        incident_state=IncidentState.NORMAL,
        method_health_observed_at=observed_at,
    )


def context(*, effects_enabled: bool = True, active_instrument_count: int = 1) -> GateContext:
    return GateContext(
        merchant_id="merchant_1",
        case_id="case_1",
        evaluated_at=NOW,
        aggregate_version=5,
        expected_aggregate_version=5,
        recovery_state=RecoveryState.ACTIVE,
        snapshot=snapshot(active_instrument_count=active_instrument_count),
        environment_effects_enabled=effects_enabled,
    )


def command() -> tuple[DeterministicGate, CancelPaymentLinkCommand]:
    gate = DeterministicGate(policy())
    candidate = proposal()
    planning = replace(
        context(),
        evaluated_at=NOW - timedelta(minutes=9),
        snapshot=replace(snapshot(), observed_at=NOW - timedelta(minutes=9, seconds=1)),
    )
    plan = gate.evaluate_policy(candidate, planning)
    assert plan.allowed
    target = CancellationTarget(
        merchant_id=candidate.merchant_id,
        case_id=candidate.case_id,
        action_id="action_cancel_1",
        action_key=candidate.action_key,
        instrument_id="instrument_1",
        provider_account_id=PROVIDER_ACCOUNT,
        payment_link_id=PAYMENT_LINK_ID,
        reference_id=REFERENCE_ID,
        amount_minor=129_900,
        currency="INR",
    )
    return gate, CancelPaymentLinkCommand(candidate, plan, target)


def truth(
    status: ProviderPaymentLinkStatus = ProviderPaymentLinkStatus.CREATED,
    **overrides: object,
) -> ProviderPaymentLinkTruth:
    amount_paid_minor = {
        ProviderPaymentLinkStatus.PAID: 129_900,
        ProviderPaymentLinkStatus.PARTIALLY_PAID: 64_950,
    }.get(status, 0)
    values: dict[str, object] = {
        "payment_link_id": PAYMENT_LINK_ID,
        "reference_id": REFERENCE_ID,
        "amount_minor": 129_900,
        "amount_paid_minor": amount_paid_minor,
        "currency": "INR",
        "accept_partial": False,
        "upi_link": False,
        "status": status,
    }
    values.update(overrides)
    return ProviderPaymentLinkTruth(**values)  # type: ignore[arg-type]


def binding(
    effect_command: CancelPaymentLinkCommand,
    status: DurableInstrumentStatus = DurableInstrumentStatus.ACTIVE,
    *,
    target: CancellationTarget | None = None,
) -> DurableInstrumentBinding:
    return DurableInstrumentBinding.record(
        target or effect_command.target,
        instrument_status=status,
        recorded_at=NOW - timedelta(hours=1),
    )


def leased_job(
    effect_command: CancelPaymentLinkCommand,
    *,
    retry_mode: RetryMode = RetryMode.NORMAL,
    max_attempts: int = 5,
) -> OutboxJob:
    pending = OutboxJob.create(
        job_id="job_cancel_1",
        action_key=effect_command.proposal.action_key,
        payload_digest=effect_command.payload_digest,
        now=NOW - timedelta(minutes=1),
        max_attempts=max_attempts,
    )
    leased = pending.claim(
        worker_id=WORKER,
        now=NOW - timedelta(seconds=1),
        lease_duration=timedelta(minutes=5),
        expected_version=pending.version,
    )
    return replace(leased, retry_mode=retry_mode)


def reclaimed_job(
    effect_command: CancelPaymentLinkCommand,
    *,
    max_attempts: int = 5,
) -> OutboxJob:
    pending = OutboxJob.create(
        job_id="job_cancel_reclaimed_1",
        action_key=effect_command.proposal.action_key,
        payload_digest=effect_command.payload_digest,
        now=NOW - timedelta(minutes=10),
        max_attempts=max_attempts,
    )
    crashed = pending.claim(
        worker_id="worker_that_crashed_before_call",
        now=NOW - timedelta(minutes=2),
        lease_duration=timedelta(minutes=1),
        expected_version=pending.version,
    )
    return crashed.claim(
        worker_id=WORKER,
        now=NOW - timedelta(seconds=1),
        lease_duration=timedelta(minutes=5),
        expected_version=crashed.version,
    )


class BindingReader:
    def __init__(
        self,
        values: list[DurableInstrumentBinding | None],
        trace: list[str],
    ) -> None:
        self.values = list(values)
        self.trace = trace
        self.calls: list[dict[str, str]] = []

    def load_cancellation_binding(self, **kwargs: str) -> DurableInstrumentBinding | None:
        self.trace.append("binding")
        self.calls.append(dict(kwargs))
        if len(self.values) > 1:
            return self.values.pop(0)
        return self.values[0]


class ContextReader:
    def __init__(self, values: list[GateContext], trace: list[str]) -> None:
        self.values = list(values)
        self.trace = trace

    def load_fresh_gate_context(self, **_kwargs: object) -> GateContext:
        self.trace.append("context")
        if len(self.values) > 1:
            return self.values.pop(0)
        return self.values[0]


class Provider:
    def __init__(
        self,
        *,
        fetches: list[object],
        cancel_result: object,
        trace: list[str],
    ) -> None:
        self.fetches = list(fetches)
        self.cancel_result = cancel_result
        self.trace = trace
        self.fetch_calls = 0
        self.cancel_calls = 0

    def fetch_payment_link(self, **_kwargs: str) -> object:
        self.trace.append("fetch")
        self.fetch_calls += 1
        value = self.fetches.pop(0)
        if isinstance(value, Exception):
            raise value
        return value

    def cancel_payment_link(self, **_kwargs: str) -> object:
        self.trace.append("cancel")
        self.cancel_calls += 1
        if isinstance(self.cancel_result, Exception):
            raise self.cancel_result
        return self.cancel_result


class AuthorizationRecorder:
    def __init__(self, trace: list[str]) -> None:
        self.trace = trace
        self.calls = 0

    def record_cancellation_authorization(self, **_kwargs: object) -> None:
        self.trace.append("authorization")
        self.calls += 1


def service(
    *,
    bindings: list[DurableInstrumentBinding | None],
    fetches: list[object],
    cancel_result: object | None = None,
    gate_context: GateContext | list[GateContext] | None = None,
    clock: Callable[[], datetime] | None = None,
    with_authorization_recorder: bool = False,
) -> tuple[
    CancelPaymentLinkExecutor,
    BindingReader,
    Provider,
    CancelPaymentLinkCommand,
    list[str],
]:
    gate, effect_command = command()
    trace: list[str] = []
    binding_reader = BindingReader(bindings, trace)
    provider = Provider(
        fetches=fetches,
        cancel_result=(
            cancel_result
            if cancel_result is not None
            else ProviderCancellationResult(
                ProviderCancellationStatus.CERTAIN_SUCCESS,
                "provider_confirmed_cancel",
                truth(ProviderPaymentLinkStatus.CANCELLED),
            )
        ),
        trace=trace,
    )
    contexts = gate_context if isinstance(gate_context, list) else [gate_context or context()]
    executor = CancelPaymentLinkExecutor(
        gate=gate,
        bindings=binding_reader,
        contexts=ContextReader(contexts, trace),
        provider=provider,
        clock=clock or (lambda: NOW),
        authorization_recorder=(
            AuthorizationRecorder(trace) if with_authorization_recorder else None
        ),
    )
    return executor, binding_reader, provider, effect_command, trace


class CancelPaymentLinkExecutorTests(unittest.TestCase):
    def test_target_rejects_non_controller_derived_reference(self) -> None:
        _gate, effect_command = command()

        with self.assertRaisesRegex(ValueError, "controller-derived"):
            replace(effect_command.target, reference_id="rtw_safe_but_arbitrary")

    def test_confirmed_cancel_requires_post_effect_truth_and_durable_binding(self) -> None:
        _gate, effect_command = command()
        executor, binding_reader, provider, effect_command, trace = service(
            bindings=[
                binding(effect_command),
                binding(effect_command),
                binding(effect_command),
            ],
            fetches=[truth(), truth(ProviderPaymentLinkStatus.CANCELLED)],
            gate_context=[
                context(),
                replace(
                    context(),
                    aggregate_version=6,
                    expected_aggregate_version=6,
                ),
            ],
        )

        result = executor.execute(
            job=leased_job(effect_command),
            command=effect_command,
            worker_id=WORKER,
        )

        self.assertEqual(CancellationDisposition.CANCELLED, result.disposition)
        self.assertEqual(OutboxState.COMPLETED, result.job.state)
        self.assertTrue(result.cancel_attempted)
        self.assertEqual(6, result.effect_decision.aggregate_version)
        self.assertEqual(
            [
                "binding",
                "context",
                "fetch",
                "binding",
                "context",
                "cancel",
                "fetch",
                "binding",
            ],
            trace,
        )
        self.assertEqual(3, len(binding_reader.calls))
        self.assertEqual(2, provider.fetch_calls)
        self.assertEqual(1, provider.cancel_calls)
        for call in binding_reader.calls:
            self.assertEqual(effect_command.target_digest, call["target_digest"])
            self.assertEqual(PAYMENT_LINK_ID, call["payment_link_id"])

    def test_authorization_is_committed_immediately_before_provider_cancel(self) -> None:
        _gate, effect_command = command()
        executor, _reader, provider, effect_command, trace = service(
            bindings=[
                binding(effect_command),
                binding(effect_command),
                binding(effect_command),
            ],
            fetches=[truth(), truth(ProviderPaymentLinkStatus.CANCELLED)],
            with_authorization_recorder=True,
        )

        result = executor.execute(
            job=leased_job(effect_command),
            command=effect_command,
            worker_id=WORKER,
        )

        self.assertEqual(CancellationDisposition.CANCELLED, result.disposition)
        self.assertEqual(1, provider.cancel_calls)
        self.assertEqual("authorization", trace[trace.index("cancel") - 1])

    def test_missing_or_changed_durable_binding_never_reaches_provider(self) -> None:
        _gate, effect_command = command()
        mismatched_target = replace(effect_command.target, instrument_id="instrument_other")
        cases = (
            [None],
            [binding(effect_command, target=mismatched_target)],
        )
        for values in cases:
            with self.subTest(values=values):
                executor, _reader, provider, effect_command, _trace = service(
                    bindings=values,
                    fetches=[truth()],
                )
                result = executor.execute(
                    job=leased_job(effect_command),
                    command=effect_command,
                    worker_id=WORKER,
                )
                self.assertEqual(CancellationDisposition.ESCALATED, result.disposition)
                self.assertEqual(OutboxState.DEAD_LETTER, result.job.state)
                self.assertEqual(0, provider.fetch_calls)
                self.assertEqual(0, provider.cancel_calls)

    def test_provider_target_mismatch_never_reaches_cancel(self) -> None:
        _gate, effect_command = command()
        executor, _reader, provider, effect_command, _trace = service(
            bindings=[binding(effect_command)],
            fetches=[truth(reference_id="rtw_other_reference")],
        )

        result = executor.execute(
            job=leased_job(effect_command), command=effect_command, worker_id=WORKER
        )

        self.assertEqual(CancellationDisposition.ESCALATED, result.disposition)
        self.assertEqual(0, provider.cancel_calls)

    def test_paid_or_partially_paid_truth_always_opens_review_without_cancel(self) -> None:
        for status in (
            ProviderPaymentLinkStatus.PAID,
            ProviderPaymentLinkStatus.PARTIALLY_PAID,
        ):
            with self.subTest(status=status):
                _gate, effect_command = command()
                executor, _reader, provider, effect_command, _trace = service(
                    bindings=[binding(effect_command)],
                    fetches=[truth(status)],
                )
                result = executor.execute(
                    job=leased_job(effect_command),
                    command=effect_command,
                    worker_id=WORKER,
                )
                self.assertEqual(CancellationDisposition.REVIEW_REQUIRED, result.disposition)
                self.assertEqual(OutboxState.DEAD_LETTER, result.job.state)
                self.assertEqual(status, result.provider_status)
                self.assertEqual(0, provider.cancel_calls)

    def test_provider_truth_amount_paid_is_bounded_and_status_consistent(self) -> None:
        invalid = (
            (ProviderPaymentLinkStatus.CREATED, 1),
            (ProviderPaymentLinkStatus.CANCELLED, 1),
            (ProviderPaymentLinkStatus.EXPIRED, 1),
            (ProviderPaymentLinkStatus.PAID, 0),
            (ProviderPaymentLinkStatus.PAID, 129_899),
            (ProviderPaymentLinkStatus.PARTIALLY_PAID, 0),
            (ProviderPaymentLinkStatus.PARTIALLY_PAID, 129_900),
            (ProviderPaymentLinkStatus.CREATED, -1),
            (ProviderPaymentLinkStatus.CREATED, 129_901),
        )
        for status, amount_paid_minor in invalid:
            with (
                self.subTest(
                    status=status,
                    amount_paid_minor=amount_paid_minor,
                ),
                self.assertRaises(ValueError),
            ):
                truth(status, amount_paid_minor=amount_paid_minor)

    def test_invalid_structural_amount_paid_fails_closed_before_cancel(self) -> None:
        _gate, effect_command = command()
        invalid_truth = SimpleNamespace(
            payment_link_id=PAYMENT_LINK_ID,
            reference_id=REFERENCE_ID,
            amount_minor=129_900,
            amount_paid_minor=1,
            currency="INR",
            accept_partial=False,
            upi_link=False,
            status="created",
        )
        executor, _reader, provider, effect_command, _trace = service(
            bindings=[binding(effect_command)],
            fetches=[invalid_truth],
        )

        result = executor.execute(
            job=leased_job(effect_command), command=effect_command, worker_id=WORKER
        )

        self.assertEqual(CancellationDisposition.RECONCILE_REQUIRED, result.disposition)
        self.assertEqual(0, provider.cancel_calls)

    def test_durable_paid_state_opens_review_even_if_provider_still_says_created(self) -> None:
        _gate, effect_command = command()
        executor, _reader, provider, effect_command, _trace = service(
            bindings=[binding(effect_command, DurableInstrumentStatus.PAID)],
            fetches=[truth()],
        )

        result = executor.execute(
            job=leased_job(effect_command), command=effect_command, worker_id=WORKER
        )

        self.assertEqual(CancellationDisposition.REVIEW_REQUIRED, result.disposition)
        self.assertEqual(0, provider.cancel_calls)

    def test_already_cancelled_or_expired_provider_truth_completes_without_cancel(self) -> None:
        expected = {
            ProviderPaymentLinkStatus.CANCELLED: CancellationDisposition.ALREADY_CANCELLED,
            ProviderPaymentLinkStatus.EXPIRED: CancellationDisposition.EXPIRED,
        }
        for status, disposition in expected.items():
            with self.subTest(status=status):
                _gate, effect_command = command()
                executor, _reader, provider, effect_command, _trace = service(
                    bindings=[binding(effect_command)],
                    fetches=[truth(status)],
                )
                result = executor.execute(
                    job=leased_job(effect_command),
                    command=effect_command,
                    worker_id=WORKER,
                )
                self.assertEqual(disposition, result.disposition)
                self.assertEqual(OutboxState.COMPLETED, result.job.state)
                self.assertEqual(0, provider.cancel_calls)

    def test_pre_effect_binding_refresh_catches_a_paid_transition(self) -> None:
        _gate, effect_command = command()
        executor, _reader, provider, effect_command, trace = service(
            bindings=[
                binding(effect_command),
                binding(effect_command, DurableInstrumentStatus.PAID),
            ],
            fetches=[truth()],
        )

        result = executor.execute(
            job=leased_job(effect_command), command=effect_command, worker_id=WORKER
        )

        self.assertEqual(CancellationDisposition.REVIEW_REQUIRED, result.disposition)
        self.assertEqual(["binding", "context", "fetch", "binding"], trace)
        self.assertEqual(0, provider.cancel_calls)

    def test_recovered_lease_grants_one_freshly_checked_effect_retry(self) -> None:
        _gate, effect_command = command()
        recovered = reclaimed_job(effect_command)
        self.assertEqual(RetryMode.RECONCILE_ONLY, recovered.retry_mode)
        executor, _reader, provider, effect_command, trace = service(
            bindings=[binding(effect_command), binding(effect_command)],
            fetches=[truth()],
        )

        result = executor.execute(
            job=recovered,
            command=effect_command,
            worker_id=WORKER,
        )

        self.assertEqual(CancellationDisposition.RECONCILE_REQUIRED, result.disposition)
        self.assertEqual(RetryMode.RETRY_SAME_EFFECT, result.job.retry_mode)
        self.assertEqual(["binding", "context", "fetch", "binding"], trace)
        self.assertEqual(0, provider.cancel_calls)

        assert result.job.available_at is not None
        next_now = result.job.available_at
        retry_job = result.job.claim(
            worker_id=WORKER,
            now=next_now,
            lease_duration=timedelta(minutes=5),
            expected_version=result.job.version,
        )
        retry_executor, _reader, retry_provider, retry_command, _trace = service(
            bindings=[
                binding(effect_command),
                binding(effect_command),
                binding(effect_command),
            ],
            fetches=[truth(), truth(ProviderPaymentLinkStatus.CANCELLED)],
            clock=lambda: next_now,
        )
        retried = retry_executor.execute(
            job=retry_job,
            command=retry_command,
            worker_id=WORKER,
        )

        self.assertEqual(CancellationDisposition.CANCELLED, retried.disposition)
        self.assertEqual(OutboxState.COMPLETED, retried.job.state)
        self.assertEqual(1, retry_provider.cancel_calls)

    def test_recovered_lease_retry_budget_is_bounded(self) -> None:
        _gate, effect_command = command()
        executor, _reader, provider, effect_command, _trace = service(
            bindings=[binding(effect_command), binding(effect_command)],
            fetches=[truth()],
        )

        result = executor.execute(
            job=reclaimed_job(effect_command, max_attempts=2),
            command=effect_command,
            worker_id=WORKER,
        )

        self.assertEqual(CancellationDisposition.DEAD_LETTER, result.disposition)
        self.assertEqual(OutboxState.DEAD_LETTER, result.job.state)
        self.assertEqual(0, provider.cancel_calls)

    def test_every_nonconfirmed_outcome_refetches_and_adopts_cancelled_truth(self) -> None:
        outcomes: tuple[object, ...] = (
            ProviderCancellationResult(
                ProviderCancellationStatus.CERTAIN_FAILURE,
                "provider_rejected_cancel_http_400",
            ),
            ProviderCancellationResult(
                ProviderCancellationStatus.AMBIGUOUS,
                "provider_write_timeout_unknown_outcome",
            ),
            RuntimeError("private provider detail"),
            object(),
        )
        for outcome in outcomes:
            with self.subTest(outcome=type(outcome).__name__):
                _gate, effect_command = command()
                executor, _reader, provider, effect_command, trace = service(
                    bindings=[
                        binding(effect_command),
                        binding(effect_command),
                        binding(effect_command),
                    ],
                    fetches=[
                        truth(),
                        truth(ProviderPaymentLinkStatus.CANCELLED),
                    ],
                    cancel_result=outcome,
                )
                result = executor.execute(
                    job=leased_job(effect_command),
                    command=effect_command,
                    worker_id=WORKER,
                )
                self.assertEqual(CancellationDisposition.CANCELLED, result.disposition)
                self.assertTrue(result.cancel_attempted)
                self.assertEqual(2, provider.fetch_calls)
                self.assertEqual(1, provider.cancel_calls)
                self.assertEqual(
                    [
                        "binding",
                        "context",
                        "fetch",
                        "binding",
                        "context",
                        "cancel",
                        "fetch",
                        "binding",
                    ],
                    trace,
                )

    def test_certain_success_never_completes_without_post_effect_truth(self) -> None:
        _gate, effect_command = command()
        executor, _reader, provider, effect_command, _trace = service(
            bindings=[
                binding(effect_command),
                binding(effect_command),
                binding(effect_command),
            ],
            fetches=[truth(), RuntimeError("private provider detail")],
        )

        result = executor.execute(
            job=leased_job(effect_command), command=effect_command, worker_id=WORKER
        )

        self.assertEqual(CancellationDisposition.RECONCILE_REQUIRED, result.disposition)
        self.assertEqual(OutboxState.PENDING, result.job.state)
        self.assertEqual(RetryMode.RECONCILE_ONLY, result.job.retry_mode)
        self.assertEqual(2, provider.fetch_calls)
        self.assertEqual(1, provider.cancel_calls)

    def test_certain_success_concurrent_paid_truth_or_binding_opens_review(self) -> None:
        cases = (
            (DurableInstrumentStatus.ACTIVE, ProviderPaymentLinkStatus.PAID),
            (DurableInstrumentStatus.PAID, ProviderPaymentLinkStatus.CANCELLED),
        )
        for final_binding_status, post_status in cases:
            with self.subTest(
                final_binding_status=final_binding_status,
                post_status=post_status,
            ):
                _gate, effect_command = command()
                executor, _reader, provider, effect_command, _trace = service(
                    bindings=[
                        binding(effect_command),
                        binding(effect_command),
                        binding(effect_command, final_binding_status),
                    ],
                    fetches=[truth(), truth(post_status)],
                )

                result = executor.execute(
                    job=leased_job(effect_command),
                    command=effect_command,
                    worker_id=WORKER,
                )

                self.assertEqual(CancellationDisposition.REVIEW_REQUIRED, result.disposition)
                self.assertEqual(OutboxState.DEAD_LETTER, result.job.state)
                self.assertEqual(1, provider.cancel_calls)

    def test_nonconfirmed_post_cancel_paid_truth_opens_review(self) -> None:
        for status in (
            ProviderPaymentLinkStatus.PAID,
            ProviderPaymentLinkStatus.PARTIALLY_PAID,
        ):
            with self.subTest(status=status):
                _gate, effect_command = command()
                executor, _reader, _provider, effect_command, _trace = service(
                    bindings=[
                        binding(effect_command),
                        binding(effect_command),
                        binding(effect_command),
                    ],
                    fetches=[truth(), truth(status)],
                    cancel_result=ProviderCancellationResult(
                        ProviderCancellationStatus.CERTAIN_FAILURE,
                        "provider_rejected_cancel_http_404",
                    ),
                )
                result = executor.execute(
                    job=leased_job(effect_command),
                    command=effect_command,
                    worker_id=WORKER,
                )
                self.assertEqual(CancellationDisposition.REVIEW_REQUIRED, result.disposition)
                self.assertEqual(status, result.provider_status)
                self.assertEqual(OutboxState.DEAD_LETTER, result.job.state)

    def test_post_effect_created_grants_retry_but_unavailable_truth_stays_reconcile_only(
        self,
    ) -> None:
        for post_fetch in (truth(), RuntimeError("private provider detail")):
            with self.subTest(post_fetch=type(post_fetch).__name__):
                _gate, effect_command = command()
                executor, _reader, _provider, effect_command, _trace = service(
                    bindings=[
                        binding(effect_command),
                        binding(effect_command),
                        binding(effect_command),
                    ],
                    fetches=[truth(), post_fetch],
                    cancel_result=ProviderCancellationResult(
                        ProviderCancellationStatus.AMBIGUOUS,
                        "provider_timeout_unknown_outcome",
                    ),
                )
                result = executor.execute(
                    job=leased_job(effect_command),
                    command=effect_command,
                    worker_id=WORKER,
                )
                self.assertEqual(CancellationDisposition.RECONCILE_REQUIRED, result.disposition)
                self.assertEqual(OutboxState.PENDING, result.job.state)
                expected_mode = (
                    RetryMode.RECONCILE_ONLY
                    if isinstance(post_fetch, Exception)
                    else RetryMode.RETRY_SAME_EFFECT
                )
                self.assertEqual(expected_mode, result.job.retry_mode)

    def test_provider_reason_must_be_machine_code_and_free_text_never_persists(self) -> None:
        with self.assertRaisesRegex(ValueError, "machine code"):
            ProviderCancellationResult(
                ProviderCancellationStatus.AMBIGUOUS,
                "private provider detail",
            )

        _gate, effect_command = command()
        invalid_outcome = SimpleNamespace(
            status="ambiguous",
            reason_code="private provider detail",
            payment_link=None,
        )
        executor, _reader, _provider, effect_command, _trace = service(
            bindings=[
                binding(effect_command),
                binding(effect_command),
                binding(effect_command),
            ],
            fetches=[truth(), truth(ProviderPaymentLinkStatus.CANCELLED)],
            cancel_result=invalid_outcome,
        )

        result = executor.execute(
            job=leased_job(effect_command), command=effect_command, worker_id=WORKER
        )

        self.assertEqual(CancellationDisposition.CANCELLED, result.disposition)
        self.assertNotIn("private provider detail", result.reason_code)

    def test_composite_retry_reason_remains_within_outbox_boundary(self) -> None:
        _gate, effect_command = command()
        executor, _reader, _provider, effect_command, _trace = service(
            bindings=[
                binding(effect_command),
                binding(effect_command),
                binding(effect_command),
            ],
            fetches=[truth(), RuntimeError("private provider detail")],
            cancel_result=ProviderCancellationResult(
                ProviderCancellationStatus.AMBIGUOUS,
                "a" * 128,
            ),
        )

        result = executor.execute(
            job=leased_job(effect_command), command=effect_command, worker_id=WORKER
        )

        self.assertIsNotNone(result.job.last_error)
        assert result.job.last_error is not None
        self.assertLessEqual(len(result.job.last_error), 512)
        self.assertNotIn("private provider detail", result.job.last_error)

    def test_pre_cancel_read_failure_retries_without_calling_cancel(self) -> None:
        _gate, effect_command = command()
        executor, _reader, provider, effect_command, _trace = service(
            bindings=[binding(effect_command)],
            fetches=[RuntimeError("private provider detail")],
        )

        result = executor.execute(
            job=leased_job(effect_command), command=effect_command, worker_id=WORKER
        )

        self.assertEqual(CancellationDisposition.RECONCILE_REQUIRED, result.disposition)
        self.assertEqual(RetryMode.NORMAL, result.job.retry_mode)
        self.assertEqual(0, provider.cancel_calls)
        self.assertNotIn("private provider detail", result.reason_code)

    def test_effect_gate_denial_never_reads_or_cancels_provider(self) -> None:
        _gate, effect_command = command()
        executor, _reader, provider, effect_command, _trace = service(
            bindings=[binding(effect_command)],
            fetches=[truth()],
            gate_context=context(effects_enabled=False),
        )

        result = executor.execute(
            job=leased_job(effect_command), command=effect_command, worker_id=WORKER
        )

        self.assertEqual(CancellationDisposition.BLOCKED, result.disposition)
        self.assertEqual(0, provider.fetch_calls)
        self.assertEqual(0, provider.cancel_calls)

    def test_final_gate_denial_after_prefetch_never_calls_cancel(self) -> None:
        _gate, effect_command = command()
        executor, _reader, provider, effect_command, trace = service(
            bindings=[binding(effect_command), binding(effect_command)],
            fetches=[truth()],
            gate_context=[context(), context(effects_enabled=False)],
        )

        result = executor.execute(
            job=leased_job(effect_command), command=effect_command, worker_id=WORKER
        )

        self.assertEqual(CancellationDisposition.BLOCKED, result.disposition)
        self.assertEqual(OutboxState.DEAD_LETTER, result.job.state)
        self.assertFalse(result.cancel_attempted)
        self.assertIsNotNone(result.effect_decision)
        assert result.effect_decision is not None
        self.assertIn(
            GateReason.ENVIRONMENT_EFFECTS_DISABLED,
            result.effect_decision.reasons,
        )
        self.assertEqual(
            ["binding", "context", "fetch", "binding", "context"],
            trace,
        )
        self.assertEqual(1, provider.fetch_calls)
        self.assertEqual(0, provider.cancel_calls)


if __name__ == "__main__":
    unittest.main()
