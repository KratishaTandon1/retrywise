"""Fail-closed Payment Link cancellation command and executor foundations.

This module contains no worker composition and no network client.  Every I/O
boundary is injected.  A cancellation can reach the provider only after an
allowed deterministic effect decision, an exact durable action/instrument-row
binding, a fresh provider fetch, and a second durable-binding read.  Any
non-confirmed cancel result is followed by another provider fetch before the
job can transition.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from ...packages.domain import (
    ActionProposal,
    ActionType,
    DeterministicGate,
    GateContext,
    GateDecision,
    GateReason,
    GateStage,
)
from ...packages.domain.canonical import canonical_json_bytes
from ...packages.domain.values import require_identifier
from ...packages.razorpay import make_recovery_reference_id
from .outbox import BackoffPolicy, OutboxJob, OutboxState, RetryMode

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_PAYMENT_LINK_ID_RE = re.compile(r"^plink_[A-Za-z0-9]{1,120}$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_REASON_CODE_RE = re.compile(r"^[a-z0-9][a-z0-9_:.-]{0,127}$")


def _require_text(value: object, *, field: str, maximum: int = 128) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{field} must be clean, non-empty text")
    return value


def _require_digest(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _require_utc(value: object, *, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field} must be a timezone-aware datetime")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field} must be expressed in UTC")
    return value.astimezone(UTC)


def _safe_exception_reason(prefix: str, exc: Exception) -> str:
    exception_name = re.sub(r"[^a-z0-9_]", "_", type(exc).__name__.casefold())[:80]
    return f"{prefix}:{exception_name or 'exception'}"


def _require_reason_code(value: object) -> str:
    if not isinstance(value, str) or not _REASON_CODE_RE.fullmatch(value):
        raise ValueError("reason_code must be a bounded lowercase machine code")
    return value


class DurableInstrumentStatus(StrEnum):
    CREATING = "CREATING"
    UNCERTAIN = "UNCERTAIN"
    ISSUED = "ISSUED"
    ACTIVE = "ACTIVE"
    CANCEL_PENDING = "CANCEL_PENDING"
    PAID = "PAID"
    PARTIALLY_PAID = "PARTIALLY_PAID"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"


class ProviderPaymentLinkStatus(StrEnum):
    CREATED = "created"
    PARTIALLY_PAID = "partially_paid"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    PAID = "paid"


class ProviderCancellationStatus(StrEnum):
    CERTAIN_SUCCESS = "certain_success"
    CERTAIN_FAILURE = "certain_failure"
    AMBIGUOUS = "ambiguous"


class CancellationDisposition(StrEnum):
    CANCELLED = "cancelled"
    ALREADY_CANCELLED = "already_cancelled"
    EXPIRED = "expired"
    BLOCKED = "blocked"
    RECONCILE_REQUIRED = "reconcile_required"
    REVIEW_REQUIRED = "review_required"
    ESCALATED = "escalated"
    DEAD_LETTER = "dead_letter"


@dataclass(frozen=True, slots=True)
class CancellationTarget:
    """Immutable DB/provider identity of the Payment Link being cancelled."""

    merchant_id: str
    case_id: str
    action_id: str
    action_key: str
    instrument_id: str
    provider_account_id: str
    payment_link_id: str
    reference_id: str
    amount_minor: int
    currency: str

    def __post_init__(self) -> None:
        for field in (
            "merchant_id",
            "case_id",
            "action_id",
            "instrument_id",
            "provider_account_id",
        ):
            try:
                require_identifier(getattr(self, field), field=field)
            except ValueError as exc:
                raise ValueError(f"{field} must be an opaque identifier") from exc
        action_key = _require_text(self.action_key, field="action_key", maximum=68)
        if not action_key.startswith("act_") or not _DIGEST_RE.fullmatch(action_key[4:]):
            raise ValueError("action_key must be a RetryWise action digest")
        if not _PAYMENT_LINK_ID_RE.fullmatch(self.payment_link_id):
            raise ValueError("payment_link_id must be a Razorpay Payment Link id")
        try:
            require_identifier(self.reference_id, field="reference_id")
        except ValueError as exc:
            raise ValueError("reference_id must be an opaque provider reference") from exc
        if len(self.reference_id) > 40:
            raise ValueError("reference_id cannot exceed the provider limit")
        expected_reference_id = make_recovery_reference_id(
            self.case_id,
            provider_account_id=self.provider_account_id,
        )
        if not hmac.compare_digest(self.reference_id, expected_reference_id):
            raise ValueError("reference_id must be the controller-derived recovery reference")
        if type(self.amount_minor) is not int or self.amount_minor <= 0:
            raise ValueError("amount_minor must be a positive integer")
        if not isinstance(self.currency, str) or not _CURRENCY_RE.fullmatch(self.currency):
            raise ValueError("currency must be a three-letter uppercase code")

    def to_primitive(self) -> dict[str, object]:
        return {
            "action_id": self.action_id,
            "action_key": self.action_key,
            "amount_minor": self.amount_minor,
            "case_id": self.case_id,
            "currency": self.currency,
            "instrument_id": self.instrument_id,
            "merchant_id": self.merchant_id,
            "payment_link_id": self.payment_link_id,
            "provider_account_id": self.provider_account_id,
            "reference_id": self.reference_id,
        }

    @property
    def target_digest(self) -> str:
        material = {
            "schema": "retrywise-cancellation-target-v1",
            "target": self.to_primitive(),
        }
        return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


@dataclass(frozen=True, slots=True)
class CancelPaymentLinkCommand:
    """Complete immutable protective-effect envelope stored in the outbox."""

    proposal: ActionProposal
    prior_plan: GateDecision
    target: CancellationTarget

    def __post_init__(self) -> None:
        if not isinstance(self.proposal, ActionProposal):
            raise TypeError("proposal must be ActionProposal")
        if not isinstance(self.prior_plan, GateDecision):
            raise TypeError("prior_plan must be GateDecision")
        if not isinstance(self.target, CancellationTarget):
            raise TypeError("target must be CancellationTarget")
        proposal = self.proposal
        plan = self.prior_plan
        target = self.target
        if proposal.action_type is not ActionType.CANCEL_PAYMENT_LINK:
            raise ValueError("cancellation command requires a cancellation proposal")
        if proposal.instrument_reference != target.payment_link_id:
            raise ValueError("proposal instrument is not the target Payment Link")
        if (
            proposal.merchant_id != target.merchant_id
            or proposal.case_id != target.case_id
            or proposal.action_key != target.action_key
        ):
            raise ValueError("cancellation proposal is not bound to its target")
        if plan.stage is not GateStage.POLICY or not plan.allowed:
            raise ValueError("cancellation command requires an allowed policy plan")
        plan_binding = (
            (plan.proposal_id, proposal.proposal_id),
            (plan.action_key, proposal.action_key),
            (plan.proposal_digest, proposal.proposal_digest),
            (plan.case_id, proposal.case_id),
            (plan.decision_version, proposal.decision_version),
        )
        if any(actual != expected for actual, expected in plan_binding):
            raise ValueError("cancellation policy plan is not bound to the proposal")

    @property
    def target_digest(self) -> str:
        return self.target.target_digest

    @property
    def payload_digest(self) -> str:
        material = {
            "action_key": self.proposal.action_key,
            "prior_plan_digest": self.prior_plan.decision_digest,
            "proposal_digest": self.proposal.proposal_digest,
            "schema": "retrywise-cancel-payment-link-command-v1",
            "target_digest": self.target_digest,
        }
        return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


@dataclass(frozen=True, slots=True)
class DurableInstrumentBinding:
    """Projection of the joined cancellation action and instrument DB rows."""

    target: CancellationTarget
    persisted_target_digest: str
    instrument_status: DurableInstrumentStatus
    recorded_at: datetime
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.target, CancellationTarget):
            raise TypeError("target must be CancellationTarget")
        _require_digest(self.persisted_target_digest, field="persisted_target_digest")
        if not isinstance(self.instrument_status, DurableInstrumentStatus):
            raise TypeError("instrument_status must be DurableInstrumentStatus")
        object.__setattr__(
            self,
            "recorded_at",
            _require_utc(self.recorded_at, field="recorded_at"),
        )
        if self.schema_version != 1:
            raise ValueError("unsupported durable instrument binding schema_version")

    @classmethod
    def record(
        cls,
        target: CancellationTarget,
        *,
        instrument_status: DurableInstrumentStatus,
        recorded_at: datetime,
    ) -> DurableInstrumentBinding:
        return cls(
            target=target,
            persisted_target_digest=target.target_digest,
            instrument_status=instrument_status,
            recorded_at=recorded_at,
        )

    def matches(self, command: CancelPaymentLinkCommand) -> bool:
        return self.target == command.target and hmac.compare_digest(
            self.persisted_target_digest, command.target_digest
        )


@dataclass(frozen=True, slots=True)
class ProviderPaymentLinkTruth:
    """Strict non-sensitive provider projection used by cancellation policy."""

    payment_link_id: str
    reference_id: str
    amount_minor: int
    amount_paid_minor: int
    currency: str
    accept_partial: bool
    upi_link: bool
    status: ProviderPaymentLinkStatus

    def __post_init__(self) -> None:
        if not _PAYMENT_LINK_ID_RE.fullmatch(self.payment_link_id):
            raise ValueError("provider truth payment_link_id is invalid")
        try:
            require_identifier(self.reference_id, field="reference_id")
        except ValueError as exc:
            raise ValueError("provider truth reference_id is invalid") from exc
        if len(self.reference_id) > 40:
            raise ValueError("provider truth reference_id exceeds the provider limit")
        if type(self.amount_minor) is not int or self.amount_minor <= 0:
            raise ValueError("provider truth amount_minor is invalid")
        if (
            type(self.amount_paid_minor) is not int
            or self.amount_paid_minor < 0
            or self.amount_paid_minor > self.amount_minor
        ):
            raise ValueError("provider truth amount_paid_minor is outside its amount")
        if not isinstance(self.currency, str) or not _CURRENCY_RE.fullmatch(self.currency):
            raise ValueError("provider truth currency is invalid")
        if type(self.accept_partial) is not bool or type(self.upi_link) is not bool:
            raise ValueError("provider truth link-mode flags must be booleans")
        if not isinstance(self.status, ProviderPaymentLinkStatus):
            raise TypeError("provider truth status must be ProviderPaymentLinkStatus")
        if self.status is ProviderPaymentLinkStatus.PAID:
            if self.amount_paid_minor != self.amount_minor:
                raise ValueError("paid provider truth must have its full amount paid")
        elif self.status is ProviderPaymentLinkStatus.PARTIALLY_PAID:
            if not 0 < self.amount_paid_minor < self.amount_minor:
                raise ValueError("partially paid provider truth must have a proper partial amount")
        elif self.amount_paid_minor != 0:
            raise ValueError(
                "created, cancelled, or expired no-partial provider truth must be unpaid"
            )

    def matches(self, target: CancellationTarget) -> bool:
        return (
            hmac.compare_digest(self.payment_link_id, target.payment_link_id)
            and hmac.compare_digest(self.reference_id, target.reference_id)
            and self.amount_minor == target.amount_minor
            and self.currency == target.currency
            and self.accept_partial is False
            and self.upi_link is False
        )


@dataclass(frozen=True, slots=True)
class ProviderCancellationResult:
    status: ProviderCancellationStatus
    reason_code: str
    payment_link: ProviderPaymentLinkTruth | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, ProviderCancellationStatus):
            raise TypeError("status must be ProviderCancellationStatus")
        _require_reason_code(self.reason_code)
        if self.status is ProviderCancellationStatus.CERTAIN_SUCCESS:
            if not isinstance(self.payment_link, ProviderPaymentLinkTruth):
                raise ValueError("certain cancellation success requires provider truth")
            if self.payment_link.status is not ProviderPaymentLinkStatus.CANCELLED:
                raise ValueError("certain cancellation success requires cancelled provider truth")
        elif self.payment_link is not None:
            raise ValueError("only certain cancellation success may carry provider truth")


class DurableInstrumentBindingReader(Protocol):
    """Load a DB-joined action/instrument binding using every target dimension."""

    def load_cancellation_binding(
        self,
        *,
        merchant_id: str,
        case_id: str,
        action_id: str,
        action_key: str,
        instrument_id: str,
        provider_account_id: str,
        payment_link_id: str,
        target_digest: str,
    ) -> DurableInstrumentBinding | None: ...


class CancellationGateContextReader(Protocol):
    def load_fresh_gate_context(
        self,
        *,
        proposal: ActionProposal,
        provider_account_id: str,
        evaluated_at: datetime,
    ) -> GateContext: ...


class PaymentLinkCancellationProvider(Protocol):
    """Fresh reads must bypass process caches and query provider truth."""

    def fetch_payment_link(
        self,
        *,
        payment_link_id: str,
        provider_account_id: str,
    ) -> object: ...

    def cancel_payment_link(
        self,
        *,
        payment_link_id: str,
        provider_account_id: str,
    ) -> object: ...


class CancellationAuthorizationRecorder(Protocol):
    """Commit the final cancellation authorization before provider mutation."""

    def record_cancellation_authorization(
        self,
        *,
        job: OutboxJob,
        command: CancelPaymentLinkCommand,
        decision: GateDecision,
        context: GateContext,
        worker_id: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class CancellationExecutionResult:
    disposition: CancellationDisposition
    job: OutboxJob
    effect_decision: GateDecision
    reason_code: str
    payment_link_id: str
    target_digest: str
    provider_status: ProviderPaymentLinkStatus | None = None
    cancel_attempted: bool = False


_AUTHORIZATION_FAULTS = frozenset(
    {
        GateReason.PLAN_AUTHORIZATION_MISSING,
        GateReason.PLAN_BINDING_MISMATCH,
        GateReason.DURABLE_INTENT_MISSING,
    }
)
_BINDING_STATUSES_WITH_PROVIDER_TARGET = frozenset(
    {
        DurableInstrumentStatus.UNCERTAIN,
        DurableInstrumentStatus.ISSUED,
        DurableInstrumentStatus.ACTIVE,
        DurableInstrumentStatus.CANCEL_PENDING,
        DurableInstrumentStatus.PAID,
        DurableInstrumentStatus.PARTIALLY_PAID,
        DurableInstrumentStatus.CANCELLED,
        DurableInstrumentStatus.EXPIRED,
    }
)
_CANCELLABLE_BINDING_STATUSES = frozenset(
    {
        DurableInstrumentStatus.UNCERTAIN,
        DurableInstrumentStatus.ISSUED,
        DurableInstrumentStatus.ACTIVE,
        DurableInstrumentStatus.CANCEL_PENDING,
    }
)
_PAID_BINDING_STATUSES = frozenset(
    {DurableInstrumentStatus.PAID, DurableInstrumentStatus.PARTIALLY_PAID}
)
_TERMINAL_BINDING_STATUSES = frozenset(
    {DurableInstrumentStatus.CANCELLED, DurableInstrumentStatus.EXPIRED}
)


class CancelPaymentLinkExecutor:
    """Execute one fenced protective cancellation without trusting target ids."""

    def __init__(
        self,
        *,
        gate: DeterministicGate,
        bindings: DurableInstrumentBindingReader,
        contexts: CancellationGateContextReader,
        provider: PaymentLinkCancellationProvider,
        clock: Callable[[], datetime],
        backoff: BackoffPolicy | None = None,
        authorization_recorder: CancellationAuthorizationRecorder | None = None,
    ) -> None:
        if not isinstance(gate, DeterministicGate):
            raise TypeError("gate must be DeterministicGate")
        if not callable(clock):
            raise TypeError("clock must be callable")
        selected_backoff = backoff or BackoffPolicy()
        if not isinstance(selected_backoff, BackoffPolicy):
            raise TypeError("backoff must be BackoffPolicy")
        self._gate = gate
        self._bindings = bindings
        self._contexts = contexts
        self._provider = provider
        self._clock = clock
        self._backoff = selected_backoff
        if authorization_recorder is not None and not callable(
            getattr(authorization_recorder, "record_cancellation_authorization", None)
        ):
            raise TypeError("authorization_recorder must provide record_cancellation_authorization")
        self._authorization_recorder = authorization_recorder

    def execute(
        self,
        *,
        job: OutboxJob,
        command: CancelPaymentLinkCommand,
        worker_id: str,
    ) -> CancellationExecutionResult:
        if not isinstance(job, OutboxJob):
            raise TypeError("job must be OutboxJob")
        if not isinstance(command, CancelPaymentLinkCommand):
            raise TypeError("command must be CancelPaymentLinkCommand")
        now = self._now()
        lease_token = job.lease_token or "missing-lease-token"
        job.assert_active_lease(worker_id=worker_id, lease_token=lease_token, now=now)

        binding = self._load_binding(command)
        binding_failure = self._binding_failure(job, command, binding, now=now)
        durable_binding_proved = binding is not None and binding_failure is None
        context = self._contexts.load_fresh_gate_context(
            proposal=command.proposal,
            provider_account_id=command.target.provider_account_id,
            evaluated_at=now,
        )
        if not isinstance(context, GateContext):
            raise TypeError("fresh context port must return GateContext")
        effect = self._gate.evaluate_effect(
            command.proposal,
            replace(
                context,
                evaluated_at=now,
                durable_intent_recorded=durable_binding_proved,
            ),
            prior_plan=command.prior_plan,
        )

        if binding_failure is not None or binding is None:
            return self._dead_letter(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=effect,
                reason=f"binding_failure:{binding_failure or 'binding_missing'}",
                disposition=CancellationDisposition.ESCALATED,
            )
        if not effect.allowed:
            reasons = ",".join(reason.value for reason in effect.reasons)
            prefix = (
                "effect_authorization_fault"
                if any(reason in _AUTHORIZATION_FAULTS for reason in effect.reasons)
                else "effect_gate_denied"
            )
            return self._dead_letter(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=effect,
                reason=f"{prefix}:{reasons}",
                disposition=CancellationDisposition.BLOCKED,
            )

        truth, fetch_failure = self._fetch_truth(command)
        if truth is None:
            return self._requeue(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=effect,
                reason=f"pre_cancel_truth_unavailable:{fetch_failure}",
                retry_mode=(
                    RetryMode.RECONCILE_ONLY
                    if job.retry_mode is RetryMode.RECONCILE_ONLY
                    else RetryMode.NORMAL
                ),
                cancel_attempted=False,
            )
        if not truth.matches(command.target):
            return self._dead_letter(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=effect,
                reason="pre_cancel_provider_target_mismatch",
                disposition=CancellationDisposition.ESCALATED,
                provider_status=truth.status,
            )

        terminal = self._resolve_without_cancel(
            job=job,
            command=command,
            worker_id=worker_id,
            effect=effect,
            binding=binding,
            truth=truth,
            phase="pre_cancel",
            cancel_attempted=False,
        )
        if terminal is not None:
            return terminal

        refreshed_binding = self._load_binding(command)
        refreshed_failure = self._binding_failure(
            job,
            command,
            refreshed_binding,
            now=self._now(),
        )
        if refreshed_failure is not None or refreshed_binding is None:
            return self._dead_letter(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=effect,
                reason=f"pre_effect_binding_failure:{refreshed_failure or 'binding_missing'}",
                disposition=CancellationDisposition.ESCALATED,
                provider_status=truth.status,
            )
        terminal = self._resolve_without_cancel(
            job=job,
            command=command,
            worker_id=worker_id,
            effect=effect,
            binding=refreshed_binding,
            truth=truth,
            phase="pre_effect",
            cancel_attempted=False,
        )
        if terminal is not None:
            return terminal

        if job.retry_mode is RetryMode.RECONCILE_ONLY:
            return self._requeue(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=effect,
                reason="reconcile_only_fresh_unpaid_link_grants_effect_retry",
                retry_mode=RetryMode.RETRY_SAME_EFFECT,
                provider_status=truth.status,
                cancel_attempted=False,
            )

        before_effect = self._now()
        job.assert_active_lease(
            worker_id=worker_id,
            lease_token=job.lease_token or "missing-lease-token",
            now=before_effect,
        )
        final_context = self._contexts.load_fresh_gate_context(
            proposal=command.proposal,
            provider_account_id=command.target.provider_account_id,
            evaluated_at=before_effect,
        )
        if not isinstance(final_context, GateContext):
            raise TypeError("final context port must return GateContext")
        final_effect = self._gate.evaluate_effect(
            command.proposal,
            replace(
                final_context,
                evaluated_at=before_effect,
                durable_intent_recorded=True,
            ),
            prior_plan=command.prior_plan,
        )
        if not final_effect.allowed:
            reasons = ",".join(reason.value for reason in final_effect.reasons)
            return self._dead_letter(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=final_effect,
                reason=f"final_effect_gate_denied:{reasons}",
                disposition=CancellationDisposition.BLOCKED,
                provider_status=truth.status,
            )
        if truth.amount_paid_minor != 0:
            return self._review(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=final_effect,
                reason="final_provider_amount_paid_requires_review",
                provider_status=truth.status,
                cancel_attempted=False,
            )

        if self._authorization_recorder is not None:
            self._authorization_recorder.record_cancellation_authorization(
                job=job,
                command=command,
                decision=final_effect,
                context=final_context,
                worker_id=worker_id,
            )

        try:
            raw_outcome = self._provider.cancel_payment_link(
                payment_link_id=command.target.payment_link_id,
                provider_account_id=command.target.provider_account_id,
            )
        except Exception as exc:  # Provider call may have crossed the effect boundary.
            return self._reconcile_after_effect(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=final_effect,
                reason=_safe_exception_reason("cancel_port_exception", exc),
            )

        outcome, outcome_failure = _normalize_cancel_outcome(raw_outcome)
        if outcome is None:
            reason = f"cancel_outcome_invalid:{outcome_failure}"
        else:
            reason = f"{outcome.status.value}:{outcome.reason_code}"
            if outcome.status is ProviderCancellationStatus.CERTAIN_SUCCESS and (
                outcome.payment_link is None or not outcome.payment_link.matches(command.target)
            ):
                reason = f"{reason}:response_target_mismatch"
        return self._reconcile_after_effect(
            job=job,
            command=command,
            worker_id=worker_id,
            effect=final_effect,
            reason=reason,
        )

    def _load_binding(self, command: CancelPaymentLinkCommand) -> DurableInstrumentBinding | None:
        target = command.target
        return self._bindings.load_cancellation_binding(
            merchant_id=target.merchant_id,
            case_id=target.case_id,
            action_id=target.action_id,
            action_key=target.action_key,
            instrument_id=target.instrument_id,
            provider_account_id=target.provider_account_id,
            payment_link_id=target.payment_link_id,
            target_digest=command.target_digest,
        )

    @staticmethod
    def _binding_failure(
        job: OutboxJob,
        command: CancelPaymentLinkCommand,
        binding: DurableInstrumentBinding | None,
        *,
        now: datetime,
    ) -> str | None:
        if job.action_key != command.proposal.action_key:
            return "job_action_key_mismatch"
        if not hmac.compare_digest(job.payload_digest, command.payload_digest):
            return "job_payload_digest_mismatch"
        if binding is None:
            return "durable_instrument_binding_missing"
        if not isinstance(binding, DurableInstrumentBinding):
            return "durable_instrument_binding_type_invalid"
        if not binding.matches(command):
            return "durable_instrument_binding_mismatch"
        if binding.recorded_at > now:
            return "durable_instrument_binding_from_future"
        if binding.instrument_status not in _BINDING_STATUSES_WITH_PROVIDER_TARGET:
            return "instrument_status_has_no_cancellable_provider_target"
        return None

    def _fetch_truth(
        self, command: CancelPaymentLinkCommand
    ) -> tuple[ProviderPaymentLinkTruth | None, str | None]:
        try:
            raw_truth = self._provider.fetch_payment_link(
                payment_link_id=command.target.payment_link_id,
                provider_account_id=command.target.provider_account_id,
            )
        except Exception as exc:
            return None, _safe_exception_reason("provider_fetch_exception", exc)
        return _normalize_truth(raw_truth)

    def _resolve_without_cancel(
        self,
        *,
        job: OutboxJob,
        command: CancelPaymentLinkCommand,
        worker_id: str,
        effect: GateDecision,
        binding: DurableInstrumentBinding,
        truth: ProviderPaymentLinkTruth,
        phase: str,
        cancel_attempted: bool,
    ) -> CancellationExecutionResult | None:
        if binding.instrument_status in _PAID_BINDING_STATUSES:
            return self._review(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=effect,
                reason=f"{phase}_durable_{binding.instrument_status.value.lower()}_requires_review",
                provider_status=truth.status,
                cancel_attempted=cancel_attempted,
            )
        if truth.status in {
            ProviderPaymentLinkStatus.PAID,
            ProviderPaymentLinkStatus.PARTIALLY_PAID,
        }:
            return self._review(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=effect,
                reason=f"{phase}_provider_{truth.status.value}_requires_review",
                provider_status=truth.status,
                cancel_attempted=cancel_attempted,
            )
        if truth.status is ProviderPaymentLinkStatus.CANCELLED:
            return self._complete(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=effect,
                reason=f"{phase}_provider_already_cancelled",
                disposition=CancellationDisposition.ALREADY_CANCELLED,
                provider_status=truth.status,
                cancel_attempted=cancel_attempted,
            )
        if truth.status is ProviderPaymentLinkStatus.EXPIRED:
            return self._complete(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=effect,
                reason=f"{phase}_provider_expired",
                disposition=CancellationDisposition.EXPIRED,
                provider_status=truth.status,
                cancel_attempted=cancel_attempted,
            )
        if binding.instrument_status in _TERMINAL_BINDING_STATUSES:
            return self._requeue(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=effect,
                reason=(
                    f"{phase}_durable_{binding.instrument_status.value.lower()}_"
                    "conflicts_with_created_provider_truth"
                ),
                retry_mode=RetryMode.RECONCILE_ONLY,
                provider_status=truth.status,
                cancel_attempted=cancel_attempted,
            )
        if binding.instrument_status not in _CANCELLABLE_BINDING_STATUSES:
            return self._dead_letter(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=effect,
                reason=f"{phase}_instrument_status_not_cancellable",
                disposition=CancellationDisposition.ESCALATED,
                provider_status=truth.status,
                cancel_attempted=cancel_attempted,
            )
        return None

    def _reconcile_after_effect(
        self,
        *,
        job: OutboxJob,
        command: CancelPaymentLinkCommand,
        worker_id: str,
        effect: GateDecision,
        reason: str,
    ) -> CancellationExecutionResult:
        truth, fetch_failure = self._fetch_truth(command)
        refreshed_binding = self._load_binding(command)
        refreshed_failure = self._binding_failure(
            job,
            command,
            refreshed_binding,
            now=self._now(),
        )
        if refreshed_failure is not None or refreshed_binding is None:
            return self._dead_letter(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=effect,
                reason=f"post_cancel_binding_failure:{refreshed_failure or 'binding_missing'}",
                disposition=CancellationDisposition.ESCALATED,
                provider_status=None if truth is None else truth.status,
                cancel_attempted=True,
            )
        if truth is None:
            return self._requeue(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=effect,
                reason=f"post_cancel_truth_unavailable:{reason}:{fetch_failure}",
                retry_mode=RetryMode.RECONCILE_ONLY,
                cancel_attempted=True,
            )
        if not truth.matches(command.target):
            return self._dead_letter(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=effect,
                reason="post_cancel_provider_target_mismatch",
                disposition=CancellationDisposition.ESCALATED,
                provider_status=truth.status,
                cancel_attempted=True,
            )
        if refreshed_binding.instrument_status in _PAID_BINDING_STATUSES:
            return self._review(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=effect,
                reason=(
                    "post_cancel_durable_"
                    f"{refreshed_binding.instrument_status.value.lower()}_requires_review"
                ),
                provider_status=truth.status,
                cancel_attempted=True,
            )
        if truth.status in {
            ProviderPaymentLinkStatus.PAID,
            ProviderPaymentLinkStatus.PARTIALLY_PAID,
        }:
            return self._review(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=effect,
                reason=f"post_cancel_provider_{truth.status.value}_requires_review",
                provider_status=truth.status,
                cancel_attempted=True,
            )
        if truth.status is ProviderPaymentLinkStatus.CANCELLED:
            return self._complete(
                job=job,
                command=command,
                worker_id=worker_id,
                effect=effect,
                reason=f"post_cancel_provider_cancelled:{reason}",
                disposition=CancellationDisposition.CANCELLED,
                provider_status=truth.status,
                cancel_attempted=True,
            )
        terminal = self._resolve_without_cancel(
            job=job,
            command=command,
            worker_id=worker_id,
            effect=effect,
            binding=refreshed_binding,
            truth=truth,
            phase="post_cancel",
            cancel_attempted=True,
        )
        if terminal is not None:
            return terminal
        return self._requeue(
            job=job,
            command=command,
            worker_id=worker_id,
            effect=effect,
            reason=f"post_cancel_fresh_unpaid_link_grants_effect_retry:{reason}",
            retry_mode=RetryMode.RETRY_SAME_EFFECT,
            provider_status=truth.status,
            cancel_attempted=True,
        )

    def _now(self) -> datetime:
        return _require_utc(self._clock(), field="clock result")

    def _complete(
        self,
        *,
        job: OutboxJob,
        command: CancelPaymentLinkCommand,
        worker_id: str,
        effect: GateDecision,
        reason: str,
        disposition: CancellationDisposition,
        provider_status: ProviderPaymentLinkStatus,
        cancel_attempted: bool,
    ) -> CancellationExecutionResult:
        completed = job.complete(
            worker_id=worker_id,
            lease_token=job.lease_token or "missing-lease-token",
            now=self._now(),
            expected_version=job.version,
            result_reference=f"{disposition.value}:{command.target_digest}",
        )
        return self._result(
            disposition,
            completed,
            effect,
            reason,
            command,
            provider_status=provider_status,
            cancel_attempted=cancel_attempted,
        )

    def _review(
        self,
        *,
        job: OutboxJob,
        command: CancelPaymentLinkCommand,
        worker_id: str,
        effect: GateDecision,
        reason: str,
        provider_status: ProviderPaymentLinkStatus,
        cancel_attempted: bool,
    ) -> CancellationExecutionResult:
        return self._dead_letter(
            job=job,
            command=command,
            worker_id=worker_id,
            effect=effect,
            reason=reason,
            disposition=CancellationDisposition.REVIEW_REQUIRED,
            provider_status=provider_status,
            cancel_attempted=cancel_attempted,
        )

    def _requeue(
        self,
        *,
        job: OutboxJob,
        command: CancelPaymentLinkCommand,
        worker_id: str,
        effect: GateDecision,
        reason: str,
        retry_mode: RetryMode,
        provider_status: ProviderPaymentLinkStatus | None = None,
        cancel_attempted: bool,
    ) -> CancellationExecutionResult:
        updated = job.requeue(
            worker_id=worker_id,
            lease_token=job.lease_token or "missing-lease-token",
            now=self._now(),
            expected_version=job.version,
            reason=reason,
            backoff=self._backoff,
            retry_mode=retry_mode,
        )
        disposition = (
            CancellationDisposition.DEAD_LETTER
            if updated.state is OutboxState.DEAD_LETTER
            else CancellationDisposition.RECONCILE_REQUIRED
        )
        return self._result(
            disposition,
            updated,
            effect,
            reason,
            command,
            provider_status=provider_status,
            cancel_attempted=cancel_attempted,
        )

    def _dead_letter(
        self,
        *,
        job: OutboxJob,
        command: CancelPaymentLinkCommand,
        worker_id: str,
        effect: GateDecision,
        reason: str,
        disposition: CancellationDisposition,
        provider_status: ProviderPaymentLinkStatus | None = None,
        cancel_attempted: bool = False,
    ) -> CancellationExecutionResult:
        dead = job.dead_letter(
            worker_id=worker_id,
            lease_token=job.lease_token or "missing-lease-token",
            now=self._now(),
            expected_version=job.version,
            reason=reason,
        )
        return self._result(
            disposition,
            dead,
            effect,
            reason,
            command,
            provider_status=provider_status,
            cancel_attempted=cancel_attempted,
        )

    @staticmethod
    def _result(
        disposition: CancellationDisposition,
        job: OutboxJob,
        effect: GateDecision,
        reason: str,
        command: CancelPaymentLinkCommand,
        *,
        provider_status: ProviderPaymentLinkStatus | None,
        cancel_attempted: bool,
    ) -> CancellationExecutionResult:
        return CancellationExecutionResult(
            disposition=disposition,
            job=job,
            effect_decision=effect,
            reason_code=reason,
            payment_link_id=command.target.payment_link_id,
            target_digest=command.target_digest,
            provider_status=provider_status,
            cancel_attempted=cancel_attempted,
        )


def _normalize_truth(
    value: object,
) -> tuple[ProviderPaymentLinkTruth | None, str | None]:
    if isinstance(value, ProviderPaymentLinkTruth):
        return value, None
    try:
        candidate: Any = value
        status_value = candidate.status
        status = ProviderPaymentLinkStatus(status_value)
        truth = ProviderPaymentLinkTruth(
            payment_link_id=candidate.payment_link_id,
            reference_id=candidate.reference_id,
            amount_minor=candidate.amount_minor,
            amount_paid_minor=candidate.amount_paid_minor,
            currency=candidate.currency,
            accept_partial=candidate.accept_partial,
            upi_link=candidate.upi_link,
            status=status,
        )
    except (AttributeError, TypeError, ValueError):
        return None, "provider_truth_contract_invalid"
    return truth, None


def _normalize_cancel_outcome(
    value: object,
) -> tuple[ProviderCancellationResult | None, str | None]:
    if isinstance(value, ProviderCancellationResult):
        return value, None
    try:
        candidate: Any = value
        status = ProviderCancellationStatus(candidate.status)
        reason = candidate.reason_code
        raw_payment_link = candidate.payment_link
        payment_link: ProviderPaymentLinkTruth | None = None
        if raw_payment_link is not None:
            payment_link, failure = _normalize_truth(raw_payment_link)
            if payment_link is None:
                return None, failure
        result = ProviderCancellationResult(
            status=status,
            reason_code=reason,
            payment_link=payment_link,
        )
    except (AttributeError, TypeError, ValueError):
        return None, "provider_cancel_contract_invalid"
    return result, None


__all__ = [
    "CancelPaymentLinkCommand",
    "CancelPaymentLinkExecutor",
    "CancellationAuthorizationRecorder",
    "CancellationDisposition",
    "CancellationExecutionResult",
    "CancellationGateContextReader",
    "CancellationTarget",
    "DurableInstrumentBinding",
    "DurableInstrumentBindingReader",
    "DurableInstrumentStatus",
    "PaymentLinkCancellationProvider",
    "ProviderCancellationResult",
    "ProviderCancellationStatus",
    "ProviderPaymentLinkStatus",
    "ProviderPaymentLinkTruth",
]
