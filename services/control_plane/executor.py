"""Fail-closed executor for creating a single Standard Payment Link.

All I/O is behind injected ports.  The executor re-authorizes against fresh
canonical truth immediately before an effect and never issues more than one
create call per delivery.  Unknown outcomes and recovered leases are resolved
through the existing Razorpay reference lookup contract.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol

from ...packages.domain import (
    ActionProposal,
    ActionType,
    DeterministicGate,
    GateContext,
    GateDecision,
    GateReason,
)
from ...packages.razorpay import (
    AmbiguousCreateAction,
    PaymentLinkLookupResult,
    PaymentLinkValidationError,
    StandardPaymentLinkRequest,
    decide_ambiguous_create,
)
from .outbox import BackoffPolicy, OutboxJob, OutboxState, RetryMode


def _require_text(value: str, *, field: str, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{field} must be clean, non-empty text")
    return value


def _require_utc(value: datetime, *, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field} must be a timezone-aware datetime")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field} must be expressed in UTC")
    return value.astimezone(UTC)


def _sha256_json(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def payment_link_request_digest(request: StandardPaymentLinkRequest) -> str:
    if not isinstance(request, StandardPaymentLinkRequest):
        raise TypeError("request must be StandardPaymentLinkRequest")
    return hashlib.sha256(request.to_json_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class CreatePaymentLinkCommand:
    """The complete immutable effect envelope stored behind an outbox row."""

    proposal: ActionProposal
    prior_plan: GateDecision
    request: StandardPaymentLinkRequest
    provider_account_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.proposal, ActionProposal):
            raise TypeError("proposal must be ActionProposal")
        if not isinstance(self.prior_plan, GateDecision):
            raise TypeError("prior_plan must be GateDecision")
        if not isinstance(self.request, StandardPaymentLinkRequest):
            raise TypeError("request must be StandardPaymentLinkRequest")
        _require_text(self.provider_account_id, field="provider_account_id", maximum=128)

    @property
    def request_digest(self) -> str:
        return payment_link_request_digest(self.request)

    @property
    def payload_digest(self) -> str:
        return _sha256_json(
            {
                "action_key": self.proposal.action_key,
                "merchant_id": self.proposal.merchant_id,
                "prior_plan_digest": self.prior_plan.decision_digest,
                "proposal_digest": self.proposal.proposal_digest,
                "provider_account_id": self.provider_account_id,
                "reference_id": self.request.reference_id,
                "request_digest": self.request_digest,
                "schema": "retrywise-create-payment-link-command-v1",
            }
        )


@dataclass(frozen=True, slots=True)
class DurableActionIntent:
    """Authorization material that must exist before an external effect."""

    action_key: str
    merchant_id: str
    provider_account_id: str
    proposal_digest: str
    prior_plan_digest: str
    request_digest: str
    payload_digest: str
    reference_id: str
    recorded_at: datetime
    schema_version: int = 1

    def __post_init__(self) -> None:
        for field, maximum in (
            ("action_key", 128),
            ("merchant_id", 128),
            ("provider_account_id", 128),
            ("reference_id", 40),
        ):
            _require_text(getattr(self, field), field=field, maximum=maximum)
        for field in (
            "proposal_digest",
            "prior_plan_digest",
            "request_digest",
            "payload_digest",
        ):
            value = getattr(self, field)
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError(f"{field} must be a lowercase SHA-256 digest")
        object.__setattr__(self, "recorded_at", _require_utc(self.recorded_at, field="recorded_at"))
        if self.schema_version != 1:
            raise ValueError("unsupported durable intent schema_version")

    @classmethod
    def record(
        cls, command: CreatePaymentLinkCommand, *, recorded_at: datetime
    ) -> DurableActionIntent:
        if not isinstance(command, CreatePaymentLinkCommand):
            raise TypeError("command must be CreatePaymentLinkCommand")
        return cls(
            action_key=command.proposal.action_key,
            merchant_id=command.proposal.merchant_id,
            provider_account_id=command.provider_account_id,
            proposal_digest=command.proposal.proposal_digest,
            prior_plan_digest=command.prior_plan.decision_digest,
            request_digest=command.request_digest,
            payload_digest=command.payload_digest,
            reference_id=command.request.reference_id,
            recorded_at=recorded_at,
        )

    def matches(self, command: CreatePaymentLinkCommand) -> bool:
        return (
            self.action_key == command.proposal.action_key
            and self.merchant_id == command.proposal.merchant_id
            and self.provider_account_id == command.provider_account_id
            and self.proposal_digest == command.proposal.proposal_digest
            and self.prior_plan_digest == command.prior_plan.decision_digest
            and self.request_digest == command.request_digest
            and self.payload_digest == command.payload_digest
            and self.reference_id == command.request.reference_id
        )


class DurableIntentReader(Protocol):
    def load_durable_intent(
        self, *, action_key: str, provider_account_id: str
    ) -> DurableActionIntent | None: ...


class FreshGateContextReader(Protocol):
    def load_fresh_gate_context(
        self,
        *,
        proposal: ActionProposal,
        provider_account_id: str,
        evaluated_at: datetime,
    ) -> GateContext: ...


class PaymentLinkProvider(Protocol):
    def create_standard_payment_link(
        self,
        request: StandardPaymentLinkRequest,
        *,
        provider_account_id: str,
    ) -> ProviderCreateOutcome: ...

    def lookup_payment_links(
        self, *, reference_id: str, provider_account_id: str
    ) -> PaymentLinkLookupResult: ...


class EffectAuthorizationRecorder(Protocol):
    """Persist the effect-stage decision before any provider request."""

    def record_effect_authorization(
        self,
        *,
        job: OutboxJob,
        command: CreatePaymentLinkCommand,
        decision: GateDecision,
        context: GateContext,
        worker_id: str,
        reconciliation_only: bool,
    ) -> None: ...


class ProviderCreateStatus(StrEnum):
    CERTAIN_SUCCESS = "certain_success"
    CERTAIN_FAILURE = "certain_failure"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True, slots=True)
class ProviderCreateOutcome:
    """Adapter-classified provider result; unknown means ambiguous, never safe."""

    status: ProviderCreateStatus
    reason_code: str
    payment_link_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, ProviderCreateStatus):
            raise TypeError("status must be ProviderCreateStatus")
        _require_text(self.reason_code, field="reason_code", maximum=256)
        if self.status is ProviderCreateStatus.CERTAIN_SUCCESS:
            if self.payment_link_id is None:
                raise ValueError("certain success requires payment_link_id")
            _require_text(self.payment_link_id, field="payment_link_id", maximum=128)
        elif self.payment_link_id is not None:
            raise ValueError("only certain success may carry payment_link_id")

    @classmethod
    def succeeded(cls, payment_link_id: str) -> ProviderCreateOutcome:
        return cls(
            ProviderCreateStatus.CERTAIN_SUCCESS,
            "provider_confirmed_create",
            payment_link_id,
        )

    @classmethod
    def failed_safely(cls, reason_code: str) -> ProviderCreateOutcome:
        return cls(ProviderCreateStatus.CERTAIN_FAILURE, reason_code)

    @classmethod
    def ambiguous(cls, reason_code: str) -> ProviderCreateOutcome:
        return cls(ProviderCreateStatus.AMBIGUOUS, reason_code)


class ExecutionDisposition(StrEnum):
    CREATED = "created"
    ADOPTED = "adopted"
    SUPPRESSED = "suppressed"
    REQUEUED = "requeued"
    REQUERY_REQUIRED = "requery_required"
    ESCALATED = "escalated"
    DEAD_LETTER = "dead_letter"


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    disposition: ExecutionDisposition
    job: OutboxJob
    effect_decision: GateDecision
    reason_code: str
    reference_id: str
    payment_link_id: str | None = None


_AUTHORIZATION_FAULTS = frozenset(
    {
        GateReason.PLAN_AUTHORIZATION_MISSING,
        GateReason.PLAN_BINDING_MISMATCH,
        GateReason.DURABLE_INTENT_MISSING,
    }
)


class CreatePaymentLinkExecutor:
    """Execute one leased create command without risking a blind duplicate."""

    def __init__(
        self,
        *,
        gate: DeterministicGate,
        intents: DurableIntentReader,
        contexts: FreshGateContextReader,
        provider: PaymentLinkProvider,
        clock: Callable[[], datetime],
        backoff: BackoffPolicy | None = None,
        authorization_recorder: EffectAuthorizationRecorder | None = None,
    ) -> None:
        if not isinstance(gate, DeterministicGate):
            raise TypeError("gate must be DeterministicGate")
        if backoff is None:
            backoff = BackoffPolicy()
        if not isinstance(backoff, BackoffPolicy):
            raise TypeError("backoff must be BackoffPolicy")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._gate = gate
        self._intents = intents
        self._contexts = contexts
        self._provider = provider
        self._clock = clock
        self._backoff = backoff
        if authorization_recorder is not None and not callable(
            getattr(authorization_recorder, "record_effect_authorization", None)
        ):
            raise TypeError("authorization_recorder must provide record_effect_authorization")
        self._authorization_recorder = authorization_recorder

    def execute(
        self,
        *,
        job: OutboxJob,
        command: CreatePaymentLinkCommand,
        worker_id: str,
    ) -> ExecutionResult:
        if not isinstance(job, OutboxJob):
            raise TypeError("job must be OutboxJob")
        if not isinstance(command, CreatePaymentLinkCommand):
            raise TypeError("command must be CreatePaymentLinkCommand")
        now = _require_utc(self._clock(), field="clock result")
        lease_token = job.lease_token or "missing-lease-token"
        job.assert_active_lease(worker_id=worker_id, lease_token=lease_token, now=now)

        intent = self._intents.load_durable_intent(
            action_key=job.action_key,
            provider_account_id=command.provider_account_id,
        )
        binding_failure = self._binding_failure(job, command, intent)
        durable_binding_proved = intent is not None and binding_failure is None

        fresh_context = self._contexts.load_fresh_gate_context(
            proposal=command.proposal,
            provider_account_id=command.provider_account_id,
            evaluated_at=now,
        )
        if not isinstance(fresh_context, GateContext):
            raise TypeError("fresh context port must return GateContext")
        # Provider truth and method-health reads can take longer than the policy's
        # allowed clock skew. Authorize against time captured after those reads.
        now = _require_utc(self._clock(), field="clock result")
        job.assert_active_lease(worker_id=worker_id, lease_token=lease_token, now=now)
        effect_context = replace(
            fresh_context,
            evaluated_at=now,
            durable_intent_recorded=durable_binding_proved,
        )
        effect = self._gate.evaluate_effect(
            command.proposal,
            effect_context,
            prior_plan=command.prior_plan,
        )

        if binding_failure is not None:
            return self._escalate(
                job=job,
                command=command,
                worker_id=worker_id,
                now=now,
                effect=effect,
                reason=f"binding_failure:{binding_failure}",
            )
        if not effect.allowed:
            reason_values = ",".join(reason.value for reason in effect.reasons)
            if any(reason in _AUTHORIZATION_FAULTS for reason in effect.reasons):
                return self._escalate(
                    job=job,
                    command=command,
                    worker_id=worker_id,
                    now=now,
                    effect=effect,
                    reason=f"effect_authorization_fault:{reason_values}",
                )
            if GateReason.PAYMENT_TRUTH_NOT_UNPAID in effect.reasons:
                completed = job.complete(
                    worker_id=worker_id,
                    lease_token=lease_token,
                    now=now,
                    expected_version=job.version,
                    result_reference=f"suppressed_{effect.decision_digest}",
                )
                return ExecutionResult(
                    ExecutionDisposition.SUPPRESSED,
                    completed,
                    effect,
                    "fresh_payment_truth_blocks_collection",
                    command.request.reference_id,
                )
            return self._suppress(
                job=job,
                command=command,
                worker_id=worker_id,
                now=now,
                effect=effect,
                reason=f"effect_gate_denied:{reason_values}",
            )

        if self._authorization_recorder is not None:
            self._authorization_recorder.record_effect_authorization(
                job=job,
                command=command,
                decision=effect,
                context=effect_context,
                worker_id=worker_id,
                reconciliation_only=job.retry_mode is RetryMode.RECONCILE_ONLY,
            )

        if job.retry_mode is RetryMode.RECONCILE_ONLY:
            return self._reconcile(
                job=job,
                command=command,
                worker_id=worker_id,
                now=now,
                effect=effect,
            )

        try:
            command.request.validate_expiry(now_epoch=int(now.timestamp()))
        except PaymentLinkValidationError as exc:
            return self._escalate(
                job=job,
                command=command,
                worker_id=worker_id,
                now=now,
                effect=effect,
                reason=f"request_not_effect_safe:{exc}",
            )

        create = self._provider.create_standard_payment_link(
            command.request,
            provider_account_id=command.provider_account_id,
        )
        if not isinstance(create, ProviderCreateOutcome):
            raise TypeError("create port must return ProviderCreateOutcome")
        if create.status is ProviderCreateStatus.CERTAIN_SUCCESS:
            payment_link_id = create.payment_link_id
            if payment_link_id is None:  # guarded by ProviderCreateOutcome
                raise AssertionError("certain success has no payment_link_id")
            completed = job.complete(
                worker_id=worker_id,
                lease_token=lease_token,
                now=now,
                expected_version=job.version,
                result_reference=payment_link_id,
            )
            return ExecutionResult(
                ExecutionDisposition.CREATED,
                completed,
                effect,
                create.reason_code,
                command.request.reference_id,
                payment_link_id,
            )
        if create.status is ProviderCreateStatus.CERTAIN_FAILURE:
            return self._requeue(
                job=job,
                command=command,
                worker_id=worker_id,
                now=now,
                effect=effect,
                reason=f"certain_failure:{create.reason_code}",
                mode=RetryMode.RETRY_SAME_EFFECT,
                disposition=ExecutionDisposition.REQUEUED,
            )
        return self._reconcile(
            job=job,
            command=command,
            worker_id=worker_id,
            now=now,
            effect=effect,
        )

    def _binding_failure(
        self,
        job: OutboxJob,
        command: CreatePaymentLinkCommand,
        intent: DurableActionIntent | None,
    ) -> str | None:
        proposal = command.proposal
        if job.action_key != proposal.action_key:
            return "job_action_key_mismatch"
        if job.payload_digest != command.payload_digest:
            return "job_payload_digest_mismatch"
        if proposal.action_type is not ActionType.CREATE_STANDARD_PAYMENT_LINK:
            return "proposal_action_type_mismatch"
        if proposal.amount is None:
            return "proposal_amount_missing"
        if proposal.amount.minor_units != command.request.amount_minor:
            return "proposal_request_amount_mismatch"
        if proposal.amount.currency != command.request.currency:
            return "proposal_request_currency_mismatch"
        if intent is None:
            return "durable_intent_missing"
        if not isinstance(intent, DurableActionIntent):
            return "durable_intent_type_invalid"
        if not intent.matches(command):
            return "durable_intent_command_mismatch"
        return None

    def _reconcile(
        self,
        *,
        job: OutboxJob,
        command: CreatePaymentLinkCommand,
        worker_id: str,
        now: datetime,
        effect: GateDecision,
    ) -> ExecutionResult:
        lookup = self._provider.lookup_payment_links(
            reference_id=command.request.reference_id,
            provider_account_id=command.provider_account_id,
        )
        if not isinstance(lookup, PaymentLinkLookupResult):
            raise TypeError("lookup port must return PaymentLinkLookupResult")
        decision = decide_ambiguous_create(command.request, lookup)
        if decision.action is AmbiguousCreateAction.ADOPT_EXISTING:
            payment_link_id = decision.payment_link_id
            if payment_link_id is None:  # guarded by reconciliation decision
                raise AssertionError("adoption decision has no payment_link_id")
            completed = job.complete(
                worker_id=worker_id,
                lease_token=job.lease_token or "missing-lease-token",
                now=now,
                expected_version=job.version,
                result_reference=payment_link_id,
            )
            return ExecutionResult(
                ExecutionDisposition.ADOPTED,
                completed,
                effect,
                decision.reason_code,
                command.request.reference_id,
                payment_link_id,
            )
        if decision.action is AmbiguousCreateAction.RETRY_CREATE_SAME_REFERENCE:
            return self._requeue(
                job=job,
                command=command,
                worker_id=worker_id,
                now=now,
                effect=effect,
                reason=decision.reason_code,
                mode=RetryMode.RETRY_SAME_EFFECT,
                disposition=ExecutionDisposition.REQUEUED,
            )
        if decision.action is AmbiguousCreateAction.REQUERY:
            return self._requeue(
                job=job,
                command=command,
                worker_id=worker_id,
                now=now,
                effect=effect,
                reason=decision.reason_code,
                mode=RetryMode.RECONCILE_ONLY,
                disposition=ExecutionDisposition.REQUERY_REQUIRED,
            )
        return self._escalate(
            job=job,
            command=command,
            worker_id=worker_id,
            now=now,
            effect=effect,
            reason=f"ambiguous_create_conflict:{decision.reason_code}",
        )

    def _requeue(
        self,
        *,
        job: OutboxJob,
        command: CreatePaymentLinkCommand,
        worker_id: str,
        now: datetime,
        effect: GateDecision,
        reason: str,
        mode: RetryMode,
        disposition: ExecutionDisposition,
    ) -> ExecutionResult:
        updated = job.requeue(
            worker_id=worker_id,
            lease_token=job.lease_token or "missing-lease-token",
            now=now,
            expected_version=job.version,
            reason=reason,
            backoff=self._backoff,
            retry_mode=mode,
        )
        final_disposition = (
            ExecutionDisposition.DEAD_LETTER
            if updated.state is OutboxState.DEAD_LETTER
            else disposition
        )
        return ExecutionResult(
            final_disposition,
            updated,
            effect,
            reason,
            command.request.reference_id,
        )

    def _suppress(
        self,
        *,
        job: OutboxJob,
        command: CreatePaymentLinkCommand,
        worker_id: str,
        now: datetime,
        effect: GateDecision,
        reason: str,
    ) -> ExecutionResult:
        completed = job.complete(
            worker_id=worker_id,
            lease_token=job.lease_token or "missing-lease-token",
            now=now,
            expected_version=job.version,
            result_reference=f"suppressed_{effect.decision_digest}",
        )
        return ExecutionResult(
            ExecutionDisposition.SUPPRESSED,
            completed,
            effect,
            reason,
            command.request.reference_id,
        )

    def _escalate(
        self,
        *,
        job: OutboxJob,
        command: CreatePaymentLinkCommand,
        worker_id: str,
        now: datetime,
        effect: GateDecision,
        reason: str,
    ) -> ExecutionResult:
        dead = job.dead_letter(
            worker_id=worker_id,
            lease_token=job.lease_token or "missing-lease-token",
            now=now,
            expected_version=job.version,
            reason=reason,
        )
        return ExecutionResult(
            ExecutionDisposition.ESCALATED,
            dead,
            effect,
            reason,
            command.request.reference_id,
        )
