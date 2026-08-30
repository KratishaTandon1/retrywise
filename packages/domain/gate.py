"""Pure two-stage policy/effect authorization gate.

The gate has no clock, database, model, or provider client. Every fact is passed
in explicitly, and reason codes are emitted in a fixed order. Planning and
effect execution therefore evaluate the same predicates reproducibly while the
effect stage additionally proves durable intent and its planning authorization.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from .actions import (
    COLLECTION_ACTIONS,
    CONTACT_ACTIONS,
    EXTERNAL_ACTIONS,
    ActionProposal,
    ActionType,
    Approval,
)
from .canonical import canonical_json_bytes, canonical_timestamp, require_utc
from .errors import InvalidValue
from .states import CanonicalPaymentState, IncidentState, RecoveryState
from .values import Money, Probability, require_identifier, require_payment_method


class GateStage(StrEnum):
    POLICY = "policy"
    EFFECT = "effect"


class GateReason(StrEnum):
    PROPOSAL_MERCHANT_MISMATCH = "PROPOSAL_MERCHANT_MISMATCH"
    PROPOSAL_CASE_MISMATCH = "PROPOSAL_CASE_MISMATCH"
    ACTION_NOT_YET_VALID = "ACTION_NOT_YET_VALID"
    ACTION_EXPIRED = "ACTION_EXPIRED"
    ACTION_NOT_ALLOWED = "ACTION_NOT_ALLOWED"
    ENVIRONMENT_EFFECTS_DISABLED = "ENVIRONMENT_EFFECTS_DISABLED"
    GLOBAL_KILL_SWITCH_ACTIVE = "GLOBAL_KILL_SWITCH_ACTIVE"
    MERCHANT_KILL_SWITCH_ACTIVE = "MERCHANT_KILL_SWITCH_ACTIVE"
    AGGREGATE_VERSION_MISMATCH = "AGGREGATE_VERSION_MISMATCH"
    RECOVERY_STATE_NOT_ACTIONABLE = "RECOVERY_STATE_NOT_ACTIONABLE"
    OBSERVATION_DEADLINE_MISSING = "OBSERVATION_DEADLINE_MISSING"
    OBSERVATION_WINDOW_ACTIVE = "OBSERVATION_WINDOW_ACTIVE"
    PAYMENT_TRUTH_NOT_UNPAID = "PAYMENT_TRUTH_NOT_UNPAID"
    PROVIDER_SNAPSHOT_FROM_FUTURE = "PROVIDER_SNAPSHOT_FROM_FUTURE"
    PROVIDER_SNAPSHOT_STALE = "PROVIDER_SNAPSHOT_STALE"
    ACTIVE_INSTRUMENT_EXISTS = "ACTIVE_INSTRUMENT_EXISTS"
    ACTIVE_INSTRUMENT_REQUIRED = "ACTIVE_INSTRUMENT_REQUIRED"
    POLICY_CURRENCY_MISMATCH = "POLICY_CURRENCY_MISMATCH"
    CURRENCY_MISMATCH = "CURRENCY_MISMATCH"
    AMOUNT_MISMATCH = "AMOUNT_MISMATCH"
    PAYMENT_METHOD_MISMATCH = "PAYMENT_METHOD_MISMATCH"
    CONSENT_MISSING = "CONSENT_MISSING"
    CUSTOMER_OPTED_OUT = "CUSTOMER_OPTED_OUT"
    COOLDOWN_ACTIVE = "COOLDOWN_ACTIVE"
    CONTACT_CAP_REACHED = "CONTACT_CAP_REACHED"
    QUIET_HOURS_ACTIVE = "QUIET_HOURS_ACTIVE"
    INCIDENT_HEALTH_FROM_FUTURE = "INCIDENT_HEALTH_FROM_FUTURE"
    INCIDENT_HEALTH_STALE = "INCIDENT_HEALTH_STALE"
    PAYMENT_METHOD_UNHEALTHY = "PAYMENT_METHOD_UNHEALTHY"
    ATTEMPT_BUDGET_EXHAUSTED = "ATTEMPT_BUDGET_EXHAUSTED"
    CONFIDENCE_UNAVAILABLE = "CONFIDENCE_UNAVAILABLE"
    CONFIDENCE_BELOW_THRESHOLD = "CONFIDENCE_BELOW_THRESHOLD"
    ABSTENTION_REQUIRES_APPROVAL = "ABSTENTION_REQUIRES_APPROVAL"
    HIGH_VALUE_REQUIRES_APPROVAL = "HIGH_VALUE_REQUIRES_APPROVAL"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_NOT_YET_VALID = "APPROVAL_NOT_YET_VALID"
    APPROVAL_BINDING_MISMATCH = "APPROVAL_BINDING_MISMATCH"
    PLAN_AUTHORIZATION_MISSING = "PLAN_AUTHORIZATION_MISSING"
    PLAN_BINDING_MISMATCH = "PLAN_BINDING_MISMATCH"
    DURABLE_INTENT_MISSING = "DURABLE_INTENT_MISSING"


APPROVAL_BLOCKING_REASONS = frozenset(
    {
        GateReason.CONFIDENCE_UNAVAILABLE,
        GateReason.CONFIDENCE_BELOW_THRESHOLD,
        GateReason.ABSTENTION_REQUIRES_APPROVAL,
        GateReason.HIGH_VALUE_REQUIRES_APPROVAL,
        GateReason.APPROVAL_REQUIRED,
        GateReason.APPROVAL_REJECTED,
        GateReason.APPROVAL_EXPIRED,
        GateReason.APPROVAL_NOT_YET_VALID,
        GateReason.APPROVAL_BINDING_MISMATCH,
    }
)


@dataclass(frozen=True, slots=True)
class GatePolicy:
    version: str
    allowed_actions: frozenset[ActionType]
    provider_snapshot_max_age: timedelta
    incident_health_max_age: timedelta
    max_attempts: int
    max_contacts_in_window: int
    approval_threshold: Money
    min_confidence: Probability
    allowed_clock_skew: timedelta = timedelta(seconds=5)

    def __post_init__(self) -> None:
        require_identifier(self.version, field="policy version")
        actions = frozenset(self.allowed_actions)
        if not actions or any(not isinstance(item, ActionType) for item in actions):
            raise InvalidValue("allowed_actions must contain ActionType values")
        object.__setattr__(self, "allowed_actions", actions)
        if not isinstance(self.approval_threshold, Money):
            raise InvalidValue("approval_threshold must be Money")
        if not isinstance(self.min_confidence, Probability):
            raise InvalidValue("min_confidence must be Probability")
        for name, duration in (
            ("provider_snapshot_max_age", self.provider_snapshot_max_age),
            ("incident_health_max_age", self.incident_health_max_age),
            ("allowed_clock_skew", self.allowed_clock_skew),
        ):
            if not isinstance(duration, timedelta) or duration < timedelta(0):
                raise InvalidValue(f"{name} must be a non-negative timedelta")
        for name, value in (
            ("max_attempts", self.max_attempts),
            ("max_contacts_in_window", self.max_contacts_in_window),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise InvalidValue(f"{name} must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class ProviderSnapshot:
    payment_state: CanonicalPaymentState
    amount_due: Money
    payment_method: str
    observed_at: datetime
    active_instrument_count: int
    incident_state: IncidentState
    method_health_observed_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.payment_state, CanonicalPaymentState):
            raise InvalidValue("snapshot payment_state is invalid")
        if not isinstance(self.incident_state, IncidentState):
            raise InvalidValue("snapshot incident_state is invalid")
        if not isinstance(self.amount_due, Money):
            raise InvalidValue("snapshot amount_due must be Money")
        require_payment_method(self.payment_method, field="snapshot payment_method")
        if isinstance(self.active_instrument_count, bool) or not isinstance(
            self.active_instrument_count, int
        ):
            raise InvalidValue("active_instrument_count must be an integer")
        if self.active_instrument_count < 0:
            raise InvalidValue("active_instrument_count cannot be negative")
        object.__setattr__(self, "observed_at", require_utc(self.observed_at, field="observed_at"))
        object.__setattr__(
            self,
            "method_health_observed_at",
            require_utc(
                self.method_health_observed_at,
                field="method_health_observed_at",
            ),
        )


@dataclass(frozen=True, slots=True)
class GateContext:
    merchant_id: str
    case_id: str
    evaluated_at: datetime
    aggregate_version: int
    expected_aggregate_version: int
    recovery_state: RecoveryState
    snapshot: ProviderSnapshot
    environment_effects_enabled: bool
    observation_deadline: datetime | None = None
    global_kill_switch: bool = False
    merchant_kill_switch: bool = False
    consent_granted: bool = True
    opted_out: bool = False
    cooldown_until: datetime | None = None
    contacts_in_window: int = 0
    quiet_hours_active: bool = False
    attempts_used: int = 0
    abstention_required: bool = False
    approval: Approval | None = None
    durable_intent_recorded: bool = False

    def __post_init__(self) -> None:
        require_identifier(self.merchant_id, field="merchant_id")
        require_identifier(self.case_id, field="case_id")
        object.__setattr__(
            self,
            "evaluated_at",
            require_utc(self.evaluated_at, field="evaluated_at"),
        )
        for name, value in (
            ("aggregate_version", self.aggregate_version),
            ("expected_aggregate_version", self.expected_aggregate_version),
            ("contacts_in_window", self.contacts_in_window),
            ("attempts_used", self.attempts_used),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise InvalidValue(f"{name} must be a non-negative integer")
        if not isinstance(self.recovery_state, RecoveryState):
            raise InvalidValue("recovery_state is invalid")
        if not isinstance(self.snapshot, ProviderSnapshot):
            raise InvalidValue("snapshot must be a ProviderSnapshot value")
        for name in (
            "environment_effects_enabled",
            "global_kill_switch",
            "merchant_kill_switch",
            "consent_granted",
            "opted_out",
            "quiet_hours_active",
            "abstention_required",
            "durable_intent_recorded",
        ):
            if not isinstance(getattr(self, name), bool):
                raise InvalidValue(f"{name} must be boolean")
        if self.approval is not None and not isinstance(self.approval, Approval):
            raise InvalidValue("approval must be an Approval value")
        if self.cooldown_until is not None:
            object.__setattr__(
                self,
                "cooldown_until",
                require_utc(self.cooldown_until, field="cooldown_until"),
            )
        if self.observation_deadline is not None:
            object.__setattr__(
                self,
                "observation_deadline",
                require_utc(self.observation_deadline, field="observation_deadline"),
            )


@dataclass(frozen=True, slots=True)
class GateDecision:
    stage: GateStage
    policy_version: str
    proposal_id: str
    action_key: str
    proposal_digest: str
    case_id: str
    decision_version: int
    aggregate_version: int
    evaluated_at: datetime
    reasons: tuple[GateReason, ...]

    @property
    def allowed(self) -> bool:
        return not self.reasons

    @property
    def decision_digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_primitive())).hexdigest()

    def to_primitive(self) -> dict[str, Any]:
        return {
            "action_key": self.action_key,
            "aggregate_version": self.aggregate_version,
            "allowed": self.allowed,
            "case_id": self.case_id,
            "decision_version": self.decision_version,
            "evaluated_at": canonical_timestamp(self.evaluated_at),
            "policy_version": self.policy_version,
            "proposal_digest": self.proposal_digest,
            "proposal_id": self.proposal_id,
            "reasons": [reason.value for reason in self.reasons],
            "stage": self.stage.value,
        }


_POLICY_ACTIONABLE_STATES = {
    ActionType.CREATE_STANDARD_PAYMENT_LINK: frozenset(
        {RecoveryState.ASSESSING, RecoveryState.APPROVAL_REQUIRED}
    ),
    ActionType.NOTIFY_EXISTING_LINK: frozenset(
        {RecoveryState.ASSESSING, RecoveryState.APPROVAL_REQUIRED, RecoveryState.ACTIVE}
    ),
    ActionType.CANCEL_PAYMENT_LINK: frozenset(
        {
            RecoveryState.EXECUTING,
            RecoveryState.ACTION_UNCERTAIN,
            RecoveryState.ACTIVE,
            RecoveryState.SUPPRESSED_PAID,
            RecoveryState.DUPLICATE_REVIEW,
        }
    ),
    ActionType.WAIT: frozenset({RecoveryState.ASSESSING}),
    ActionType.ESCALATE: frozenset(
        {
            RecoveryState.ASSESSING,
            RecoveryState.WAITING,
            RecoveryState.ACTION_UNCERTAIN,
        }
    ),
    ActionType.STOP: frozenset(
        {
            RecoveryState.ASSESSING,
            RecoveryState.WAITING,
            RecoveryState.APPROVAL_REQUIRED,
            RecoveryState.ACTION_QUEUED,
        }
    ),
}


_EFFECT_ACTIONABLE_STATES = {
    ActionType.CREATE_STANDARD_PAYMENT_LINK: frozenset(
        {
            RecoveryState.ACTION_QUEUED,
            RecoveryState.EXECUTING,
            RecoveryState.ACTION_UNCERTAIN,
        }
    ),
    ActionType.NOTIFY_EXISTING_LINK: frozenset(
        {RecoveryState.ACTION_QUEUED, RecoveryState.EXECUTING, RecoveryState.ACTIVE}
    ),
    ActionType.CANCEL_PAYMENT_LINK: _POLICY_ACTIONABLE_STATES[ActionType.CANCEL_PAYMENT_LINK],
    ActionType.WAIT: frozenset(),
    ActionType.ESCALATE: frozenset(),
    ActionType.STOP: frozenset(),
}


class DeterministicGate:
    """Evaluate policy authorization and re-authorization before effects."""

    def __init__(self, policy: GatePolicy) -> None:
        self.policy = policy

    def evaluate_policy(self, proposal: ActionProposal, context: GateContext) -> GateDecision:
        return self._evaluate(
            stage=GateStage.POLICY,
            proposal=proposal,
            context=context,
            prior_plan=None,
        )

    def evaluate_effect(
        self,
        proposal: ActionProposal,
        context: GateContext,
        *,
        prior_plan: GateDecision | None,
    ) -> GateDecision:
        return self._evaluate(
            stage=GateStage.EFFECT,
            proposal=proposal,
            context=context,
            prior_plan=prior_plan,
        )

    def _evaluate(
        self,
        *,
        stage: GateStage,
        proposal: ActionProposal,
        context: GateContext,
        prior_plan: GateDecision | None,
    ) -> GateDecision:
        reasons: list[GateReason] = []
        policy = self.policy
        is_collection = proposal.action_type in COLLECTION_ACTIONS
        is_contact = proposal.action_type in CONTACT_ACTIONS
        is_external = proposal.action_type in EXTERNAL_ACTIONS

        if proposal.merchant_id != context.merchant_id:
            reasons.append(GateReason.PROPOSAL_MERCHANT_MISMATCH)
        if proposal.case_id != context.case_id:
            reasons.append(GateReason.PROPOSAL_CASE_MISMATCH)
        if proposal.created_at > context.evaluated_at + policy.allowed_clock_skew:
            reasons.append(GateReason.ACTION_NOT_YET_VALID)
        if context.evaluated_at >= proposal.expires_at:
            reasons.append(GateReason.ACTION_EXPIRED)
        if proposal.action_type not in policy.allowed_actions:
            reasons.append(GateReason.ACTION_NOT_ALLOWED)
        if is_external and not context.environment_effects_enabled:
            reasons.append(GateReason.ENVIRONMENT_EFFECTS_DISABLED)
        if is_collection and context.global_kill_switch:
            reasons.append(GateReason.GLOBAL_KILL_SWITCH_ACTIVE)
        if is_collection and context.merchant_kill_switch:
            reasons.append(GateReason.MERCHANT_KILL_SWITCH_ACTIVE)
        if context.aggregate_version != context.expected_aggregate_version:
            reasons.append(GateReason.AGGREGATE_VERSION_MISMATCH)

        actionable_states = (
            _POLICY_ACTIONABLE_STATES if stage is GateStage.POLICY else _EFFECT_ACTIONABLE_STATES
        )[proposal.action_type]
        if context.recovery_state not in actionable_states:
            reasons.append(GateReason.RECOVERY_STATE_NOT_ACTIONABLE)

        if is_collection:
            if context.observation_deadline is None:
                reasons.append(GateReason.OBSERVATION_DEADLINE_MISSING)
            elif context.evaluated_at < context.observation_deadline:
                reasons.append(GateReason.OBSERVATION_WINDOW_ACTIVE)

        snapshot = context.snapshot
        if is_collection:
            if snapshot.payment_state is not CanonicalPaymentState.UNPAID:
                reasons.append(GateReason.PAYMENT_TRUTH_NOT_UNPAID)
            if snapshot.observed_at > context.evaluated_at + policy.allowed_clock_skew:
                reasons.append(GateReason.PROVIDER_SNAPSHOT_FROM_FUTURE)
            elif context.evaluated_at - snapshot.observed_at > policy.provider_snapshot_max_age:
                reasons.append(GateReason.PROVIDER_SNAPSHOT_STALE)

        if proposal.action_type is ActionType.CREATE_STANDARD_PAYMENT_LINK:
            if snapshot.active_instrument_count > 0:
                reasons.append(GateReason.ACTIVE_INSTRUMENT_EXISTS)
        elif (
            proposal.action_type
            in {
                ActionType.NOTIFY_EXISTING_LINK,
                ActionType.CANCEL_PAYMENT_LINK,
            }
            and snapshot.active_instrument_count == 0
        ):
            reasons.append(GateReason.ACTIVE_INSTRUMENT_REQUIRED)

        if is_collection and proposal.amount is not None:
            if proposal.amount.currency != snapshot.amount_due.currency:
                reasons.append(GateReason.CURRENCY_MISMATCH)
            elif proposal.amount.minor_units != snapshot.amount_due.minor_units:
                reasons.append(GateReason.AMOUNT_MISMATCH)
            if proposal.payment_method != snapshot.payment_method:
                reasons.append(GateReason.PAYMENT_METHOD_MISMATCH)

        if is_contact:
            if not context.consent_granted:
                reasons.append(GateReason.CONSENT_MISSING)
            if context.opted_out:
                reasons.append(GateReason.CUSTOMER_OPTED_OUT)
            if context.cooldown_until is not None and context.evaluated_at < context.cooldown_until:
                reasons.append(GateReason.COOLDOWN_ACTIVE)
            if context.contacts_in_window >= policy.max_contacts_in_window:
                reasons.append(GateReason.CONTACT_CAP_REACHED)
            if context.quiet_hours_active:
                reasons.append(GateReason.QUIET_HOURS_ACTIVE)

        if is_collection:
            if (
                snapshot.method_health_observed_at
                > context.evaluated_at + policy.allowed_clock_skew
            ):
                reasons.append(GateReason.INCIDENT_HEALTH_FROM_FUTURE)
            elif (
                context.evaluated_at - snapshot.method_health_observed_at
                > policy.incident_health_max_age
            ):
                reasons.append(GateReason.INCIDENT_HEALTH_STALE)
            if snapshot.incident_state is IncidentState.CONFIRMED:
                reasons.append(GateReason.PAYMENT_METHOD_UNHEALTHY)
            if context.attempts_used >= policy.max_attempts:
                reasons.append(GateReason.ATTEMPT_BUDGET_EXHAUSTED)

        if is_collection:
            approval_causes: list[GateReason] = []
            if proposal.amount is not None:
                if proposal.amount.currency != policy.approval_threshold.currency:
                    reasons.append(GateReason.POLICY_CURRENCY_MISMATCH)
                elif proposal.amount.minor_units >= policy.approval_threshold.minor_units:
                    approval_causes.append(GateReason.HIGH_VALUE_REQUIRES_APPROVAL)
            if proposal.model_confidence is None:
                approval_causes.append(GateReason.CONFIDENCE_UNAVAILABLE)
            elif proposal.model_confidence < policy.min_confidence:
                approval_causes.append(GateReason.CONFIDENCE_BELOW_THRESHOLD)
            if context.abstention_required:
                approval_causes.append(GateReason.ABSTENTION_REQUIRES_APPROVAL)
            approval_needed = proposal.requires_approval or bool(approval_causes)
            if approval_needed:
                approval_reason = self._approval_failure(proposal, context)
                if approval_reason is not None:
                    reasons.extend(approval_causes)
                    reasons.append(approval_reason)

        if stage is GateStage.EFFECT and is_external:
            if prior_plan is None:
                reasons.append(GateReason.PLAN_AUTHORIZATION_MISSING)
            elif not self._plan_matches(prior_plan, proposal, context):
                reasons.append(GateReason.PLAN_BINDING_MISMATCH)
            if not context.durable_intent_recorded:
                reasons.append(GateReason.DURABLE_INTENT_MISSING)

        return GateDecision(
            stage=stage,
            policy_version=policy.version,
            proposal_id=proposal.proposal_id,
            action_key=proposal.action_key,
            proposal_digest=proposal.proposal_digest,
            case_id=proposal.case_id,
            decision_version=proposal.decision_version,
            aggregate_version=context.aggregate_version,
            evaluated_at=context.evaluated_at,
            reasons=tuple(reasons),
        )

    def _approval_failure(
        self, proposal: ActionProposal, context: GateContext
    ) -> GateReason | None:
        approval = context.approval
        if approval is None:
            return GateReason.APPROVAL_REQUIRED
        if not approval.granted:
            return GateReason.APPROVAL_REJECTED
        if context.evaluated_at < approval.approved_at:
            return GateReason.APPROVAL_NOT_YET_VALID
        if context.evaluated_at >= approval.expires_at:
            return GateReason.APPROVAL_EXPIRED
        if (
            approval.merchant_id != proposal.merchant_id
            or approval.case_id != proposal.case_id
            or approval.action_key != proposal.action_key
            or approval.proposal_digest != proposal.proposal_digest
            or approval.decision_version != proposal.decision_version
        ):
            return GateReason.APPROVAL_BINDING_MISMATCH
        return None

    def _plan_matches(
        self,
        prior_plan: GateDecision,
        proposal: ActionProposal,
        context: GateContext,
    ) -> bool:
        return (
            prior_plan.stage is GateStage.POLICY
            and prior_plan.allowed
            and prior_plan.policy_version == self.policy.version
            and prior_plan.proposal_id == proposal.proposal_id
            and prior_plan.action_key == proposal.action_key
            and prior_plan.proposal_digest == proposal.proposal_digest
            and prior_plan.case_id == proposal.case_id
            and prior_plan.decision_version == proposal.decision_version
            and prior_plan.aggregate_version <= context.aggregate_version
            and prior_plan.evaluated_at <= context.evaluated_at
        )
