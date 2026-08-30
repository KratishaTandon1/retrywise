"""Immutable, versioned recovery-case aggregate.

Commands are deterministic and return a new aggregate plus immutable domain
events. No method reads time, performs I/O, or mutates an existing instance.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any

from .actions import (
    COLLECTION_ACTIONS,
    INTERNAL_ACTIONS,
    ActionProposal,
    ActionType,
)
from .canonical import canonical_json, canonical_timestamp, require_utc
from .errors import (
    AuthorizationBindingError,
    DomainError,
    InvalidTransition,
    InvalidValue,
    VersionConflict,
)
from .gate import (
    APPROVAL_BLOCKING_REASONS,
    GateDecision,
    GateStage,
)
from .states import (
    COLLECTION_TERMINAL_STATES,
    NONTERMINAL_RECOVERY_STATES,
    CanonicalPaymentState,
    IncidentState,
    RecoveryState,
    validate_incident_transition,
    validate_payment_transition,
    validate_recovery_transition,
)
from .values import LateCapturePolicy, Money, require_identifier


@dataclass(frozen=True, slots=True)
class AggregateEvent:
    event_type: str
    case_id: str
    version: int
    occurred_at: datetime
    payload_json: str

    @property
    def payload(self) -> dict[str, Any]:
        payload = json.loads(self.payload_json)
        if not isinstance(payload, dict):
            raise InvalidValue("aggregate event payload must decode to an object")
        return payload

    def to_primitive(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "event_type": self.event_type,
            "occurred_at": canonical_timestamp(self.occurred_at),
            "payload": self.payload,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class AggregateChange:
    aggregate: RecoveryAggregate
    events: tuple[AggregateEvent, ...]

    @property
    def changed(self) -> bool:
        return bool(self.events)


@dataclass(frozen=True, slots=True)
class RecoveryAggregate:
    merchant_id: str
    case_id: str
    logical_order_id: str
    amount_due: Money
    state: RecoveryState = RecoveryState.DORMANT
    payment_state: CanonicalPaymentState = CanonicalPaymentState.UNKNOWN
    incident_state: IncidentState = IncidentState.NORMAL
    version: int = 0
    decision_version: int = 0
    active_action_key: str | None = None
    active_proposal_id: str | None = None
    active_instrument_reference: str | None = None
    last_transition_at: datetime | None = None
    late_capture_policy: LateCapturePolicy = field(default_factory=LateCapturePolicy)
    observation_started_at: datetime | None = None
    observation_deadline: datetime | None = None

    def __post_init__(self) -> None:
        require_identifier(self.merchant_id, field="merchant_id")
        require_identifier(self.case_id, field="case_id")
        require_identifier(self.logical_order_id, field="logical_order_id")
        if self.amount_due.minor_units <= 0:
            raise InvalidValue("recovery amount_due must be positive")
        if not isinstance(self.state, RecoveryState):
            raise InvalidValue("aggregate recovery state is invalid")
        if not isinstance(self.payment_state, CanonicalPaymentState):
            raise InvalidValue("aggregate payment state is invalid")
        if not isinstance(self.incident_state, IncidentState):
            raise InvalidValue("aggregate incident state is invalid")
        if not isinstance(self.late_capture_policy, LateCapturePolicy):
            raise InvalidValue("late_capture_policy must be a LateCapturePolicy value")
        for name, counter_value in (
            ("version", self.version),
            ("decision_version", self.decision_version),
        ):
            if (
                isinstance(counter_value, bool)
                or not isinstance(counter_value, int)
                or counter_value < 0
            ):
                raise InvalidValue(f"{name} must be a non-negative integer")
        if self.version < self.decision_version:
            raise InvalidValue("decision_version cannot exceed aggregate version")
        for name, identifier_value in (
            ("active_action_key", self.active_action_key),
            ("active_proposal_id", self.active_proposal_id),
            ("active_instrument_reference", self.active_instrument_reference),
        ):
            if identifier_value is not None:
                require_identifier(identifier_value, field=name)
        if self.active_action_key is not None and not self.active_action_key.startswith("act_"):
            raise InvalidValue("active_action_key has an invalid prefix")
        if self.last_transition_at is not None:
            object.__setattr__(
                self,
                "last_transition_at",
                require_utc(self.last_transition_at, field="last_transition_at"),
            )
        if self.observation_started_at is not None:
            object.__setattr__(
                self,
                "observation_started_at",
                require_utc(self.observation_started_at, field="observation_started_at"),
            )
        if self.observation_deadline is not None:
            object.__setattr__(
                self,
                "observation_deadline",
                require_utc(self.observation_deadline, field="observation_deadline"),
            )
        if self.state is RecoveryState.DORMANT:
            if self.observation_started_at is not None or self.observation_deadline is not None:
                raise InvalidValue("a dormant case cannot have observation timing")
        elif self.observation_started_at is None or self.observation_deadline is None:
            raise InvalidValue("a started recovery case requires observation timing")
        elif self.last_transition_at is None:
            raise InvalidValue("a started recovery case requires a last transition time")
        if self.observation_started_at is not None and self.observation_deadline is not None:
            minimum_deadline = (
                self.observation_started_at + self.late_capture_policy.minimum_observation_window
            )
            if self.observation_deadline < minimum_deadline:
                raise InvalidValue("observation deadline is below the bound policy floor")
            if (
                self.last_transition_at is not None
                and self.observation_started_at > self.last_transition_at
            ):
                raise InvalidValue("observation start cannot follow the last transition")

    @property
    def collection_closed(self) -> bool:
        return self.state in COLLECTION_TERMINAL_STATES

    def observe_failure(
        self,
        *,
        expected_version: int,
        at: datetime,
        provider_event_id: str,
        extend_observation_until: datetime | None = None,
    ) -> AggregateChange:
        self._require_version(expected_version)
        require_identifier(provider_event_id, field="provider_event_id")
        self._require_recovery_transition(RecoveryState.OBSERVING)
        observed_at = require_utc(at, field="occurred_at")
        observation_deadline = self.late_capture_policy.observation_deadline(
            observed_at=observed_at,
            extend_until=extend_observation_until,
        )
        return self._change(
            event_type="RecoveryObservationStarted",
            at=observed_at,
            payload={
                "late_capture_policy": self.late_capture_policy.to_primitive(),
                "observation_deadline": observation_deadline,
                "provider_event_id": provider_event_id,
            },
            state=RecoveryState.OBSERVING,
            observation_started_at=observed_at,
            observation_deadline=observation_deadline,
        )

    def reconcile_payment_truth(
        self,
        target: CanonicalPaymentState,
        *,
        expected_version: int,
        at: datetime,
        evidence: str,
    ) -> AggregateChange:
        self._require_version(expected_version)
        require_identifier(evidence, field="evidence")
        if target in {
            CanonicalPaymentState.PAID,
            CanonicalPaymentState.OVERPAID,
        }:
            raise DomainError("paid truth requires a path-aware success or duplicate command")
        changed = validate_payment_transition(self.payment_state, target)
        if not changed:
            return AggregateChange(self, ())
        return self._change(
            event_type="CanonicalPaymentTruthChanged",
            at=at,
            payload={
                "evidence": evidence,
                "from": self.payment_state.value,
                "to": target.value,
            },
            payment_state=target,
        )

    def update_incident_state(
        self,
        target: IncidentState,
        *,
        expected_version: int,
        at: datetime,
        evidence: str,
    ) -> AggregateChange:
        self._require_version(expected_version)
        require_identifier(evidence, field="evidence")
        changed = validate_incident_transition(self.incident_state, target)
        if not changed:
            return AggregateChange(self, ())
        return self._change(
            event_type="IncidentStateChanged",
            at=at,
            payload={
                "evidence": evidence,
                "from": self.incident_state.value,
                "to": target.value,
            },
            incident_state=target,
        )

    def mark_ready_for_evaluation(self, *, expected_version: int, at: datetime) -> AggregateChange:
        self._require_version(expected_version)
        self._require_recovery_transition(RecoveryState.ASSESSING)
        if self.payment_state is not CanonicalPaymentState.UNPAID:
            raise DomainError("only freshly reconciled UNPAID truth can be assessed")
        return self._workflow_change(
            RecoveryState.ASSESSING,
            event_type="RecoveryAssessmentStarted",
            at=at,
            payload={"observation_deadline": self.observation_deadline},
        )

    def wait(self, *, expected_version: int, at: datetime, reason: str) -> AggregateChange:
        self._require_version(expected_version)
        require_identifier(reason, field="reason")
        self._require_recovery_transition(RecoveryState.WAITING)
        return self._workflow_change(
            RecoveryState.WAITING,
            event_type="RecoveryWaitScheduled",
            at=at,
            payload={"reason": reason},
        )

    def wake(self, *, expected_version: int, at: datetime) -> AggregateChange:
        self._require_version(expected_version)
        self._require_recovery_transition(RecoveryState.ASSESSING)
        if self.payment_state is not CanonicalPaymentState.UNPAID:
            raise DomainError("waiting case cannot re-open without UNPAID truth")
        return self._workflow_change(
            RecoveryState.ASSESSING,
            event_type="RecoveryWaitElapsed",
            at=at,
            payload={},
        )

    def request_approval(
        self,
        proposal: ActionProposal,
        plan_decision: GateDecision,
        *,
        expected_version: int,
        at: datetime,
    ) -> AggregateChange:
        self._require_version(expected_version)
        if self.state is not RecoveryState.ASSESSING:
            raise InvalidTransition(
                machine="recovery",
                current=self.state.value,
                target=RecoveryState.APPROVAL_REQUIRED.value,
            )
        self._require_observation_elapsed(at)
        self._require_proposal_binding(proposal, next_decision=True)
        self._require_gate_binding(proposal, plan_decision, stage=GateStage.POLICY, allowed=False)
        reasons = frozenset(plan_decision.reasons)
        if not reasons or not reasons.issubset(APPROVAL_BLOCKING_REASONS):
            raise AuthorizationBindingError("approval cannot override non-approval safety failures")
        if proposal.action_type not in COLLECTION_ACTIONS:
            raise DomainError("only collection proposals use approval workflow")
        if self.payment_state is not CanonicalPaymentState.UNPAID:
            raise DomainError("approval cannot be requested unless payment is UNPAID")
        return self._workflow_change(
            RecoveryState.APPROVAL_REQUIRED,
            event_type="RecoveryApprovalRequested",
            at=at,
            payload={
                "gate_digest": plan_decision.decision_digest,
                "proposal": proposal.to_primitive(),
                "reason_codes": [reason.value for reason in plan_decision.reasons],
            },
            decision_version=proposal.decision_version,
            active_action_key=proposal.action_key,
            active_proposal_id=proposal.proposal_id,
        )

    def authorize_action(
        self,
        proposal: ActionProposal,
        plan_decision: GateDecision,
        *,
        expected_version: int,
        at: datetime,
    ) -> AggregateChange:
        self._require_version(expected_version)
        if self.state not in {
            RecoveryState.ASSESSING,
            RecoveryState.APPROVAL_REQUIRED,
        }:
            raise InvalidTransition(
                machine="recovery",
                current=self.state.value,
                target=RecoveryState.ACTION_QUEUED.value,
            )
        self._require_observation_elapsed(at)
        self._require_proposal_binding(
            proposal, next_decision=self.state is RecoveryState.ASSESSING
        )
        self._require_gate_binding(proposal, plan_decision, stage=GateStage.POLICY, allowed=True)
        if proposal.action_type not in COLLECTION_ACTIONS:
            raise DomainError("only collection actions enter the execution workflow")
        if self.payment_state is not CanonicalPaymentState.UNPAID:
            raise DomainError("only UNPAID truth can authorize collection")
        if self.state is RecoveryState.APPROVAL_REQUIRED and (
            self.active_action_key != proposal.action_key
            or self.active_proposal_id != proposal.proposal_id
        ):
            raise AuthorizationBindingError("approved proposal does not match the pending decision")
        self._require_recovery_transition(RecoveryState.ACTION_QUEUED)
        return self._workflow_change(
            RecoveryState.ACTION_QUEUED,
            event_type="RecoveryActionAuthorized",
            at=at,
            payload={
                "gate_digest": plan_decision.decision_digest,
                "proposal": proposal.to_primitive(),
            },
            decision_version=proposal.decision_version,
            active_action_key=proposal.action_key,
            active_proposal_id=proposal.proposal_id,
        )

    def record_internal_decision(
        self,
        proposal: ActionProposal,
        plan_decision: GateDecision,
        *,
        expected_version: int,
        at: datetime,
    ) -> AggregateChange:
        self._require_version(expected_version)
        if proposal.action_type not in INTERNAL_ACTIONS:
            raise DomainError("proposal is not an internal action")
        self._require_proposal_binding(proposal, next_decision=True)
        self._require_gate_binding(proposal, plan_decision, stage=GateStage.POLICY, allowed=True)
        target = {
            ActionType.WAIT: RecoveryState.WAITING,
            ActionType.ESCALATE: RecoveryState.ESCALATED,
            ActionType.STOP: RecoveryState.SUPPRESSED_POLICY,
        }[proposal.action_type]
        self._require_recovery_transition(target)
        return self._workflow_change(
            target,
            event_type="RecoveryInternalDecisionRecorded",
            at=at,
            payload={
                "gate_digest": plan_decision.decision_digest,
                "proposal": proposal.to_primitive(),
            },
            decision_version=proposal.decision_version,
        )

    def begin_execution(
        self,
        proposal: ActionProposal,
        effect_decision: GateDecision,
        *,
        expected_version: int,
        at: datetime,
    ) -> AggregateChange:
        self._require_version(expected_version)
        self._require_proposal_binding(proposal, next_decision=False)
        self._require_gate_binding(proposal, effect_decision, stage=GateStage.EFFECT, allowed=True)
        if self.state is not RecoveryState.ACTION_QUEUED:
            raise InvalidTransition(
                machine="recovery",
                current=self.state.value,
                target=RecoveryState.EXECUTING.value,
            )
        self._require_observation_elapsed(at)
        if self.active_action_key != proposal.action_key:
            raise AuthorizationBindingError("effect action key is not pending")
        if self.payment_state is not CanonicalPaymentState.UNPAID:
            raise DomainError("payment truth changed before execution")
        return self._workflow_change(
            RecoveryState.EXECUTING,
            event_type="RecoveryActionExecutionStarted",
            at=at,
            payload={
                "effect_gate_digest": effect_decision.decision_digest,
                "action_key": proposal.action_key,
            },
        )

    def record_action_active(
        self,
        *,
        expected_version: int,
        at: datetime,
        action_key: str,
        instrument_reference: str,
    ) -> AggregateChange:
        self._require_version(expected_version)
        self._require_active_action(action_key)
        require_identifier(instrument_reference, field="instrument_reference")
        if (
            self.state is RecoveryState.ACTIVE
            and self.active_instrument_reference == instrument_reference
        ):
            return AggregateChange(self, ())
        self._require_recovery_transition(RecoveryState.ACTIVE)
        return self._workflow_change(
            RecoveryState.ACTIVE,
            event_type="RecoveryInstrumentActivated",
            at=at,
            payload={
                "action_key": action_key,
                "instrument_reference": instrument_reference,
            },
            active_instrument_reference=instrument_reference,
        )

    def record_action_uncertain(
        self,
        *,
        expected_version: int,
        at: datetime,
        action_key: str,
        failure_code: str,
    ) -> AggregateChange:
        self._require_version(expected_version)
        self._require_active_action(action_key)
        require_identifier(failure_code, field="failure_code")
        self._require_recovery_transition(RecoveryState.ACTION_UNCERTAIN)
        return self._workflow_change(
            RecoveryState.ACTION_UNCERTAIN,
            event_type="RecoveryActionOutcomeUncertain",
            at=at,
            payload={"action_key": action_key, "failure_code": failure_code},
        )

    def requeue_after_absence_proven(
        self,
        *,
        expected_version: int,
        at: datetime,
        action_key: str,
    ) -> AggregateChange:
        self._require_version(expected_version)
        self._require_active_action(action_key)
        self._require_recovery_transition(RecoveryState.ACTION_QUEUED)
        return self._workflow_change(
            RecoveryState.ACTION_QUEUED,
            event_type="RecoveryActionAbsenceProven",
            at=at,
            payload={"action_key": action_key},
        )

    def escalate_uncertain_action(
        self,
        *,
        expected_version: int,
        at: datetime,
        action_key: str,
        reason: str,
    ) -> AggregateChange:
        self._require_version(expected_version)
        self._require_active_action(action_key)
        require_identifier(reason, field="reason")
        self._require_recovery_transition(RecoveryState.ESCALATED)
        return self._workflow_change(
            RecoveryState.ESCALATED,
            event_type="RecoveryActionEscalated",
            at=at,
            payload={"action_key": action_key, "reason": reason},
        )

    def record_action_failed_safe(
        self,
        *,
        expected_version: int,
        at: datetime,
        action_key: str,
        failure_code: str,
    ) -> AggregateChange:
        self._require_version(expected_version)
        self._require_active_action(action_key)
        require_identifier(failure_code, field="failure_code")
        self._require_recovery_transition(RecoveryState.FAILED_SAFE)
        return self._workflow_change(
            RecoveryState.FAILED_SAFE,
            event_type="RecoveryActionFailedSafe",
            at=at,
            payload={"action_key": action_key, "failure_code": failure_code},
        )

    def record_active_expired(
        self,
        *,
        expected_version: int,
        at: datetime,
        budget_remains: bool,
    ) -> AggregateChange:
        self._require_version(expected_version)
        target = RecoveryState.ASSESSING if budget_remains else RecoveryState.EXHAUSTED
        self._require_recovery_transition(target)
        return self._workflow_change(
            target,
            event_type="RecoveryInstrumentExpired",
            at=at,
            payload={"budget_remains": budget_remains},
            active_action_key=None,
            active_proposal_id=None,
            active_instrument_reference=None,
        )

    def record_original_paid(
        self,
        *,
        expected_version: int,
        at: datetime,
        evidence: str,
    ) -> AggregateChange:
        self._require_version(expected_version)
        require_identifier(evidence, field="evidence")
        if self.state is RecoveryState.DORMANT:
            raise DomainError("a dormant case cannot process payment success")

        if (
            self.state is RecoveryState.DUPLICATE_REVIEW
            and self.payment_state is CanonicalPaymentState.OVERPAID
        ):
            return AggregateChange(self, ())

        if self.state is RecoveryState.RECOVERED:
            return self.record_duplicate_collection(
                expected_version=expected_version, at=at, evidence=evidence
            )

        payment_target = CanonicalPaymentState.PAID
        payment_changed = validate_payment_transition(self.payment_state, payment_target)
        workflow_changed = self.state in NONTERMINAL_RECOVERY_STATES
        if workflow_changed:
            self._require_recovery_transition(RecoveryState.SUPPRESSED_PAID)
        if not payment_changed and not workflow_changed:
            return AggregateChange(self, ())
        changes: dict[str, Any] = {"payment_state": payment_target}
        if workflow_changed:
            changes.update(
                {
                    "state": RecoveryState.SUPPRESSED_PAID,
                    "active_action_key": None,
                    "active_proposal_id": None,
                }
            )
        return self._change(
            event_type="OriginalPaymentSucceeded",
            at=at,
            payload={
                "evidence": evidence,
                "payment_from": self.payment_state.value,
                "payment_to": payment_target.value,
                "workflow_from": self.state.value,
                "workflow_to": (
                    RecoveryState.SUPPRESSED_PAID.value if workflow_changed else self.state.value
                ),
            },
            **changes,
        )

    def record_recovery_paid(
        self,
        *,
        expected_version: int,
        at: datetime,
        evidence: str,
    ) -> AggregateChange:
        self._require_version(expected_version)
        require_identifier(evidence, field="evidence")
        if (
            self.state is RecoveryState.RECOVERED
            and self.payment_state is CanonicalPaymentState.PAID
        ):
            return AggregateChange(self, ())
        if self.state is not RecoveryState.ACTIVE:
            raise InvalidTransition(
                machine="recovery",
                current=self.state.value,
                target=RecoveryState.RECOVERED.value,
            )
        if self.payment_state is CanonicalPaymentState.PAID:
            return self.record_duplicate_collection(
                expected_version=expected_version, at=at, evidence=evidence
            )
        validate_payment_transition(self.payment_state, CanonicalPaymentState.PAID)
        self._require_recovery_transition(RecoveryState.RECOVERED)
        return self._change(
            event_type="RecoveryPaymentSucceeded",
            at=at,
            payload={
                "evidence": evidence,
                "payment_from": self.payment_state.value,
                "payment_to": CanonicalPaymentState.PAID.value,
            },
            payment_state=CanonicalPaymentState.PAID,
            state=RecoveryState.RECOVERED,
        )

    def record_duplicate_collection(
        self,
        *,
        expected_version: int,
        at: datetime,
        evidence: str,
    ) -> AggregateChange:
        self._require_version(expected_version)
        require_identifier(evidence, field="evidence")
        payment_changed = validate_payment_transition(
            self.payment_state, CanonicalPaymentState.OVERPAID
        )
        workflow_changed = validate_recovery_transition(self.state, RecoveryState.DUPLICATE_REVIEW)
        if not payment_changed and not workflow_changed:
            return AggregateChange(self, ())
        return self._change(
            event_type="DuplicateCollectionDetected",
            at=at,
            payload={
                "evidence": evidence,
                "payment_from": self.payment_state.value,
                "workflow_from": self.state.value,
            },
            payment_state=CanonicalPaymentState.OVERPAID,
            state=RecoveryState.DUPLICATE_REVIEW,
            active_action_key=None,
            active_proposal_id=None,
        )

    def to_primitive(self) -> dict[str, Any]:
        return {
            "active_action_key": self.active_action_key,
            "active_instrument_reference": self.active_instrument_reference,
            "active_proposal_id": self.active_proposal_id,
            "amount_due": self.amount_due.to_primitive(),
            "case_id": self.case_id,
            "collection_closed": self.collection_closed,
            "decision_version": self.decision_version,
            "incident_state": self.incident_state.value,
            "last_transition_at": (
                None
                if self.last_transition_at is None
                else canonical_timestamp(self.last_transition_at)
            ),
            "logical_order_id": self.logical_order_id,
            "late_capture_policy": self.late_capture_policy.to_primitive(),
            "merchant_id": self.merchant_id,
            "observation_deadline": (
                None
                if self.observation_deadline is None
                else canonical_timestamp(self.observation_deadline)
            ),
            "observation_started_at": (
                None
                if self.observation_started_at is None
                else canonical_timestamp(self.observation_started_at)
            ),
            "payment_state": self.payment_state.value,
            "state": self.state.value,
            "version": self.version,
        }

    def _require_version(self, expected_version: int) -> None:
        if (
            isinstance(expected_version, bool)
            or not isinstance(expected_version, int)
            or expected_version < 0
        ):
            raise InvalidValue("expected_version must be a non-negative integer")
        if expected_version != self.version:
            raise VersionConflict(expected=expected_version, actual=self.version)

    def _require_recovery_transition(self, target: RecoveryState) -> None:
        validate_recovery_transition(self.state, target)

    def _require_proposal_binding(self, proposal: ActionProposal, *, next_decision: bool) -> None:
        if proposal.merchant_id != self.merchant_id or proposal.case_id != self.case_id:
            raise AuthorizationBindingError("proposal belongs to another aggregate")
        expected_decision = self.decision_version + 1 if next_decision else self.decision_version
        if proposal.decision_version != expected_decision:
            raise AuthorizationBindingError("proposal decision_version is stale or from the future")

    def _require_gate_binding(
        self,
        proposal: ActionProposal,
        decision: GateDecision,
        *,
        stage: GateStage,
        allowed: bool,
    ) -> None:
        if decision.stage is not stage:
            raise AuthorizationBindingError("gate stage does not match command")
        if decision.allowed is not allowed:
            raise AuthorizationBindingError("gate outcome does not match command")
        if (
            decision.proposal_id != proposal.proposal_id
            or decision.action_key != proposal.action_key
            or decision.proposal_digest != proposal.proposal_digest
            or decision.case_id != self.case_id
            or decision.decision_version != proposal.decision_version
            or decision.aggregate_version != self.version
        ):
            raise AuthorizationBindingError("gate evidence is bound to other state")

    def _require_active_action(self, action_key: str) -> None:
        if action_key != self.active_action_key:
            raise AuthorizationBindingError("action key is not active for this case")

    def _require_observation_elapsed(self, at: datetime) -> None:
        evaluated_at = require_utc(at, field="occurred_at")
        if self.observation_deadline is None:
            raise DomainError("observation deadline is missing")
        if evaluated_at < self.observation_deadline:
            raise DomainError("late-capture observation window has not elapsed")

    def _workflow_change(
        self,
        target: RecoveryState,
        *,
        event_type: str,
        at: datetime,
        payload: dict[str, Any],
        **changes: Any,
    ) -> AggregateChange:
        validate_recovery_transition(self.state, target)
        if target is RecoveryState.ASSESSING:
            self._require_observation_elapsed(at)
        return self._change(
            event_type=event_type,
            at=at,
            payload={
                **payload,
                "workflow_from": self.state.value,
                "workflow_to": target.value,
            },
            state=target,
            **changes,
        )

    def _change(
        self,
        *,
        event_type: str,
        at: datetime,
        payload: dict[str, Any],
        **changes: Any,
    ) -> AggregateChange:
        require_identifier(event_type, field="event_type")
        occurred_at = require_utc(at, field="occurred_at")
        if self.last_transition_at is not None and occurred_at < self.last_transition_at:
            raise InvalidValue("command time cannot precede the last transition")
        next_version = self.version + 1
        aggregate = replace(
            self,
            version=next_version,
            last_transition_at=occurred_at,
            **changes,
        )
        event = AggregateEvent(
            event_type=event_type,
            case_id=self.case_id,
            version=next_version,
            occurred_at=occurred_at,
            payload_json=canonical_json(payload),
        )
        return AggregateChange(aggregate=aggregate, events=(event,))
