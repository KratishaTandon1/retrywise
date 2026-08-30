"""Assessment-to-durable-intent boundary for one Razorpay Test recovery case.

The Razorpay payment read and detector-owned method-health read are injected
and happen after the initial PostgreSQL transaction has closed.  A second
transaction locks and revalidates the exact tenant/account/case/order/payment
projection before binding the previously computed redacted diagnosis and running
the deterministic policy gate. An allowed plan is committed as one immutable decision, action
intent, reserved Standard Payment Link instrument, and outbox command.  This
module never performs a provider effect.

The selected diagnosis engine is non-authoritative: it contributes a closed diagnosis and
confidence.  A fixed proposal policy chooses the only supported action, and the
deterministic gate is the sole planning authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, cast

from ...packages.diagnosis import (
    DiagnosisResult,
    DiagnosisRouter,
    FailureClass,
)
from ...packages.diagnosis.schema import FEATURE_SCHEMA_VERSION, normalize_features
from ...packages.domain import (
    APPROVAL_BLOCKING_REASONS,
    ActionProposal,
    ActionType,
    CanonicalPaymentState,
    DeterministicGate,
    GateContext,
    GateDecision,
    IncidentState,
    Money,
    ProviderSnapshot,
    RecoveryState,
)
from ...packages.domain.canonical import (
    canonical_json,
    canonical_json_bytes,
    canonical_timestamp,
)
from ...packages.domain.values import require_identifier, require_payment_method
from ...packages.razorpay import StandardPaymentLinkRequest, make_recovery_reference_id
from .effect_command_codec import (
    CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA_VERSION,
    CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE,
    encode_create_standard_payment_link_command,
)
from .executor import CreatePaymentLinkCommand, DurableActionIntent
from .postgres_audit import AuditActorType, TransactionalAuditAppender
from .postgres_connection import PostgresConnectionPolicy

_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_PROVIDER_ACCOUNT_IDENTIFIER_RE = re.compile(r"^acc_[A-Za-z0-9_-]{1,124}$")
_PROVIDER_RESOURCE_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{1,127}$")
_MACHINE_FACT_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_REASON_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_CROCKFORD_BASE32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_MAX_ULID_TIMESTAMP = (1 << 48) - 1
_MINIMUM_OBSERVATION = timedelta(minutes=2)
_MINIMUM_LINK_LEAD = timedelta(minutes=15)
_MAX_LINK_TTL = timedelta(days=180)
_LINK_ELIGIBLE_FAILURE_CLASSES = frozenset(
    {
        FailureClass.CUSTOMER_CORRECTABLE,
        FailureClass.CREDENTIAL_PERMANENT,
        FailureClass.FUNDS_TEMPORARY,
    }
)


class AssessmentSource(StrEnum):
    """The only provenance allowed to enqueue a provider-effect command."""

    RAZORPAY_TEST_MODE = "RAZORPAY_TEST_MODE"


class ProviderPaymentStatus(StrEnum):
    CREATED = "created"
    AUTHORIZED = "authorized"
    CAPTURED = "captured"
    REFUNDED = "refunded"
    FAILED = "failed"


class AssessmentDisposition(StrEnum):
    INTENT_QUEUED = "INTENT_QUEUED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    WAITING = "WAITING"
    BLOCKED = "BLOCKED"


class AssessmentReason(StrEnum):
    DIAGNOSIS_NOT_LINK_ELIGIBLE = "DIAGNOSIS_NOT_LINK_ELIGIBLE"
    PROVIDER_PAYMENT_NOT_FAILED = "PROVIDER_PAYMENT_NOT_FAILED"


class AssessmentError(RuntimeError):
    """A sanitized fail-closed assessment boundary error."""

    def __init__(self, reason_code: str) -> None:
        if not isinstance(reason_code, str) or not re.fullmatch(
            r"^[a-z][a-z0-9_]{0,127}$", reason_code
        ):
            raise ValueError("reason_code must be a stable lowercase machine code")
        self.reason_code = reason_code
        super().__init__(reason_code)


class AssessmentNotEligibleError(AssessmentError):
    """The durable projection cannot safely enter assessment."""


class AssessmentStateChangedError(AssessmentError):
    """The durable projection changed while provider truth was fetched."""


class AssessmentProviderTruthError(AssessmentError):
    """Fresh provider truth is unavailable, malformed, or misbound."""


class AssessmentMethodHealthError(AssessmentError):
    """Fresh detector-owned method health is unavailable or misbound."""


class AssessmentDiagnosisError(AssessmentError):
    """Diagnosis routing could not produce a safe local or external result."""


class AssessmentAuthorizationError(AssessmentError):
    """No effect intent was authorized; the caller must not settle work."""

    def __init__(self, reason_codes: tuple[str, ...]) -> None:
        if not reason_codes or any(
            not isinstance(reason, str) or not _REASON_CODE_RE.fullmatch(reason)
            for reason in reason_codes
        ):
            raise ValueError("authorization failure requires canonical reason codes")
        self.reason_codes = reason_codes
        super().__init__("assessment_not_authorized")


class AssessmentPersistenceError(AssessmentError):
    """A compare-and-swap or durable write did not complete exactly once."""


def _ulid(value: object, *, field_name: str) -> str:
    if type(value) is not str or not _ULID_RE.fullmatch(value):
        raise ValueError(f"{field_name} must be an uppercase Crockford ULID")
    return value


def _clean_text(value: object, *, field_name: str, maximum: int) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or not value.isascii()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{field_name} must be clean bounded ASCII text")
    return value


def _optional_resource_id(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    rendered = _clean_text(value, field_name=field_name, maximum=128)
    if not _PROVIDER_RESOURCE_ID_RE.fullmatch(rendered):
        raise ValueError(f"{field_name} must be an opaque provider resource id")
    return rendered


def _provider_resource_id(value: object, *, field_name: str) -> str:
    rendered = _optional_resource_id(value, field_name=field_name)
    if rendered is None:
        raise ValueError(f"{field_name} is required")
    return rendered


def _aware_utc(value: object, *, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def _nonnegative_integer(value: object, *, field_name: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value


def _positive_integer(value: object, *, field_name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{field_name} must be a positive integer")
    return value


def _optional_machine_fact(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or not _MACHINE_FACT_RE.fullmatch(value):
        raise ValueError(f"{field_name} must be a canonical machine fact")
    return value


def _database_enum(value: object, *, field_name: str) -> str:
    return _clean_text(value, field_name=field_name, maximum=64)


def _new_ulid() -> str:
    timestamp_ms = time.time_ns() // 1_000_000
    if not 0 <= timestamp_ms <= _MAX_ULID_TIMESTAMP:
        raise RuntimeError("system clock is outside the ULID timestamp range")
    value = (timestamp_ms << 80) | secrets.randbits(80)
    characters = ["0"] * 26
    for index in range(25, -1, -1):
        characters[index] = _CROCKFORD_BASE32[value & 31]
        value >>= 5
    return "".join(characters)


@dataclass(frozen=True, slots=True)
class AssessRecoveryCaseCommand:
    """Exact durable identity and optimistic version for one assessment."""

    merchant_id: str
    provider_account_id: str
    logical_order_id: str
    payment_record_id: str
    recovery_case_id: str
    expected_case_version: int
    source: AssessmentSource = AssessmentSource.RAZORPAY_TEST_MODE

    def __post_init__(self) -> None:
        for field_name in (
            "merchant_id",
            "provider_account_id",
            "logical_order_id",
            "payment_record_id",
            "recovery_case_id",
        ):
            _ulid(getattr(self, field_name), field_name=field_name)
        _nonnegative_integer(self.expected_case_version, field_name="expected_case_version")
        if self.source is not AssessmentSource.RAZORPAY_TEST_MODE:
            raise ValueError("assessment effects require RAZORPAY_TEST_MODE provenance")


@dataclass(frozen=True, slots=True)
class MerchantAssessmentState:
    status: str
    kill_switch_enabled: bool
    policy_version: str

    def __post_init__(self) -> None:
        if self.status != "ACTIVE":
            raise ValueError("merchant must be ACTIVE")
        if type(self.kill_switch_enabled) is not bool:
            raise ValueError("merchant kill switch must be boolean")
        require_identifier(self.policy_version, field="policy_version")


@dataclass(frozen=True, slots=True)
class ProviderAccountAssessmentState:
    provider: str
    provider_account_identifier: str
    environment: str
    enabled: bool
    credential_binding_version: int

    def __post_init__(self) -> None:
        if self.provider != "RAZORPAY":
            raise ValueError("provider account must be Razorpay")
        if not _PROVIDER_ACCOUNT_IDENTIFIER_RE.fullmatch(self.provider_account_identifier):
            raise ValueError("provider account identifier is malformed")
        if self.environment != "TEST":
            raise ValueError("provider account must be TEST")
        if type(self.enabled) is not bool or not self.enabled:
            raise ValueError("provider account must be enabled")
        _positive_integer(
            self.credential_binding_version,
            field_name="credential_binding_version",
        )


@dataclass(frozen=True, slots=True)
class RecoveryCaseAssessmentState:
    recovery_case_id: str
    merchant_id: str
    logical_order_id: str
    provider_account_id: str
    currency: str
    amount_due_minor: int
    state: str
    version: int
    observation_contract_version: int
    observation_started_at: datetime
    observation_deadline_at: datetime
    attempt_count: int
    contact_count: int
    incident_id: str | None

    def __post_init__(self) -> None:
        for field_name in (
            "recovery_case_id",
            "merchant_id",
            "logical_order_id",
            "provider_account_id",
        ):
            _ulid(getattr(self, field_name), field_name=field_name)
        Money(
            _positive_integer(self.amount_due_minor, field_name="amount_due_minor"), self.currency
        )
        if self.state not in {"OBSERVING", "WAITING"}:
            raise ValueError("recovery case must be OBSERVING or WAITING")
        _nonnegative_integer(self.version, field_name="case version")
        if self.observation_contract_version != 1:
            raise ValueError("recovery case lacks trusted observation evidence")
        started = _aware_utc(
            self.observation_started_at,
            field_name="observation_started_at",
        )
        deadline = _aware_utc(
            self.observation_deadline_at,
            field_name="observation_deadline_at",
        )
        if deadline - started < _MINIMUM_OBSERVATION:
            raise ValueError("observation deadline is below the safety floor")
        object.__setattr__(self, "observation_started_at", started)
        object.__setattr__(self, "observation_deadline_at", deadline)
        _nonnegative_integer(self.attempt_count, field_name="attempt_count")
        _nonnegative_integer(self.contact_count, field_name="contact_count")
        if self.incident_id is not None:
            _ulid(self.incident_id, field_name="incident_id")


@dataclass(frozen=True, slots=True)
class LogicalOrderAssessmentState:
    original_provider_order_id: str
    amount_due_minor: int
    currency: str
    captured_total_minor: int
    refunded_total_minor: int
    canonical_truth: str
    truth_version: int
    provider_snapshot_at: datetime
    mapping_status: str

    def __post_init__(self) -> None:
        _provider_resource_id(
            self.original_provider_order_id,
            field_name="original_provider_order_id",
        )
        amount = _positive_integer(self.amount_due_minor, field_name="order amount_due_minor")
        Money(amount, self.currency)
        captured = _nonnegative_integer(
            self.captured_total_minor,
            field_name="captured_total_minor",
        )
        refunded = _nonnegative_integer(
            self.refunded_total_minor,
            field_name="refunded_total_minor",
        )
        if captured != 0 or refunded != 0 or self.canonical_truth != "UNPAID":
            raise ValueError("logical order is not safely unpaid")
        _nonnegative_integer(self.truth_version, field_name="truth_version")
        object.__setattr__(
            self,
            "provider_snapshot_at",
            _aware_utc(self.provider_snapshot_at, field_name="order provider_snapshot_at"),
        )
        if self.mapping_status != "MAPPED":
            raise ValueError("logical order is not exactly mapped")


@dataclass(frozen=True, slots=True)
class ProviderPaymentAssessmentState:
    payment_record_id: str
    provider_payment_id: str
    provider_order_id: str
    status: str
    amount_minor: int
    currency: str
    captured_minor: int
    refunded_minor: int
    payment_method: str | None
    error_source: str | None
    error_step: str | None
    error_reason: str | None
    provider_created_at: datetime | None
    provider_snapshot_at: datetime

    def __post_init__(self) -> None:
        _ulid(self.payment_record_id, field_name="payment_record_id")
        _provider_resource_id(self.provider_payment_id, field_name="provider_payment_id")
        _provider_resource_id(self.provider_order_id, field_name="provider_order_id")
        if self.status != "FAILED":
            raise ValueError("persisted provider payment must be FAILED")
        Money(
            _positive_integer(self.amount_minor, field_name="payment amount_minor"), self.currency
        )
        if (
            _nonnegative_integer(self.captured_minor, field_name="payment captured_minor") != 0
            or _nonnegative_integer(self.refunded_minor, field_name="payment refunded_minor") != 0
        ):
            raise ValueError("failed provider payment cannot contain collected money")
        if self.payment_method is not None:
            require_payment_method(self.payment_method)
        for field_name in ("error_source", "error_step", "error_reason"):
            _optional_machine_fact(getattr(self, field_name), field_name=field_name)
        if self.provider_created_at is not None:
            object.__setattr__(
                self,
                "provider_created_at",
                _aware_utc(self.provider_created_at, field_name="provider_created_at"),
            )
        object.__setattr__(
            self,
            "provider_snapshot_at",
            _aware_utc(self.provider_snapshot_at, field_name="payment provider_snapshot_at"),
        )


@dataclass(frozen=True, slots=True)
class AssessmentSnapshot:
    """Redacted authoritative projection used on both sides of provider I/O."""

    database_now: datetime
    merchant: MerchantAssessmentState
    provider_account: ProviderAccountAssessmentState
    recovery_case: RecoveryCaseAssessmentState
    logical_order: LogicalOrderAssessmentState
    provider_payment: ProviderPaymentAssessmentState
    active_instrument_count: int

    def __post_init__(self) -> None:
        now = _aware_utc(self.database_now, field_name="database_now")
        object.__setattr__(self, "database_now", now)
        for field_name, expected_type in (
            ("merchant", MerchantAssessmentState),
            ("provider_account", ProviderAccountAssessmentState),
            ("recovery_case", RecoveryCaseAssessmentState),
            ("logical_order", LogicalOrderAssessmentState),
            ("provider_payment", ProviderPaymentAssessmentState),
        ):
            if type(getattr(self, field_name)) is not expected_type:
                raise TypeError(f"{field_name} has an invalid snapshot type")
        _nonnegative_integer(
            self.active_instrument_count,
            field_name="active_instrument_count",
        )
        case = self.recovery_case
        order = self.logical_order
        payment = self.provider_payment
        if now < case.observation_deadline_at:
            raise ValueError("observation deadline has not elapsed")
        if order.provider_snapshot_at > now + timedelta(seconds=5):
            raise ValueError("logical order snapshot is from the future")
        if payment.provider_snapshot_at > now + timedelta(seconds=5):
            raise ValueError("provider payment snapshot is from the future")
        if (
            case.currency != order.currency
            or case.currency != payment.currency
            or case.amount_due_minor != order.amount_due_minor
            or case.amount_due_minor != payment.amount_minor
            or order.original_provider_order_id != payment.provider_order_id
        ):
            raise ValueError("case, order, and payment money or mapping disagree")

    def assert_command_binding(self, command: AssessRecoveryCaseCommand) -> None:
        actual = (
            self.recovery_case.merchant_id,
            self.recovery_case.provider_account_id,
            self.recovery_case.logical_order_id,
            self.provider_payment.payment_record_id,
            self.recovery_case.recovery_case_id,
            self.recovery_case.version,
        )
        expected = (
            command.merchant_id,
            command.provider_account_id,
            command.logical_order_id,
            command.payment_record_id,
            command.recovery_case_id,
            command.expected_case_version,
        )
        if actual != expected:
            raise ValueError("assessment snapshot does not match its command")

    @property
    def state_digest(self) -> str:
        """Digest all durable authorization facts, excluding only database time."""

        material = {
            "active_instrument_count": self.active_instrument_count,
            "logical_order": {
                "amount_due_minor": self.logical_order.amount_due_minor,
                "canonical_truth": self.logical_order.canonical_truth,
                "captured_total_minor": self.logical_order.captured_total_minor,
                "currency": self.logical_order.currency,
                "mapping_status": self.logical_order.mapping_status,
                "original_provider_order_id": self.logical_order.original_provider_order_id,
                "provider_snapshot_at": self.logical_order.provider_snapshot_at,
                "refunded_total_minor": self.logical_order.refunded_total_minor,
                "truth_version": self.logical_order.truth_version,
            },
            "merchant": {
                "kill_switch_enabled": self.merchant.kill_switch_enabled,
                "policy_version": self.merchant.policy_version,
                "status": self.merchant.status,
            },
            "provider_account": {
                "credential_binding_version": (self.provider_account.credential_binding_version),
                "enabled": self.provider_account.enabled,
                "environment": self.provider_account.environment,
                "provider": self.provider_account.provider,
                "provider_account_identifier": (self.provider_account.provider_account_identifier),
            },
            "provider_payment": {
                "amount_minor": self.provider_payment.amount_minor,
                "captured_minor": self.provider_payment.captured_minor,
                "currency": self.provider_payment.currency,
                "error_reason": self.provider_payment.error_reason,
                "error_source": self.provider_payment.error_source,
                "error_step": self.provider_payment.error_step,
                "payment_method": self.provider_payment.payment_method,
                "payment_record_id": self.provider_payment.payment_record_id,
                "provider_created_at": self.provider_payment.provider_created_at,
                "provider_order_id": self.provider_payment.provider_order_id,
                "provider_payment_id": self.provider_payment.provider_payment_id,
                "provider_snapshot_at": self.provider_payment.provider_snapshot_at,
                "refunded_minor": self.provider_payment.refunded_minor,
                "status": self.provider_payment.status,
            },
            "recovery_case": {
                "amount_due_minor": self.recovery_case.amount_due_minor,
                "attempt_count": self.recovery_case.attempt_count,
                "contact_count": self.recovery_case.contact_count,
                "currency": self.recovery_case.currency,
                "incident_id": self.recovery_case.incident_id,
                "logical_order_id": self.recovery_case.logical_order_id,
                "merchant_id": self.recovery_case.merchant_id,
                "observation_contract_version": (self.recovery_case.observation_contract_version),
                "observation_deadline_at": (self.recovery_case.observation_deadline_at),
                "observation_started_at": self.recovery_case.observation_started_at,
                "provider_account_id": self.recovery_case.provider_account_id,
                "recovery_case_id": self.recovery_case.recovery_case_id,
                "state": self.recovery_case.state,
                "version": self.recovery_case.version,
            },
            "schema": "retrywise-assessment-snapshot-v1",
        }
        return hashlib.sha256(canonical_json_bytes(material)).hexdigest()

    @property
    def provider_query(self) -> ProviderTruthQuery:
        return ProviderTruthQuery(
            merchant_id=self.recovery_case.merchant_id,
            provider_account_id=self.recovery_case.provider_account_id,
            provider_account_identifier=(self.provider_account.provider_account_identifier),
            credential_binding_version=(self.provider_account.credential_binding_version),
            payment_record_id=self.provider_payment.payment_record_id,
            provider_payment_id=self.provider_payment.provider_payment_id,
            provider_order_id=self.provider_payment.provider_order_id,
        )

    def method_health_query(self, *, payment_method: str) -> MethodHealthQuery:
        return MethodHealthQuery(
            merchant_id=self.recovery_case.merchant_id,
            provider_account_id=self.recovery_case.provider_account_id,
            payment_method=payment_method,
            incident_id=self.recovery_case.incident_id,
        )


@dataclass(frozen=True, slots=True)
class ProviderTruthQuery:
    """Exact, non-secret routing request for a cache-bypassing provider read."""

    merchant_id: str
    provider_account_id: str
    provider_account_identifier: str
    credential_binding_version: int
    payment_record_id: str
    provider_payment_id: str
    provider_order_id: str

    def __post_init__(self) -> None:
        for field_name in ("merchant_id", "provider_account_id", "payment_record_id"):
            _ulid(getattr(self, field_name), field_name=field_name)
        if not _PROVIDER_ACCOUNT_IDENTIFIER_RE.fullmatch(self.provider_account_identifier):
            raise ValueError("provider_account_identifier is malformed")
        _positive_integer(
            self.credential_binding_version,
            field_name="credential_binding_version",
        )
        _provider_resource_id(self.provider_payment_id, field_name="provider_payment_id")
        _provider_resource_id(self.provider_order_id, field_name="provider_order_id")


@dataclass(frozen=True, slots=True)
class FreshProviderPaymentTruth:
    """Strict redacted projection returned by the injected fresh-read adapter.

    Account fields are routing metadata attested by RetryWise composition; they
    are not provider-issued proof that a key owns an account.
    """

    merchant_id: str
    provider_account_id: str
    credential_binding_version: int
    provider_payment_id: str
    provider_order_id: str
    status: ProviderPaymentStatus
    amount_minor: int
    currency: str
    captured_minor: int
    refunded_minor: int
    payment_method: str
    error_source: str | None
    error_step: str | None
    error_reason: str | None
    observed_at: datetime
    source: AssessmentSource = AssessmentSource.RAZORPAY_TEST_MODE

    def __post_init__(self) -> None:
        _ulid(self.merchant_id, field_name="merchant_id")
        _ulid(self.provider_account_id, field_name="provider_account_id")
        _positive_integer(
            self.credential_binding_version,
            field_name="credential_binding_version",
        )
        _provider_resource_id(self.provider_payment_id, field_name="provider_payment_id")
        _provider_resource_id(self.provider_order_id, field_name="provider_order_id")
        if not isinstance(self.status, ProviderPaymentStatus):
            raise TypeError("status must be ProviderPaymentStatus")
        amount = _positive_integer(self.amount_minor, field_name="amount_minor")
        Money(amount, self.currency)
        captured = _nonnegative_integer(self.captured_minor, field_name="captured_minor")
        refunded = _nonnegative_integer(self.refunded_minor, field_name="refunded_minor")
        if captured > amount or refunded > captured:
            raise ValueError("provider money is outside the payment amount")
        if self.status in {
            ProviderPaymentStatus.CREATED,
            ProviderPaymentStatus.AUTHORIZED,
            ProviderPaymentStatus.FAILED,
        } and (captured != 0 or refunded != 0):
            raise ValueError("non-captured provider status cannot contain collected money")
        if self.status is ProviderPaymentStatus.CAPTURED and captured == 0:
            raise ValueError("captured provider status requires collected money")
        if self.status is ProviderPaymentStatus.REFUNDED and (captured == 0 or refunded == 0):
            raise ValueError("refunded provider status requires capture and refund money")
        require_payment_method(self.payment_method)
        error_facts = tuple(
            _optional_machine_fact(getattr(self, field_name), field_name=field_name)
            for field_name in ("error_source", "error_step", "error_reason")
        )
        if self.status is ProviderPaymentStatus.FAILED and any(
            value is None for value in error_facts
        ):
            raise ValueError("failed provider truth requires closed failure facts")
        if self.status is not ProviderPaymentStatus.FAILED and any(
            value is not None for value in error_facts
        ):
            raise ValueError("non-failed provider truth cannot carry stale failure facts")
        object.__setattr__(
            self,
            "observed_at",
            _aware_utc(self.observed_at, field_name="observed_at"),
        )
        if self.source is not AssessmentSource.RAZORPAY_TEST_MODE:
            raise ValueError("fresh provider truth must carry Test provenance")

    @property
    def canonical_payment_state(self) -> CanonicalPaymentState:
        if self.status in {ProviderPaymentStatus.CREATED, ProviderPaymentStatus.FAILED}:
            return CanonicalPaymentState.UNPAID
        if self.status is ProviderPaymentStatus.AUTHORIZED:
            return CanonicalPaymentState.AUTHORIZED
        if self.captured_minor < self.amount_minor:
            return CanonicalPaymentState.PARTIALLY_PAID
        return CanonicalPaymentState.PAID


class FreshProviderTruthReader(Protocol):
    """Fetch exact provider truth synchronously, bypassing process caches."""

    def fetch_fresh_payment_truth(
        self,
        query: ProviderTruthQuery,
    ) -> FreshProviderPaymentTruth: ...


@dataclass(frozen=True, slots=True)
class MethodHealthQuery:
    """Exact detector scope needed after the provider reveals the method."""

    merchant_id: str
    provider_account_id: str
    payment_method: str
    incident_id: str | None

    def __post_init__(self) -> None:
        _ulid(self.merchant_id, field_name="merchant_id")
        _ulid(self.provider_account_id, field_name="provider_account_id")
        require_payment_method(self.payment_method)
        if self.incident_id is not None:
            _ulid(self.incident_id, field_name="incident_id")


@dataclass(frozen=True, slots=True)
class FreshMethodHealthTruth:
    """Fresh detector-owned state; never represented as a Razorpay fact."""

    merchant_id: str
    provider_account_id: str
    payment_method: str
    incident_state: IncidentState
    observed_at: datetime
    detector_version: str
    threshold_version: str
    incident_id: str | None = None

    def __post_init__(self) -> None:
        _ulid(self.merchant_id, field_name="merchant_id")
        _ulid(self.provider_account_id, field_name="provider_account_id")
        require_payment_method(self.payment_method)
        if not isinstance(self.incident_state, IncidentState):
            raise TypeError("incident_state must be IncidentState")
        object.__setattr__(
            self,
            "observed_at",
            _aware_utc(self.observed_at, field_name="method_health_observed_at"),
        )
        require_identifier(self.detector_version, field="detector_version")
        require_identifier(self.threshold_version, field="threshold_version")
        if self.incident_id is not None:
            _ulid(self.incident_id, field_name="incident_id")
        if self.incident_state is not IncidentState.NORMAL and self.incident_id is None:
            raise ValueError("non-normal method health requires a durable incident id")


class FreshMethodHealthReader(Protocol):
    """Read current detector-owned health without using a provider response."""

    def fetch_fresh_method_health(
        self,
        query: MethodHealthQuery,
    ) -> FreshMethodHealthTruth: ...


@dataclass(frozen=True, slots=True)
class BlockedAssessmentPlan:
    diagnosis: DiagnosisResult
    reason_codes: tuple[str, ...]
    proposal: ActionProposal | None = None
    planning_decision: GateDecision | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.diagnosis, DiagnosisResult):
            raise TypeError("diagnosis must be DiagnosisResult")
        if not self.reason_codes:
            raise ValueError("blocked plan requires reason codes")
        for reason_code in self.reason_codes:
            if not _REASON_CODE_RE.fullmatch(reason_code):
                raise ValueError("assessment reason code is not canonical")
        if self.proposal is not None and not isinstance(self.proposal, ActionProposal):
            raise TypeError("proposal must be ActionProposal when present")
        if self.planning_decision is not None:
            if not isinstance(self.planning_decision, GateDecision):
                raise TypeError("planning_decision must be GateDecision")
            if self.planning_decision.allowed:
                raise ValueError("blocked plan cannot carry an allowed gate decision")

    @property
    def disposition(self) -> AssessmentDisposition:
        if self.planning_decision is not None:
            reasons = frozenset(self.planning_decision.reasons)
            if reasons and reasons <= APPROVAL_BLOCKING_REASONS:
                return AssessmentDisposition.APPROVAL_REQUIRED
        return AssessmentDisposition.BLOCKED


@dataclass(frozen=True, slots=True)
class AuthorizedAssessmentPlan:
    """Complete immutable material to commit before any provider effect."""

    snapshot_digest: str
    diagnosis: DiagnosisResult
    proposal: ActionProposal
    planning_decision: GateDecision
    command: CreatePaymentLinkCommand
    durable_intent: DurableActionIntent
    decision_id: str
    action_id: str
    instrument_id: str
    outbox_job_id: str
    link_expires_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot_digest, str) or not re.fullmatch(
            r"^[0-9a-f]{64}$", self.snapshot_digest
        ):
            raise ValueError("snapshot_digest must be SHA-256")
        if not isinstance(self.diagnosis, DiagnosisResult):
            raise TypeError("diagnosis must be DiagnosisResult")
        if not isinstance(self.proposal, ActionProposal):
            raise TypeError("proposal must be ActionProposal")
        if not isinstance(self.planning_decision, GateDecision):
            raise TypeError("planning_decision must be GateDecision")
        if not self.planning_decision.allowed:
            raise ValueError("authorized plan requires an allowed gate decision")
        if not isinstance(self.command, CreatePaymentLinkCommand):
            raise TypeError("command must be CreatePaymentLinkCommand")
        if not isinstance(self.durable_intent, DurableActionIntent):
            raise TypeError("durable_intent must be DurableActionIntent")
        if self.command.proposal != self.proposal:
            raise ValueError("effect command is not bound to the authorized proposal")
        if self.command.prior_plan != self.planning_decision:
            raise ValueError("effect command is not bound to the planning decision")
        if not self.durable_intent.matches(self.command):
            raise ValueError("durable intent does not match the effect command")
        for field_name in (
            "decision_id",
            "action_id",
            "instrument_id",
            "outbox_job_id",
        ):
            _ulid(getattr(self, field_name), field_name=field_name)
        expires_at = _aware_utc(self.link_expires_at, field_name="link_expires_at")
        object.__setattr__(self, "link_expires_at", expires_at)
        if int(expires_at.timestamp()) != self.command.request.expire_by_epoch:
            raise ValueError("instrument and provider request expiry disagree")
        encode_create_standard_payment_link_command(self.command)


AssessmentPlanningOutcome = BlockedAssessmentPlan | AuthorizedAssessmentPlan


@dataclass(frozen=True, slots=True)
class AssessmentResult:
    """Proof that one authorized, waiting, approval, or terminal outcome committed."""

    disposition: AssessmentDisposition
    recovery_case_id: str
    initial_case_version: int
    diagnosis: DiagnosisResult
    reason_codes: tuple[str, ...] = ()
    final_case_version: int | None = None
    decision_id: str | None = None
    approval_id: str | None = None
    action_id: str | None = None
    instrument_id: str | None = None
    outbox_job_id: str | None = None
    action_key: str | None = None
    reference_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.disposition, AssessmentDisposition):
            raise TypeError("disposition must be AssessmentDisposition")
        _ulid(self.recovery_case_id, field_name="recovery_case_id")
        _nonnegative_integer(
            self.initial_case_version,
            field_name="initial_case_version",
        )
        if not isinstance(self.diagnosis, DiagnosisResult):
            raise TypeError("diagnosis must be DiagnosisResult")
        for reason_code in self.reason_codes:
            if not _REASON_CODE_RE.fullmatch(reason_code):
                raise ValueError("result reason code is not canonical")
        if self.final_case_version != self.initial_case_version + 2:
            raise ValueError("assessment outcomes must advance the case by two transitions")
        if self.decision_id is None:
            raise ValueError("assessment outcomes require an immutable decision")
        _ulid(self.decision_id, field_name="decision_id")
        if self.disposition is AssessmentDisposition.INTENT_QUEUED:
            identifiers = (self.action_id, self.instrument_id, self.outbox_job_id)
            if (
                self.reason_codes
                or self.approval_id is not None
                or any(value is None for value in identifiers)
            ):
                raise ValueError("queued result requires effect ids and no blocked metadata")
            if self.action_key is None or self.reference_id is None:
                raise ValueError("queued result requires action and provider references")
            for field_name, value in zip(
                ("action_id", "instrument_id", "outbox_job_id"),
                identifiers,
                strict=True,
            ):
                _ulid(value, field_name=field_name)
            return
        if not self.reason_codes:
            raise ValueError("non-effect assessment outcomes require reason codes")
        if any(
            value is not None
            for value in (
                self.action_id,
                self.instrument_id,
                self.outbox_job_id,
                self.action_key,
                self.reference_id,
            )
        ):
            raise ValueError("non-effect outcomes cannot claim effect intent")
        if self.disposition is AssessmentDisposition.APPROVAL_REQUIRED:
            if self.approval_id is None:
                raise ValueError("approval outcomes require approval_id")
            _ulid(self.approval_id, field_name="approval_id")
        elif self.approval_id is not None:
            raise ValueError("only approval outcomes carry approval_id")


def _truth_matches_snapshot(
    snapshot: AssessmentSnapshot,
    truth: FreshProviderPaymentTruth,
) -> bool:
    query = snapshot.provider_query
    return (
        hmac.compare_digest(truth.merchant_id, query.merchant_id)
        and hmac.compare_digest(
            truth.provider_account_id,
            query.provider_account_id,
        )
        and truth.credential_binding_version == query.credential_binding_version
        and hmac.compare_digest(
            truth.provider_payment_id,
            query.provider_payment_id,
        )
        and hmac.compare_digest(truth.provider_order_id, query.provider_order_id)
        and truth.amount_minor == snapshot.provider_payment.amount_minor
        and truth.currency == snapshot.provider_payment.currency
        and (
            snapshot.provider_payment.payment_method is None
            or truth.payment_method == snapshot.provider_payment.payment_method
        )
    )


def _method_health_matches_snapshot(
    snapshot: AssessmentSnapshot,
    truth: FreshProviderPaymentTruth,
    method_health: FreshMethodHealthTruth,
) -> bool:
    return (
        hmac.compare_digest(
            method_health.merchant_id,
            snapshot.recovery_case.merchant_id,
        )
        and hmac.compare_digest(
            method_health.provider_account_id,
            snapshot.recovery_case.provider_account_id,
        )
        and method_health.payment_method == truth.payment_method
        and method_health.incident_id == snapshot.recovery_case.incident_id
        and (
            snapshot.provider_payment.payment_method is None
            or method_health.payment_method == snapshot.provider_payment.payment_method
        )
    )


def _attempt_bucket(attempt_count: int) -> str:
    if attempt_count == 0:
        return "first"
    if attempt_count == 1:
        return "second"
    return "many"


def _failure_age_bucket(*, observed_at: datetime, failure_at: datetime) -> str:
    age = observed_at - failure_at
    if age <= timedelta(minutes=5):
        return "fresh"
    if age <= timedelta(hours=1):
        return "recent"
    return "stale"


def _diagnosis_error_step(value: str | None) -> str | None:
    """Map Razorpay's prefixed machine steps into the closed model vocabulary."""

    if value is None:
        return None
    aliases = {
        "payment_authentication": "authentication",
        "payment_authorization": "authorization",
        "payment_callback": "callback",
        "payment_capture": "capture",
        "payment_initiation": "initiation",
        "payment_processing": "processing",
    }
    return aliases.get(value, value)


def _diagnosis_features(
    snapshot: AssessmentSnapshot,
    truth: FreshProviderPaymentTruth,
    method_health: FreshMethodHealthTruth,
) -> dict[str, object]:
    return {
        "attempt_bucket": _attempt_bucket(snapshot.recovery_case.attempt_count),
        "error_reason": truth.error_reason,
        "error_source": truth.error_source,
        "error_step": _diagnosis_error_step(truth.error_step),
        "failure_age_bucket": _failure_age_bucket(
            observed_at=snapshot.database_now,
            failure_at=snapshot.provider_payment.provider_snapshot_at,
        ),
        "incident_state": method_health.incident_state.value,
        "payment_method": truth.payment_method,
    }


class StandardPaymentLinkAssessmentPlanner:
    """Routed diagnosis proposal selection followed by deterministic gating."""

    policy_name = "retrywise_standard_payment_link"

    def __init__(
        self,
        *,
        gate: DeterministicGate,
        proposal_ttl: timedelta = timedelta(minutes=5),
        link_ttl: timedelta = timedelta(hours=24),
        id_factory: Callable[[], str] = _new_ulid,
        global_kill_switch: bool = False,
        diagnosis_router: DiagnosisRouter | None = None,
    ) -> None:
        if not isinstance(gate, DeterministicGate):
            raise TypeError("gate must be DeterministicGate")
        if not isinstance(proposal_ttl, timedelta) or proposal_ttl <= timedelta(0):
            raise ValueError("proposal_ttl must be a positive timedelta")
        if (
            not isinstance(link_ttl, timedelta)
            or link_ttl < proposal_ttl + _MINIMUM_LINK_LEAD
            or link_ttl > _MAX_LINK_TTL
        ):
            raise ValueError(
                "link_ttl must preserve a 15-minute execution lead and stay within 180 days"
            )
        if not callable(id_factory):
            raise TypeError("id_factory must be callable")
        if type(global_kill_switch) is not bool:
            raise TypeError("global_kill_switch must be boolean")
        self.gate = gate
        self._proposal_ttl = proposal_ttl
        self._link_ttl = link_ttl
        self._id_factory = id_factory
        self._global_kill_switch = global_kill_switch
        if diagnosis_router is not None and not isinstance(diagnosis_router, DiagnosisRouter):
            raise TypeError("diagnosis_router must be DiagnosisRouter")
        self._diagnosis_router = diagnosis_router or DiagnosisRouter()

    def plan(
        self,
        snapshot: AssessmentSnapshot,
        truth: FreshProviderPaymentTruth,
        method_health: FreshMethodHealthTruth,
        *,
        diagnosis: DiagnosisResult | None = None,
    ) -> AssessmentPlanningOutcome:
        if not isinstance(snapshot, AssessmentSnapshot):
            raise TypeError("snapshot must be AssessmentSnapshot")
        if type(truth) is not FreshProviderPaymentTruth:
            raise AssessmentProviderTruthError("fresh_provider_truth_malformed")
        if type(method_health) is not FreshMethodHealthTruth:
            raise AssessmentMethodHealthError("fresh_method_health_malformed")
        if snapshot.merchant.policy_version != self.gate.policy.version:
            raise AssessmentNotEligibleError("merchant_policy_version_mismatch")
        if not _truth_matches_snapshot(snapshot, truth):
            raise AssessmentProviderTruthError("fresh_provider_truth_binding_mismatch")
        if not _method_health_matches_snapshot(snapshot, truth, method_health):
            raise AssessmentMethodHealthError("fresh_method_health_binding_mismatch")

        expected_features = normalize_features(_diagnosis_features(snapshot, truth, method_health))
        if diagnosis is None:
            diagnosis = self._diagnosis_router.infer(
                merchant_id=snapshot.recovery_case.merchant_id,
                raw_features=_diagnosis_features(snapshot, truth, method_health),
            )
        elif not isinstance(diagnosis, DiagnosisResult):
            raise TypeError("diagnosis must be DiagnosisResult")
        elif diagnosis.feature_snapshot != expected_features:
            raise AssessmentStateChangedError("diagnosis_feature_snapshot_changed")
        if truth.status is not ProviderPaymentStatus.FAILED:
            return BlockedAssessmentPlan(
                diagnosis=diagnosis,
                reason_codes=(AssessmentReason.PROVIDER_PAYMENT_NOT_FAILED.value,),
            )
        if diagnosis.predicted_class not in _LINK_ELIGIBLE_FAILURE_CLASSES:
            return BlockedAssessmentPlan(
                diagnosis=diagnosis,
                reason_codes=(AssessmentReason.DIAGNOSIS_NOT_LINK_ELIGIBLE.value,),
            )

        case = snapshot.recovery_case
        decision_version = case.version + 1
        evaluated_at = snapshot.database_now
        proposal = ActionProposal(
            proposal_id=f"proposal:{case.recovery_case_id}:{decision_version}",
            merchant_id=case.merchant_id,
            case_id=case.recovery_case_id,
            decision_version=decision_version,
            action_type=ActionType.CREATE_STANDARD_PAYMENT_LINK,
            created_at=evaluated_at,
            expires_at=evaluated_at + self._proposal_ttl,
            attempt_ordinal=case.attempt_count + 1,
            amount=Money(case.amount_due_minor, case.currency),
            payment_method=truth.payment_method,
            model_confidence=diagnosis.confidence,
            requires_approval=diagnosis.abstained,
        )
        gate_snapshot = ProviderSnapshot(
            payment_state=truth.canonical_payment_state,
            amount_due=Money(case.amount_due_minor, case.currency),
            payment_method=truth.payment_method,
            observed_at=truth.observed_at,
            active_instrument_count=snapshot.active_instrument_count,
            incident_state=method_health.incident_state,
            method_health_observed_at=method_health.observed_at,
        )
        context = GateContext(
            merchant_id=case.merchant_id,
            case_id=case.recovery_case_id,
            evaluated_at=evaluated_at,
            aggregate_version=decision_version,
            expected_aggregate_version=decision_version,
            recovery_state=RecoveryState.ASSESSING,
            snapshot=gate_snapshot,
            environment_effects_enabled=(
                snapshot.provider_account.provider == "RAZORPAY"
                and snapshot.provider_account.environment == "TEST"
                and snapshot.provider_account.enabled
            ),
            observation_deadline=case.observation_deadline_at,
            global_kill_switch=self._global_kill_switch,
            merchant_kill_switch=snapshot.merchant.kill_switch_enabled,
            contacts_in_window=case.contact_count,
            attempts_used=case.attempt_count,
            abstention_required=diagnosis.abstained,
        )
        decision = self.gate.evaluate_policy(proposal, context)
        if not decision.allowed:
            return BlockedAssessmentPlan(
                diagnosis=diagnosis,
                proposal=proposal,
                planning_decision=decision,
                reason_codes=tuple(reason.value for reason in decision.reasons),
            )

        reference_id = make_recovery_reference_id(
            case.recovery_case_id,
            provider_account_id=case.provider_account_id,
        )
        expire_by_epoch = int((evaluated_at + self._link_ttl).timestamp())
        link_expires_at = datetime.fromtimestamp(expire_by_epoch, UTC)
        request = StandardPaymentLinkRequest(
            amount_minor=case.amount_due_minor,
            currency=case.currency,
            reference_id=reference_id,
            description=f"Retry payment for order {case.logical_order_id}",
            expire_by_epoch=expire_by_epoch,
            notes={
                # The wire-schema key is provider-facing legacy terminology;
                # its value is a RetryWise ULID, never the merchant reference.
                "merchant_order_id": case.logical_order_id,
                "recovery_case_id": case.recovery_case_id,
            },
        )
        request.validate_expiry(now_epoch=int(evaluated_at.timestamp()))
        command = CreatePaymentLinkCommand(
            proposal=proposal,
            prior_plan=decision,
            request=request,
            provider_account_id=case.provider_account_id,
        )
        durable_intent = DurableActionIntent.record(
            command,
            recorded_at=evaluated_at,
        )
        generated_ids = tuple(self._id_factory() for _ in range(4))
        try:
            decision_id, action_id, instrument_id, outbox_job_id = (
                _ulid(value, field_name="id_factory result") for value in generated_ids
            )
        except ValueError as exc:
            raise RuntimeError("assessment id_factory returned an invalid ULID") from exc
        return AuthorizedAssessmentPlan(
            snapshot_digest=snapshot.state_digest,
            diagnosis=diagnosis,
            proposal=proposal,
            planning_decision=decision,
            command=command,
            durable_intent=durable_intent,
            decision_id=decision_id,
            action_id=action_id,
            instrument_id=instrument_id,
            outbox_job_id=outbox_job_id,
            link_expires_at=link_expires_at,
        )

    def diagnose(
        self,
        snapshot: AssessmentSnapshot,
        truth: FreshProviderPaymentTruth,
        method_health: FreshMethodHealthTruth,
    ) -> DiagnosisResult:
        """Run optional external inference before the locked commit transaction."""

        if not isinstance(snapshot, AssessmentSnapshot):
            raise TypeError("snapshot must be AssessmentSnapshot")
        if type(truth) is not FreshProviderPaymentTruth:
            raise AssessmentProviderTruthError("fresh_provider_truth_malformed")
        if type(method_health) is not FreshMethodHealthTruth:
            raise AssessmentMethodHealthError("fresh_method_health_malformed")
        if not _truth_matches_snapshot(snapshot, truth):
            raise AssessmentProviderTruthError("fresh_provider_truth_binding_mismatch")
        if not _method_health_matches_snapshot(snapshot, truth, method_health):
            raise AssessmentMethodHealthError("fresh_method_health_binding_mismatch")
        return self._diagnosis_router.infer(
            merchant_id=snapshot.recovery_case.merchant_id,
            raw_features=_diagnosis_features(snapshot, truth, method_health),
        )


_ASSESSMENT_COLUMNS = """
SELECT
    statement.now,
    recovery_case.id::text,
    recovery_case.merchant_id::text,
    recovery_case.logical_order_id::text,
    recovery_case.provider_account_id::text,
    recovery_case.currency::text,
    recovery_case.amount_due_snapshot_minor,
    recovery_case.state::text,
    recovery_case.version,
    recovery_case.observation_contract_version,
    recovery_case.observation_started_at,
    recovery_case.observation_deadline_at,
    recovery_case.attempt_count,
    recovery_case.contact_count,
    recovery_case.incident_id::text,
    merchant.status::text,
    merchant.kill_switch_enabled,
    merchant.default_policy_version,
    account.provider::text,
    account.provider_account_identifier,
    account.environment::text,
    account.enabled,
    account.credential_binding_version,
    logical_order.original_provider_order_id,
    logical_order.amount_due_minor,
    logical_order.currency::text,
    logical_order.captured_total_minor,
    logical_order.refunded_total_minor,
    logical_order.canonical_truth::text,
    logical_order.truth_version,
    logical_order.provider_snapshot_at,
    logical_order.mapping_status::text,
    payment.id::text,
    payment.provider_payment_id,
    payment.provider_order_id,
    payment.status::text,
    payment.amount_minor,
    payment.currency::text,
    payment.captured_minor,
    payment.refunded_minor,
    payment.payment_method,
    payment.error_facts ->> 'error_source',
    payment.error_facts ->> 'error_step',
    payment.error_facts ->> 'error_reason',
    payment.provider_created_at,
    payment.provider_snapshot_at,
    (
        SELECT count(*)
        FROM retrywise.recovery_instruments AS instrument
        WHERE instrument.merchant_id = recovery_case.merchant_id
          AND instrument.logical_order_id = recovery_case.logical_order_id
          AND instrument.currency = recovery_case.currency
          AND instrument.status IN (
              'CREATING', 'UNCERTAIN', 'ISSUED', 'ACTIVE', 'CANCEL_PENDING'
          )
    ) AS active_instrument_count
FROM retrywise.recovery_cases AS recovery_case
CROSS JOIN statement
JOIN retrywise.merchants AS merchant
  ON merchant.id = recovery_case.merchant_id
JOIN retrywise.provider_accounts AS account
  ON account.merchant_id = recovery_case.merchant_id
 AND account.id = recovery_case.provider_account_id
JOIN retrywise.logical_orders AS logical_order
  ON logical_order.merchant_id = recovery_case.merchant_id
 AND logical_order.id = recovery_case.logical_order_id
 AND logical_order.provider_account_id = recovery_case.provider_account_id
 AND logical_order.currency = recovery_case.currency
 AND logical_order.amount_due_minor = recovery_case.amount_due_snapshot_minor
JOIN retrywise.provider_payments AS payment
  ON payment.merchant_id = recovery_case.merchant_id
 AND payment.provider_account_id = recovery_case.provider_account_id
 AND payment.logical_order_id = recovery_case.logical_order_id
 AND payment.currency = recovery_case.currency
WHERE recovery_case.id = %(recovery_case_id)s
  AND recovery_case.merchant_id = %(merchant_id)s
  AND recovery_case.provider_account_id = %(provider_account_id)s
  AND recovery_case.logical_order_id = %(logical_order_id)s
  AND payment.id = %(payment_record_id)s
"""

_LOAD_ASSESSMENT = (
    "WITH statement AS MATERIALIZED (SELECT clock_timestamp() AS now)\n" + _ASSESSMENT_COLUMNS
)

_LOCK_ASSESSMENT = (
    "WITH statement AS MATERIALIZED (SELECT clock_timestamp() AS now)\n"
    + _ASSESSMENT_COLUMNS
    + """
FOR UPDATE OF recovery_case
FOR SHARE OF merchant, account, logical_order, payment
"""
)

_START_ASSESSMENT = """
UPDATE retrywise.recovery_cases
SET state = 'ASSESSING',
    version = version + 1
WHERE id = %(recovery_case_id)s
  AND merchant_id = %(merchant_id)s
  AND provider_account_id = %(provider_account_id)s
  AND logical_order_id = %(logical_order_id)s
  AND state IN ('OBSERVING', 'WAITING')
  AND version = %(expected_case_version)s
  AND observation_contract_version = 1
  AND (
      (state = 'OBSERVING' AND observation_deadline_at <= clock_timestamp())
      OR
      (state = 'WAITING' AND evaluation_deadline_at <= clock_timestamp())
  )
RETURNING version
"""

_INSERT_DECISION = """
INSERT INTO retrywise.decisions (
    id,
    merchant_id,
    recovery_case_id,
    logical_order_id,
    aggregate_version,
    feature_schema_version,
    feature_snapshot,
    feature_snapshot_sha256,
    model_name,
    model_version,
    class_probabilities,
    requested_diagnosis_mode,
    executed_diagnosis_engine,
    diagnosis_latency_ms,
    diagnosis_fallback_reason_code,
    shadow_diagnosis,
    abstained,
    out_of_distribution,
    policy_name,
    policy_version,
    candidates,
    selected_action,
    planning_gate_verdict,
    planning_gate_reason_codes,
    expected_value_inputs,
    expected_value_minor,
    source_label,
    created_at
) VALUES (
    %(decision_id)s,
    %(merchant_id)s,
    %(recovery_case_id)s,
    %(logical_order_id)s,
    %(decision_version)s,
    %(feature_schema_version)s,
    %(feature_snapshot)s::jsonb,
    %(feature_snapshot_sha256)s,
    %(model_name)s,
    %(model_version)s,
    %(class_probabilities)s::jsonb,
    %(requested_diagnosis_mode)s,
    %(executed_diagnosis_engine)s,
    %(diagnosis_latency_ms)s,
    %(diagnosis_fallback_reason_code)s,
    %(shadow_diagnosis)s::jsonb,
    %(abstained)s,
    %(out_of_distribution)s,
    %(policy_name)s,
    %(policy_version)s,
    %(candidates)s::jsonb,
    'CREATE_STANDARD_PAYMENT_LINK',
    'ALLOWED',
    '{}'::text[],
    %(expected_value_inputs)s::jsonb,
    NULL,
    %(source_label)s,
    %(evaluated_at)s
)
RETURNING id::text
"""

_INSERT_NON_EFFECT_DECISION = """
INSERT INTO retrywise.decisions (
    id,
    merchant_id,
    recovery_case_id,
    logical_order_id,
    aggregate_version,
    feature_schema_version,
    feature_snapshot,
    feature_snapshot_sha256,
    model_name,
    model_version,
    class_probabilities,
    requested_diagnosis_mode,
    executed_diagnosis_engine,
    diagnosis_latency_ms,
    diagnosis_fallback_reason_code,
    shadow_diagnosis,
    abstained,
    out_of_distribution,
    policy_name,
    policy_version,
    candidates,
    selected_action,
    planning_gate_verdict,
    planning_gate_reason_codes,
    expected_value_inputs,
    expected_value_minor,
    source_label,
    created_at
) VALUES (
    %(decision_id)s,
    %(merchant_id)s,
    %(recovery_case_id)s,
    %(logical_order_id)s,
    %(decision_version)s,
    %(feature_schema_version)s,
    %(feature_snapshot)s::jsonb,
    %(feature_snapshot_sha256)s,
    %(model_name)s,
    %(model_version)s,
    %(class_probabilities)s::jsonb,
    %(requested_diagnosis_mode)s,
    %(executed_diagnosis_engine)s,
    %(diagnosis_latency_ms)s,
    %(diagnosis_fallback_reason_code)s,
    %(shadow_diagnosis)s::jsonb,
    %(abstained)s,
    %(out_of_distribution)s,
    %(policy_name)s,
    %(policy_version)s,
    %(candidates)s::jsonb,
    %(selected_action)s::retrywise.action_type,
    %(planning_gate_verdict)s::retrywise.gate_verdict,
    %(planning_gate_reason_codes)s::text[],
    %(expected_value_inputs)s::jsonb,
    NULL,
    %(source_label)s,
    %(evaluated_at)s
)
RETURNING id::text
"""

_INSERT_APPROVAL = """
INSERT INTO retrywise.approvals (
    id,
    merchant_id,
    recovery_case_id,
    decision_id,
    aggregate_version,
    verdict,
    requested_at,
    expires_at
) VALUES (
    %(approval_id)s,
    %(merchant_id)s,
    %(recovery_case_id)s,
    %(decision_id)s,
    %(decision_version)s,
    'PENDING',
    %(evaluated_at)s,
    %(approval_expires_at)s
)
RETURNING id::text
"""

_FINISH_NON_EFFECT_CASE = """
UPDATE retrywise.recovery_cases
SET state = %(case_state)s::retrywise.recovery_case_state,
    version = version + 1,
    evaluation_deadline_at = %(evaluation_deadline_at)s,
    terminal_reason_code = %(terminal_reason_code)s,
    terminal_at = %(terminal_at)s,
    last_decision_id = %(decision_id)s,
    last_decision_at = %(evaluated_at)s
WHERE id = %(recovery_case_id)s
  AND merchant_id = %(merchant_id)s
  AND provider_account_id = %(provider_account_id)s
  AND logical_order_id = %(logical_order_id)s
  AND state = 'ASSESSING'
  AND version = %(decision_version)s
RETURNING version
"""

_INSERT_ACTION = """
INSERT INTO retrywise.actions (
    id,
    merchant_id,
    recovery_case_id,
    decision_id,
    aggregate_version,
    action_key,
    action_type,
    source_label,
    status,
    max_attempts,
    request_metadata,
    external_reference_id,
    scheduled_at,
    created_at,
    updated_at
) VALUES (
    %(action_id)s,
    %(merchant_id)s,
    %(recovery_case_id)s,
    %(decision_id)s,
    %(decision_version)s,
    %(action_key)s,
    'CREATE_STANDARD_PAYMENT_LINK',
    %(source_label)s,
    'PLANNED',
    %(action_max_attempts)s,
    %(request_metadata)s::jsonb,
    %(reference_id)s,
    %(evaluated_at)s,
    %(evaluated_at)s,
    %(evaluated_at)s
)
RETURNING id::text
"""

_INSERT_INSTRUMENT = """
INSERT INTO retrywise.recovery_instruments (
    id,
    merchant_id,
    recovery_case_id,
    logical_order_id,
    provider_account_id,
    action_id,
    reference_id,
    amount_minor,
    currency,
    status,
    accept_partial,
    expires_at,
    created_at,
    updated_at
) VALUES (
    %(instrument_id)s,
    %(merchant_id)s,
    %(recovery_case_id)s,
    %(logical_order_id)s,
    %(provider_account_id)s,
    %(action_id)s,
    %(reference_id)s,
    %(amount_minor)s,
    %(currency)s,
    'CREATING',
    FALSE,
    %(link_expires_at)s,
    %(evaluated_at)s,
    %(evaluated_at)s
)
RETURNING id::text
"""

_QUEUE_ACTION = """
UPDATE retrywise.actions
SET status = 'QUEUED'
WHERE id = %(action_id)s
  AND merchant_id = %(merchant_id)s
  AND recovery_case_id = %(recovery_case_id)s
  AND decision_id = %(decision_id)s
  AND aggregate_version = %(decision_version)s
  AND action_key = %(action_key)s
  AND source_label = %(source_label)s
  AND status = 'PLANNED'
RETURNING status::text
"""

_QUEUE_CASE = """
UPDATE retrywise.recovery_cases
SET state = 'ACTION_QUEUED',
    version = version + 1,
    attempt_count = attempt_count + 1,
    last_decision_id = %(decision_id)s,
    last_decision_at = %(evaluated_at)s,
    last_action_id = %(action_id)s,
    last_action_at = %(evaluated_at)s
WHERE id = %(recovery_case_id)s
  AND merchant_id = %(merchant_id)s
  AND provider_account_id = %(provider_account_id)s
  AND logical_order_id = %(logical_order_id)s
  AND state = 'ASSESSING'
  AND version = %(decision_version)s
RETURNING version
"""

_INSERT_OUTBOX = """
INSERT INTO retrywise.outbox_jobs (
    id,
    merchant_id,
    aggregate_type,
    aggregate_id,
    command_type,
    command_schema_version,
    command_payload,
    idempotency_key,
    status,
    max_attempts,
    next_attempt_at,
    created_at,
    updated_at
) VALUES (
    %(outbox_job_id)s,
    %(merchant_id)s,
    'ACTION',
    %(action_id)s,
    %(command_type)s,
    %(command_schema_version)s,
    %(command_payload)s::jsonb,
    %(outbox_idempotency_key)s,
    'PENDING',
    %(outbox_max_attempts)s,
    %(evaluated_at)s,
    %(evaluated_at)s,
    %(evaluated_at)s
)
RETURNING id::text
"""


class _Cursor(Protocol):
    def execute(self, query: str, params: Mapping[str, object]) -> object: ...

    def fetchone(self) -> Sequence[object] | None: ...

    def __enter__(self) -> _Cursor: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> bool | None: ...


class _Transaction(Protocol):
    def __enter__(self) -> object: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> bool | None: ...


class _Connection(Protocol):
    def cursor(self) -> _Cursor: ...

    def transaction(self) -> _Transaction: ...


class _ConnectionContext(Protocol):
    def __enter__(self) -> _Connection: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> bool | None: ...


ConnectionFactory = Callable[[], _ConnectionContext]


class AssessmentIntentRepository(Protocol):
    def load_candidate(self, command: AssessRecoveryCaseCommand) -> AssessmentSnapshot: ...

    def commit_plan(
        self,
        command: AssessRecoveryCaseCommand,
        *,
        initial_snapshot: AssessmentSnapshot,
        provider_truth: FreshProviderPaymentTruth,
        method_health: FreshMethodHealthTruth,
        planner: StandardPaymentLinkAssessmentPlanner,
        diagnosis: DiagnosisResult,
    ) -> AssessmentResult: ...


def _dsn_factory(dsn: str, *, require_tls: bool) -> ConnectionFactory:
    policy = PostgresConnectionPolicy(require_tls=require_tls)
    policy.validate_dsn(dsn)

    def connect() -> _ConnectionContext:
        return cast(
            _ConnectionContext,
            policy.connect(dsn, component="PostgresAssessmentIntentRepository"),
        )

    return connect


def _snapshot_from_row(
    row: Sequence[object] | None,
    *,
    command: AssessRecoveryCaseCommand,
) -> AssessmentSnapshot:
    if row is None:
        raise AssessmentNotEligibleError("assessment_candidate_not_found")
    if len(row) != 47:
        raise AssessmentNotEligibleError("assessment_candidate_row_unsafe")
    try:
        case = RecoveryCaseAssessmentState(
            recovery_case_id=_ulid(row[1], field_name="recovery_case_id"),
            merchant_id=_ulid(row[2], field_name="merchant_id"),
            logical_order_id=_ulid(row[3], field_name="logical_order_id"),
            provider_account_id=_ulid(row[4], field_name="provider_account_id"),
            currency=_database_enum(row[5], field_name="case currency"),
            amount_due_minor=_positive_integer(
                row[6],
                field_name="case amount_due_minor",
            ),
            state=_database_enum(row[7], field_name="case state"),
            version=_nonnegative_integer(row[8], field_name="case version"),
            observation_contract_version=_positive_integer(
                row[9],
                field_name="observation_contract_version",
            ),
            observation_started_at=_aware_utc(
                row[10],
                field_name="observation_started_at",
            ),
            observation_deadline_at=_aware_utc(
                row[11],
                field_name="observation_deadline_at",
            ),
            attempt_count=_nonnegative_integer(row[12], field_name="attempt_count"),
            contact_count=_nonnegative_integer(row[13], field_name="contact_count"),
            incident_id=(None if row[14] is None else _ulid(row[14], field_name="incident_id")),
        )
        merchant = MerchantAssessmentState(
            status=_database_enum(row[15], field_name="merchant status"),
            kill_switch_enabled=(row[16] if type(row[16]) is bool else _raise_value("kill switch")),
            policy_version=_clean_text(
                row[17],
                field_name="policy_version",
                maximum=100,
            ),
        )
        account = ProviderAccountAssessmentState(
            provider=_database_enum(row[18], field_name="provider"),
            provider_account_identifier=_clean_text(
                row[19],
                field_name="provider_account_identifier",
                maximum=128,
            ),
            environment=_database_enum(row[20], field_name="environment"),
            enabled=row[21] if type(row[21]) is bool else _raise_value("account enabled"),
            credential_binding_version=_positive_integer(
                row[22],
                field_name="credential_binding_version",
            ),
        )
        order = LogicalOrderAssessmentState(
            original_provider_order_id=_provider_resource_id(
                row[23],
                field_name="original_provider_order_id",
            ),
            amount_due_minor=_positive_integer(
                row[24],
                field_name="order amount_due_minor",
            ),
            currency=_database_enum(row[25], field_name="order currency"),
            captured_total_minor=_nonnegative_integer(
                row[26],
                field_name="captured_total_minor",
            ),
            refunded_total_minor=_nonnegative_integer(
                row[27],
                field_name="refunded_total_minor",
            ),
            canonical_truth=_database_enum(row[28], field_name="canonical_truth"),
            truth_version=_nonnegative_integer(row[29], field_name="truth_version"),
            provider_snapshot_at=_aware_utc(
                row[30],
                field_name="order provider_snapshot_at",
            ),
            mapping_status=_database_enum(row[31], field_name="mapping_status"),
        )
        payment = ProviderPaymentAssessmentState(
            payment_record_id=_ulid(row[32], field_name="payment_record_id"),
            provider_payment_id=_provider_resource_id(
                row[33],
                field_name="provider_payment_id",
            ),
            provider_order_id=_provider_resource_id(
                row[34],
                field_name="provider_order_id",
            ),
            status=_database_enum(row[35], field_name="payment status"),
            amount_minor=_positive_integer(row[36], field_name="payment amount_minor"),
            currency=_database_enum(row[37], field_name="payment currency"),
            captured_minor=_nonnegative_integer(
                row[38],
                field_name="payment captured_minor",
            ),
            refunded_minor=_nonnegative_integer(
                row[39],
                field_name="payment refunded_minor",
            ),
            payment_method=(
                None
                if row[40] is None
                else _clean_text(row[40], field_name="payment_method", maximum=32)
            ),
            error_source=_optional_machine_fact(row[41], field_name="error_source"),
            error_step=_optional_machine_fact(row[42], field_name="error_step"),
            error_reason=_optional_machine_fact(row[43], field_name="error_reason"),
            provider_created_at=(
                None if row[44] is None else _aware_utc(row[44], field_name="provider_created_at")
            ),
            provider_snapshot_at=_aware_utc(
                row[45],
                field_name="payment provider_snapshot_at",
            ),
        )
        snapshot = AssessmentSnapshot(
            database_now=_aware_utc(row[0], field_name="database_now"),
            merchant=merchant,
            provider_account=account,
            recovery_case=case,
            logical_order=order,
            provider_payment=payment,
            active_instrument_count=_nonnegative_integer(
                row[46],
                field_name="active_instrument_count",
            ),
        )
        snapshot.assert_command_binding(command)
    except (TypeError, ValueError):
        raise AssessmentNotEligibleError("assessment_candidate_row_unsafe") from None
    return snapshot


def _raise_value(field_name: str) -> bool:
    raise ValueError(f"{field_name} is malformed")


def _single_value(
    row: Sequence[object] | None,
    *,
    expected: object,
    operation: str,
) -> None:
    if row is None or len(row) != 1 or row[0] != expected:
        raise AssessmentPersistenceError(f"{operation}_compare_and_swap_failed")


def _json(value: object) -> str:
    try:
        encoded = canonical_json(value)
        decoded = json.loads(encoded)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AssessmentPersistenceError("assessment_evidence_not_json") from exc
    if not isinstance(decoded, (dict, list)):
        raise AssessmentPersistenceError("assessment_evidence_not_container")
    return encoded


def _class_probabilities(diagnosis: DiagnosisResult) -> dict[str, str]:
    return {
        item.failure_class.value: item.probability.to_primitive()
        for item in diagnosis.class_probabilities
    }


def _intent_metadata(intent: DurableActionIntent) -> dict[str, object]:
    return {
        "action_key": intent.action_key,
        "executor_payload_sha256": intent.payload_digest,
        "prior_plan_sha256": intent.prior_plan_digest,
        "proposal_sha256": intent.proposal_digest,
        "provider_account_id": intent.provider_account_id,
        "provider_request_sha256": intent.request_digest,
        "recorded_at": canonical_timestamp(intent.recorded_at),
        "reference_id": intent.reference_id,
        "schema": "retrywise-durable-action-intent",
        "schema_version": intent.schema_version,
    }


def _audit_policy_version_sha256(policy_version: str) -> str:
    """Represent arbitrary policy labels inside the audit fact allow-list."""

    return hashlib.sha256(policy_version.encode("utf-8")).hexdigest()


def _expected_value_inputs(
    diagnosis: DiagnosisResult,
    truth: FreshProviderPaymentTruth,
    method_health: FreshMethodHealthTruth,
) -> dict[str, object]:
    return {
        "artifact_version": diagnosis.artifact_version,
        "confidence": diagnosis.confidence.to_primitive(),
        "detector_version": method_health.detector_version,
        "estimated": False,
        "incident_state": method_health.incident_state.value,
        "method_health_observed_at": canonical_timestamp(method_health.observed_at),
        "predicted_class": diagnosis.predicted_class.value,
        "provider_truth_observed_at": canonical_timestamp(truth.observed_at),
        "diagnosis_provenance": diagnosis.provenance.to_primitive(),
        "schema": "retrywise-expected-value-inputs-v1",
        "threshold_version": method_health.threshold_version,
    }


def _diagnosis_persistence(diagnosis: DiagnosisResult) -> dict[str, object]:
    provenance = diagnosis.provenance
    return {
        "diagnosis_fallback_reason_code": provenance.fallback_reason_code,
        "diagnosis_latency_ms": provenance.latency_ms,
        "executed_diagnosis_engine": provenance.executed_engine.value,
        "model_name": provenance.model_name,
        "model_version": diagnosis.artifact_version,
        "requested_diagnosis_mode": provenance.requested_mode.value,
        "shadow_diagnosis": (
            None if provenance.shadow is None else _json(provenance.shadow.to_primitive())
        ),
    }


class PostgresAssessmentIntentRepository:
    """Short-read/fresh-provider-read/locked-CAS assessment persistence."""

    durable = True

    def __init__(
        self,
        *,
        dsn: str | None = None,
        connector: ConnectionFactory | None = None,
        require_tls: bool = False,
        action_max_attempts: int = 5,
        outbox_max_attempts: int = 8,
        audit_appender: TransactionalAuditAppender | None = None,
        id_factory: Callable[[], str] = _new_ulid,
        incident_wait: timedelta = timedelta(minutes=5),
        approval_ttl: timedelta = timedelta(minutes=5),
    ) -> None:
        if (dsn is None) == (connector is None):
            raise ValueError("provide exactly one of dsn or connector")
        if not isinstance(require_tls, bool):
            raise TypeError("require_tls must be boolean")
        if dsn is not None:
            self._connector = _dsn_factory(dsn, require_tls=require_tls)
        else:
            if require_tls:
                raise ValueError(
                    "require_tls needs the built-in DSN connector so its policy is verifiable"
                )
            if not callable(connector):
                raise TypeError("connector must be callable")
            self._connector = connector
        self._action_max_attempts = _positive_integer(
            action_max_attempts,
            field_name="action_max_attempts",
        )
        self._outbox_max_attempts = _positive_integer(
            outbox_max_attempts,
            field_name="outbox_max_attempts",
        )
        if audit_appender is not None and not callable(getattr(audit_appender, "append", None)):
            raise TypeError("audit_appender must provide append")
        if not callable(id_factory):
            raise TypeError("id_factory must be callable")
        if not isinstance(incident_wait, timedelta) or incident_wait <= timedelta(0):
            raise ValueError("incident_wait must be a positive timedelta")
        if not isinstance(approval_ttl, timedelta) or approval_ttl <= timedelta(0):
            raise ValueError("approval_ttl must be a positive timedelta")
        self._audit_appender = audit_appender
        self._id_factory = id_factory
        self._incident_wait = incident_wait
        self._approval_ttl = approval_ttl

    def __repr__(self) -> str:
        return "PostgresAssessmentIntentRepository(durable=True)"

    def load_candidate(self, command: AssessRecoveryCaseCommand) -> AssessmentSnapshot:
        if not isinstance(command, AssessRecoveryCaseCommand):
            raise TypeError("command must be AssessRecoveryCaseCommand")
        try:
            return self._load_candidate(command)
        except AssessmentError:
            raise
        except Exception:
            raise AssessmentPersistenceError("assessment_candidate_load_failed") from None

    def _load_candidate(self, command: AssessRecoveryCaseCommand) -> AssessmentSnapshot:
        params = _command_params(command)
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(_LOAD_ASSESSMENT, params)
            return _snapshot_from_row(cursor.fetchone(), command=command)

    def commit_plan(
        self,
        command: AssessRecoveryCaseCommand,
        *,
        initial_snapshot: AssessmentSnapshot,
        provider_truth: FreshProviderPaymentTruth,
        method_health: FreshMethodHealthTruth,
        planner: StandardPaymentLinkAssessmentPlanner,
        diagnosis: DiagnosisResult,
    ) -> AssessmentResult:
        if not isinstance(command, AssessRecoveryCaseCommand):
            raise TypeError("command must be AssessRecoveryCaseCommand")
        if not isinstance(initial_snapshot, AssessmentSnapshot):
            raise TypeError("initial_snapshot must be AssessmentSnapshot")
        if type(provider_truth) is not FreshProviderPaymentTruth:
            raise AssessmentProviderTruthError("fresh_provider_truth_malformed")
        if type(method_health) is not FreshMethodHealthTruth:
            raise AssessmentMethodHealthError("fresh_method_health_malformed")
        if type(planner) is not StandardPaymentLinkAssessmentPlanner:
            raise TypeError("planner must be StandardPaymentLinkAssessmentPlanner")
        if not isinstance(diagnosis, DiagnosisResult):
            raise TypeError("diagnosis must be DiagnosisResult")
        try:
            return self._commit_plan(
                command,
                initial_snapshot=initial_snapshot,
                provider_truth=provider_truth,
                method_health=method_health,
                planner=planner,
                diagnosis=diagnosis,
            )
        except AssessmentError:
            raise
        except Exception:
            raise AssessmentPersistenceError("assessment_commit_failed") from None

    def _commit_plan(
        self,
        command: AssessRecoveryCaseCommand,
        *,
        initial_snapshot: AssessmentSnapshot,
        provider_truth: FreshProviderPaymentTruth,
        method_health: FreshMethodHealthTruth,
        planner: StandardPaymentLinkAssessmentPlanner,
        diagnosis: DiagnosisResult,
    ) -> AssessmentResult:
        try:
            initial_snapshot.assert_command_binding(command)
        except ValueError:
            raise AssessmentStateChangedError("assessment_initial_snapshot_misbound") from None

        params = _command_params(command)
        with (
            self._connector() as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            cursor.execute(_LOCK_ASSESSMENT, params)
            locked = _snapshot_from_row(cursor.fetchone(), command=command)
            if not hmac.compare_digest(
                initial_snapshot.state_digest,
                locked.state_digest,
            ):
                raise AssessmentStateChangedError("assessment_state_changed_during_provider_read")
            if not _truth_matches_snapshot(locked, provider_truth):
                raise AssessmentProviderTruthError("fresh_provider_truth_binding_mismatch")
            if not _method_health_matches_snapshot(
                locked,
                provider_truth,
                method_health,
            ):
                raise AssessmentMethodHealthError("fresh_method_health_binding_mismatch")
            outcome = planner.plan(
                locked,
                provider_truth,
                method_health,
                diagnosis=diagnosis,
            )
            if isinstance(outcome, BlockedAssessmentPlan):
                return self._persist_blocked(
                    cursor,
                    command=command,
                    snapshot=locked,
                    provider_truth=provider_truth,
                    method_health=method_health,
                    plan=outcome,
                    policy_name=planner.policy_name,
                    policy_version=planner.gate.policy.version,
                )
            if type(outcome) is not AuthorizedAssessmentPlan:
                raise AssessmentPersistenceError("assessment_planner_result_unsafe")
            self._persist_authorized(
                cursor,
                command=command,
                snapshot=locked,
                provider_truth=provider_truth,
                method_health=method_health,
                plan=outcome,
            )
            self._append_audit(
                cursor,
                command=command,
                snapshot=locked,
                diagnosis=outcome.diagnosis,
                disposition=AssessmentDisposition.INTENT_QUEUED,
                decision_id=outcome.decision_id,
                reason_codes=(),
                action_id=outcome.action_id,
            )
            return AssessmentResult(
                disposition=AssessmentDisposition.INTENT_QUEUED,
                recovery_case_id=command.recovery_case_id,
                initial_case_version=command.expected_case_version,
                final_case_version=command.expected_case_version + 2,
                diagnosis=outcome.diagnosis,
                decision_id=outcome.decision_id,
                action_id=outcome.action_id,
                instrument_id=outcome.instrument_id,
                outbox_job_id=outcome.outbox_job_id,
                action_key=outcome.proposal.action_key,
                reference_id=outcome.command.request.reference_id,
            )

    def _persist_authorized(
        self,
        cursor: _Cursor,
        *,
        command: AssessRecoveryCaseCommand,
        snapshot: AssessmentSnapshot,
        provider_truth: FreshProviderPaymentTruth,
        method_health: FreshMethodHealthTruth,
        plan: AuthorizedAssessmentPlan,
    ) -> None:
        if not hmac.compare_digest(plan.snapshot_digest, snapshot.state_digest):
            raise AssessmentPersistenceError("authorized_plan_snapshot_mismatch")
        expected = command.expected_case_version + 1
        if (
            plan.proposal.merchant_id != command.merchant_id
            or plan.proposal.case_id != command.recovery_case_id
            or plan.proposal.decision_version != expected
            or plan.command.provider_account_id != command.provider_account_id
            or plan.planning_decision.aggregate_version != expected
        ):
            raise AssessmentPersistenceError("authorized_plan_binding_mismatch")

        feature_snapshot = plan.diagnosis.feature_snapshot.to_primitive()
        feature_snapshot_digest = hashlib.sha256(canonical_json_bytes(feature_snapshot)).digest()
        command_payload = encode_create_standard_payment_link_command(plan.command)
        common: dict[str, object] = {
            **_command_params(command),
            "action_id": plan.action_id,
            "action_key": plan.proposal.action_key,
            "action_max_attempts": self._action_max_attempts,
            "amount_minor": snapshot.recovery_case.amount_due_minor,
            "currency": snapshot.recovery_case.currency,
            "decision_id": plan.decision_id,
            "decision_version": expected,
            "evaluated_at": snapshot.database_now,
            "instrument_id": plan.instrument_id,
            "link_expires_at": plan.link_expires_at,
            "outbox_job_id": plan.outbox_job_id,
            "outbox_max_attempts": self._outbox_max_attempts,
            "reference_id": plan.command.request.reference_id,
            "source_label": command.source.value,
        }

        cursor.execute(_START_ASSESSMENT, common)
        _single_value(
            cursor.fetchone(),
            expected=expected,
            operation="start_assessment",
        )

        decision_params = {
            **common,
            "abstained": plan.diagnosis.abstained,
            "candidates": _json([plan.proposal.to_primitive()]),
            "class_probabilities": _json(_class_probabilities(plan.diagnosis)),
            "expected_value_inputs": _json(
                _expected_value_inputs(
                    plan.diagnosis,
                    provider_truth,
                    method_health,
                )
            ),
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "feature_snapshot": _json(feature_snapshot),
            "feature_snapshot_sha256": feature_snapshot_digest,
            **_diagnosis_persistence(plan.diagnosis),
            "out_of_distribution": plan.diagnosis.out_of_distribution,
            "policy_name": StandardPaymentLinkAssessmentPlanner.policy_name,
            "policy_version": plan.planning_decision.policy_version,
        }
        cursor.execute(_INSERT_DECISION, decision_params)
        _single_value(
            cursor.fetchone(),
            expected=plan.decision_id,
            operation="insert_decision",
        )

        action_params = {
            **common,
            "request_metadata": _json(_intent_metadata(plan.durable_intent)),
        }
        cursor.execute(_INSERT_ACTION, action_params)
        _single_value(
            cursor.fetchone(),
            expected=plan.action_id,
            operation="insert_action",
        )

        cursor.execute(_INSERT_INSTRUMENT, common)
        _single_value(
            cursor.fetchone(),
            expected=plan.instrument_id,
            operation="insert_instrument",
        )

        cursor.execute(_QUEUE_ACTION, common)
        _single_value(
            cursor.fetchone(),
            expected="QUEUED",
            operation="queue_action",
        )

        cursor.execute(_QUEUE_CASE, common)
        _single_value(
            cursor.fetchone(),
            expected=command.expected_case_version + 2,
            operation="queue_case",
        )

        outbox_params = {
            **common,
            "command_payload": _json(command_payload),
            "command_schema_version": (CREATE_STANDARD_PAYMENT_LINK_COMMAND_SCHEMA_VERSION),
            "command_type": CREATE_STANDARD_PAYMENT_LINK_COMMAND_TYPE,
            "outbox_idempotency_key": (f"create-standard-payment-link:{plan.proposal.action_key}"),
        }
        cursor.execute(_INSERT_OUTBOX, outbox_params)
        _single_value(
            cursor.fetchone(),
            expected=plan.outbox_job_id,
            operation="insert_outbox",
        )

    def _persist_blocked(
        self,
        cursor: _Cursor,
        *,
        command: AssessRecoveryCaseCommand,
        snapshot: AssessmentSnapshot,
        provider_truth: FreshProviderPaymentTruth,
        method_health: FreshMethodHealthTruth,
        plan: BlockedAssessmentPlan,
        policy_name: str,
        policy_version: str,
    ) -> AssessmentResult:
        decision_id = self._next_id("decision_id")
        approval_id: str | None = None
        disposition = plan.disposition
        wait_reasons = {
            "PAYMENT_METHOD_UNHEALTHY",
            "COOLDOWN_ACTIVE",
        }
        if disposition is not AssessmentDisposition.APPROVAL_REQUIRED and wait_reasons.intersection(
            plan.reason_codes
        ):
            disposition = AssessmentDisposition.WAITING

        evaluated_at = snapshot.database_now
        decision_version = command.expected_case_version + 1
        feature_snapshot = plan.diagnosis.feature_snapshot.to_primitive()
        feature_snapshot_digest = hashlib.sha256(canonical_json_bytes(feature_snapshot)).digest()
        candidate_values = [] if plan.proposal is None else [plan.proposal.to_primitive()]
        common: dict[str, object] = {
            **_command_params(command),
            "decision_id": decision_id,
            "decision_version": decision_version,
            "evaluated_at": evaluated_at,
            "source_label": command.source.value,
        }
        cursor.execute(_START_ASSESSMENT, common)
        _single_value(
            cursor.fetchone(),
            expected=decision_version,
            operation="start_blocked_assessment",
        )
        cursor.execute(
            _INSERT_NON_EFFECT_DECISION,
            {
                **common,
                "abstained": plan.diagnosis.abstained,
                "candidates": _json(candidate_values),
                "class_probabilities": _json(_class_probabilities(plan.diagnosis)),
                "expected_value_inputs": _json(
                    _expected_value_inputs(plan.diagnosis, provider_truth, method_health)
                ),
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "feature_snapshot": _json(feature_snapshot),
                "feature_snapshot_sha256": feature_snapshot_digest,
                **_diagnosis_persistence(plan.diagnosis),
                "out_of_distribution": plan.diagnosis.out_of_distribution,
                "planning_gate_reason_codes": list(plan.reason_codes),
                "planning_gate_verdict": (
                    "APPROVAL_REQUIRED"
                    if disposition is AssessmentDisposition.APPROVAL_REQUIRED
                    else "BLOCKED"
                ),
                "policy_name": policy_name,
                "policy_version": policy_version,
                "selected_action": (
                    "CREATE_STANDARD_PAYMENT_LINK"
                    if disposition is AssessmentDisposition.APPROVAL_REQUIRED
                    else None
                ),
            },
        )
        _single_value(
            cursor.fetchone(),
            expected=decision_id,
            operation="insert_non_effect_decision",
        )

        if disposition is AssessmentDisposition.APPROVAL_REQUIRED:
            if plan.proposal is None:
                raise AssessmentPersistenceError("approval_proposal_missing")
            approval_id = self._next_id("approval_id")
            approval_expires_at = min(
                plan.proposal.expires_at,
                evaluated_at + self._approval_ttl,
            )
            if approval_expires_at <= evaluated_at:
                raise AssessmentPersistenceError("approval_window_expired")
            cursor.execute(
                _INSERT_APPROVAL,
                {
                    **common,
                    "approval_id": approval_id,
                    "approval_expires_at": approval_expires_at,
                },
            )
            _single_value(
                cursor.fetchone(),
                expected=approval_id,
                operation="insert_approval",
            )

        paid_truth = provider_truth.status in {
            ProviderPaymentStatus.CAPTURED,
            ProviderPaymentStatus.REFUNDED,
        }
        if disposition is AssessmentDisposition.APPROVAL_REQUIRED:
            case_state = "APPROVAL_REQUIRED"
            evaluation_deadline_at = None
            terminal_reason_code = None
            terminal_at = None
        elif disposition is AssessmentDisposition.WAITING:
            case_state = "WAITING"
            evaluation_deadline_at = evaluated_at + self._incident_wait
            terminal_reason_code = None
            terminal_at = None
        else:
            case_state = "SUPPRESSED_PAID" if paid_truth else "SUPPRESSED_POLICY"
            evaluation_deadline_at = None
            terminal_reason_code = plan.reason_codes[0]
            terminal_at = evaluated_at
        cursor.execute(
            _FINISH_NON_EFFECT_CASE,
            {
                **common,
                "case_state": case_state,
                "evaluation_deadline_at": evaluation_deadline_at,
                "terminal_reason_code": terminal_reason_code,
                "terminal_at": terminal_at,
            },
        )
        final_version = command.expected_case_version + 2
        _single_value(
            cursor.fetchone(),
            expected=final_version,
            operation="finish_non_effect_case",
        )
        self._append_audit(
            cursor,
            command=command,
            snapshot=snapshot,
            diagnosis=plan.diagnosis,
            disposition=disposition,
            decision_id=decision_id,
            reason_codes=plan.reason_codes,
            action_id=None,
        )
        return AssessmentResult(
            disposition=disposition,
            recovery_case_id=command.recovery_case_id,
            initial_case_version=command.expected_case_version,
            final_case_version=final_version,
            diagnosis=plan.diagnosis,
            reason_codes=plan.reason_codes,
            decision_id=decision_id,
            approval_id=approval_id,
        )

    def _append_audit(
        self,
        cursor: _Cursor,
        *,
        command: AssessRecoveryCaseCommand,
        snapshot: AssessmentSnapshot,
        diagnosis: DiagnosisResult,
        disposition: AssessmentDisposition,
        decision_id: str,
        reason_codes: tuple[str, ...],
        action_id: str | None,
    ) -> None:
        if self._audit_appender is None:
            return
        facts: dict[str, object] = {
            "assessment_disposition": disposition.value,
            "decision_id": decision_id,
            "model_version_sha256": hashlib.sha256(
                diagnosis.artifact_version.encode("utf-8")
            ).hexdigest(),
            "diagnosis_engine": diagnosis.provenance.executed_engine.value,
            "diagnosis_mode": diagnosis.provenance.requested_mode.value,
            "diagnosis_fallback_reason": diagnosis.provenance.fallback_reason_code,
            "policy_version_sha256": _audit_policy_version_sha256(snapshot.merchant.policy_version),
            "reason_codes": list(reason_codes),
        }
        if action_id is not None:
            facts["action_id"] = action_id
        self._audit_appender.append(
            cursor=cursor,
            audit_entry_id=self._next_id("audit_entry_id"),
            merchant_id=command.merchant_id,
            recovery_case_id=command.recovery_case_id,
            entry_type="ASSESSMENT_COMMITTED",
            actor_type=AuditActorType.WORKER,
            actor_subject=("worker:" + hashlib.sha256(b"retrywise-assessment-worker").hexdigest()),
            facts=facts,
            created_at=snapshot.database_now,
        )

    def _next_id(self, field_name: str) -> str:
        try:
            return _ulid(self._id_factory(), field_name=field_name)
        except ValueError as exc:
            raise AssessmentPersistenceError("assessment_id_factory_failed") from exc


def _command_params(command: AssessRecoveryCaseCommand) -> dict[str, object]:
    return {
        "expected_case_version": command.expected_case_version,
        "logical_order_id": command.logical_order_id,
        "merchant_id": command.merchant_id,
        "payment_record_id": command.payment_record_id,
        "provider_account_id": command.provider_account_id,
        "recovery_case_id": command.recovery_case_id,
    }


class AssessmentToIntentService:
    """Orchestrate fresh external reads without holding a DB transaction."""

    def __init__(
        self,
        *,
        repository: AssessmentIntentRepository,
        provider_truth_reader: FreshProviderTruthReader,
        method_health_reader: FreshMethodHealthReader,
        planner: StandardPaymentLinkAssessmentPlanner,
    ) -> None:
        if not isinstance(planner, StandardPaymentLinkAssessmentPlanner):
            raise TypeError("planner must be StandardPaymentLinkAssessmentPlanner")
        self._repository = repository
        self._provider_truth_reader = provider_truth_reader
        self._method_health_reader = method_health_reader
        self._planner = planner

    def assess(self, command: AssessRecoveryCaseCommand) -> AssessmentResult:
        if not isinstance(command, AssessRecoveryCaseCommand):
            raise TypeError("command must be AssessRecoveryCaseCommand")
        try:
            snapshot = self._repository.load_candidate(command)
        except AssessmentError:
            raise
        except Exception:
            raise AssessmentPersistenceError("assessment_candidate_load_failed") from None
        try:
            provider_truth = self._provider_truth_reader.fetch_fresh_payment_truth(
                snapshot.provider_query
            )
        except AssessmentError:
            raise
        except Exception:
            raise AssessmentProviderTruthError("fresh_provider_truth_unavailable") from None
        if type(provider_truth) is not FreshProviderPaymentTruth:
            raise AssessmentProviderTruthError("fresh_provider_truth_malformed")
        if not _truth_matches_snapshot(snapshot, provider_truth):
            raise AssessmentProviderTruthError("fresh_provider_truth_binding_mismatch")
        try:
            method_health = self._method_health_reader.fetch_fresh_method_health(
                snapshot.method_health_query(
                    payment_method=provider_truth.payment_method,
                )
            )
        except AssessmentError:
            raise
        except Exception:
            raise AssessmentMethodHealthError("fresh_method_health_unavailable") from None
        if type(method_health) is not FreshMethodHealthTruth:
            raise AssessmentMethodHealthError("fresh_method_health_malformed")
        if not _method_health_matches_snapshot(snapshot, provider_truth, method_health):
            raise AssessmentMethodHealthError("fresh_method_health_binding_mismatch")
        try:
            diagnosis = self._planner.diagnose(snapshot, provider_truth, method_health)
        except AssessmentError:
            raise
        except Exception:
            raise AssessmentDiagnosisError("diagnosis_unavailable") from None
        try:
            return self._repository.commit_plan(
                command,
                initial_snapshot=snapshot,
                provider_truth=provider_truth,
                method_health=method_health,
                planner=self._planner,
                diagnosis=diagnosis,
            )
        except AssessmentError:
            raise
        except Exception:
            raise AssessmentPersistenceError("assessment_commit_failed") from None


__all__ = [
    "AssessRecoveryCaseCommand",
    "AssessmentAuthorizationError",
    "AssessmentDiagnosisError",
    "AssessmentDisposition",
    "AssessmentError",
    "AssessmentIntentRepository",
    "AssessmentMethodHealthError",
    "AssessmentNotEligibleError",
    "AssessmentPersistenceError",
    "AssessmentProviderTruthError",
    "AssessmentReason",
    "AssessmentResult",
    "AssessmentSnapshot",
    "AssessmentSource",
    "AssessmentStateChangedError",
    "AssessmentToIntentService",
    "AuthorizedAssessmentPlan",
    "BlockedAssessmentPlan",
    "FreshMethodHealthReader",
    "FreshMethodHealthTruth",
    "FreshProviderPaymentTruth",
    "FreshProviderTruthReader",
    "MethodHealthQuery",
    "PostgresAssessmentIntentRepository",
    "ProviderPaymentStatus",
    "ProviderTruthQuery",
    "StandardPaymentLinkAssessmentPlanner",
]
