"""Deterministic payment-method incident detector with TTL and hysteresis."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from decimal import Decimal

from ...packages.domain import IncidentState
from ...packages.domain.canonical import require_utc
from ...packages.domain.states import validate_incident_transition
from ...packages.domain.values import Probability, require_identifier, require_payment_method

DEFAULT_SUSPECT_DROP = Probability("0.15")
DEFAULT_CONFIRM_DROP = Probability("0.25")
DEFAULT_HEALTHY_DROP = Probability("0.05")


@dataclass(frozen=True, slots=True)
class IncidentDetectorConfig:
    version: str
    minimum_volume: int = 20
    suspect_drop: Probability = DEFAULT_SUSPECT_DROP
    confirm_drop: Probability = DEFAULT_CONFIRM_DROP
    healthy_drop: Probability = DEFAULT_HEALTHY_DROP
    ttl: timedelta = timedelta(minutes=10)
    cooling_period: timedelta = timedelta(minutes=3)

    def __post_init__(self) -> None:
        require_identifier(self.version, field="detector_version")
        if type(self.minimum_volume) is not int or self.minimum_volume <= 0:
            raise ValueError("minimum_volume must be a positive integer")
        for name in ("suspect_drop", "confirm_drop", "healthy_drop"):
            if not isinstance(getattr(self, name), Probability):
                raise ValueError(f"{name} must be a Probability")
        if self.confirm_drop.value < self.suspect_drop.value:
            raise ValueError("confirm_drop cannot be below suspect_drop")
        if self.healthy_drop.value > self.suspect_drop.value:
            raise ValueError("healthy_drop must be at or below suspect_drop")
        if self.ttl <= timedelta(0) or self.cooling_period <= timedelta(0):
            raise ValueError("ttl and cooling_period must be positive")


@dataclass(frozen=True, slots=True)
class MethodHealthWindow:
    scope_id: str
    merchant_id: str
    payment_method: str
    window_started_at: datetime
    observed_at: datetime
    successes: int
    failures: int
    baseline_success_rate: Probability
    provider_downtime_active: bool = False

    def __post_init__(self) -> None:
        require_identifier(self.scope_id, field="scope_id")
        require_identifier(self.merchant_id, field="merchant_id")
        require_payment_method(self.payment_method)
        started = require_utc(self.window_started_at, field="window_started_at")
        observed = require_utc(self.observed_at, field="observed_at")
        if observed < started:
            raise ValueError("observed_at cannot precede the window start")
        object.__setattr__(self, "window_started_at", started)
        object.__setattr__(self, "observed_at", observed)
        for name in ("successes", "failures"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if not isinstance(self.baseline_success_rate, Probability):
            raise ValueError("baseline_success_rate must be a Probability")
        if not isinstance(self.provider_downtime_active, bool):
            raise ValueError("provider_downtime_active must be boolean")

    @property
    def volume(self) -> int:
        return self.successes + self.failures

    @property
    def observed_success_rate(self) -> Probability:
        if self.volume == 0:
            return Probability(0)
        return Probability(Decimal(self.successes) / Decimal(self.volume))

    @property
    def degradation(self) -> Probability:
        drop = self.baseline_success_rate.value - self.observed_success_rate.value
        return Probability(max(drop, Decimal(0)))


@dataclass(frozen=True, slots=True)
class IncidentProjection:
    scope_id: str
    merchant_id: str
    payment_method: str
    state: IncidentState = IncidentState.NORMAL
    version: int = 0
    state_since: datetime | None = None
    last_evidence_at: datetime | None = None
    expires_at: datetime | None = None
    cooling_until: datetime | None = None

    def __post_init__(self) -> None:
        require_identifier(self.scope_id, field="scope_id")
        require_identifier(self.merchant_id, field="merchant_id")
        require_payment_method(self.payment_method)
        if not isinstance(self.state, IncidentState):
            raise ValueError("state must be an IncidentState")
        if type(self.version) is not int or self.version < 0:
            raise ValueError("version must be a non-negative integer")
        for name in ("state_since", "last_evidence_at", "expires_at", "cooling_until"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, require_utc(value, field=name))


@dataclass(frozen=True, slots=True)
class IncidentEvaluation:
    projection: IncidentProjection
    changed: bool
    reason_code: str
    observed_success_rate: Probability
    baseline_success_rate: Probability
    degradation: Probability
    provider_corroborated: bool
    minimum_volume_met: bool

    def to_primitive(self) -> dict[str, object]:
        return {
            "scope_id": self.projection.scope_id,
            "state": self.projection.state.value,
            "version": self.projection.version,
            "changed": self.changed,
            "reason_code": self.reason_code,
            "observed_success_rate": self.observed_success_rate.to_primitive(),
            "baseline_success_rate": self.baseline_success_rate.to_primitive(),
            "degradation": self.degradation.to_primitive(),
            "provider_corroborated": self.provider_corroborated,
            "minimum_volume_met": self.minimum_volume_met,
        }


class IncidentDetector:
    def __init__(self, config: IncidentDetectorConfig) -> None:
        self.config = config

    def evaluate(
        self,
        projection: IncidentProjection,
        window: MethodHealthWindow,
    ) -> IncidentEvaluation:
        if (
            projection.scope_id != window.scope_id
            or projection.merchant_id != window.merchant_id
            or projection.payment_method != window.payment_method
        ):
            raise ValueError("health window belongs to another incident scope")
        if (
            projection.last_evidence_at is not None
            and window.observed_at < projection.last_evidence_at
        ):
            raise ValueError("incident evidence cannot move backwards in time")

        rate = window.observed_success_rate
        drop = window.degradation
        enough_volume = window.volume >= self.config.minimum_volume
        suspected = enough_volume and drop.value >= self.config.suspect_drop.value
        strong = (
            enough_volume
            and window.volume >= self.config.minimum_volume * 2
            and drop.value >= self.config.confirm_drop.value
        )
        healthy = enough_volume and drop.value <= self.config.healthy_drop.value

        current = projection.state
        target = current
        reason = "NO_MATERIAL_CHANGE"
        cooling_until = projection.cooling_until

        if current is IncidentState.NORMAL:
            if window.provider_downtime_active or suspected:
                target = IncidentState.SUSPECTED
                reason = (
                    "PROVIDER_DOWNTIME_SUSPECTED"
                    if window.provider_downtime_active
                    else "STATISTICAL_DEGRADATION_SUSPECTED"
                )
        elif current is IncidentState.SUSPECTED:
            evidence_expired = (
                projection.expires_at is not None and window.observed_at >= projection.expires_at
            )
            if window.provider_downtime_active or strong:
                target = IncidentState.CONFIRMED
                reason = (
                    "PROVIDER_DOWNTIME_CONFIRMED"
                    if window.provider_downtime_active
                    else "STRONG_CORROBORATION_CONFIRMED"
                )
            elif healthy or evidence_expired:
                target = IncidentState.NORMAL
                reason = (
                    "SUSPECTED_EVIDENCE_EXPIRED"
                    if evidence_expired
                    else "SUSPECTED_EVIDENCE_DECAYED"
                )
        elif current is IncidentState.CONFIRMED:
            evidence_expired = (
                projection.expires_at is not None and window.observed_at >= projection.expires_at
            )
            if not window.provider_downtime_active and (healthy or evidence_expired):
                target = IncidentState.COOLING
                cooling_until = window.observed_at + self.config.cooling_period
                reason = "RECOVERY_SIGNAL_ENTERED_COOLING"
        elif current is IncidentState.COOLING:
            if window.provider_downtime_active or strong:
                target = IncidentState.CONFIRMED
                cooling_until = None
                reason = "DEGRADATION_RESUMED"
            elif (
                healthy
                and projection.cooling_until is not None
                and window.observed_at >= projection.cooling_until
            ):
                target = IncidentState.NORMAL
                cooling_until = None
                reason = "HYSTERESIS_WINDOW_PASSED"

        changed = validate_incident_transition(current, target)
        next_projection = projection
        if changed:
            next_projection = replace(
                projection,
                state=target,
                version=projection.version + 1,
                state_since=window.observed_at,
                last_evidence_at=window.observed_at,
                expires_at=(
                    window.observed_at + self.config.ttl
                    if target in {IncidentState.SUSPECTED, IncidentState.CONFIRMED}
                    else None
                ),
                cooling_until=cooling_until,
            )
        elif projection.last_evidence_at != window.observed_at:
            next_projection = replace(
                projection,
                last_evidence_at=window.observed_at,
                expires_at=(
                    window.observed_at + self.config.ttl
                    if current in {IncidentState.SUSPECTED, IncidentState.CONFIRMED}
                    and (suspected or strong or window.provider_downtime_active)
                    else projection.expires_at
                ),
            )

        return IncidentEvaluation(
            projection=next_projection,
            changed=changed,
            reason_code=reason,
            observed_success_rate=rate,
            baseline_success_rate=window.baseline_success_rate,
            degradation=drop,
            provider_corroborated=window.provider_downtime_active,
            minimum_volume_met=enough_volume,
        )
