"""Financial and scalar value objects for the RetryWise domain."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any

from .canonical import require_utc
from .errors import InvalidValue

_CURRENCY_PATTERN = re.compile(r"^[A-Z]{3}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_METHOD_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


MINIMUM_LATE_CAPTURE_WINDOW = timedelta(minutes=2)


def require_identifier(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER_PATTERN.fullmatch(value):
        raise InvalidValue(f"{field} must be 1-128 safe identifier characters")
    return value


def require_payment_method(value: str, *, field: str = "payment_method") -> str:
    if not isinstance(value, str) or not _METHOD_PATTERN.fullmatch(value):
        raise InvalidValue(f"{field} must be a canonical lowercase payment-method identifier")
    return value


@dataclass(frozen=True, slots=True)
class LateCapturePolicy:
    """Policy-owned minimum before a replacement collection path may open.

    A diagnosis or caller may request a later deadline through
    :meth:`observation_deadline`, but can never reduce this policy-owned floor.
    The hard lower bound protects deployments from accidentally restoring the
    short observation window that allowed rare duplicate-collection paths.
    """

    minimum_observation_window: timedelta = MINIMUM_LATE_CAPTURE_WINDOW

    def __post_init__(self) -> None:
        window = self.minimum_observation_window
        if not isinstance(window, timedelta):
            raise InvalidValue("minimum_observation_window must be a timedelta")
        if window < MINIMUM_LATE_CAPTURE_WINDOW:
            raise InvalidValue("minimum_observation_window is below the safety floor")

    def observation_deadline(
        self,
        *,
        observed_at: datetime,
        extend_until: datetime | None = None,
    ) -> datetime:
        """Return the policy floor, extended by a later caller suggestion only."""

        observed = require_utc(observed_at, field="observed_at")
        policy_deadline = observed + self.minimum_observation_window
        if extend_until is None:
            return policy_deadline
        requested = require_utc(extend_until, field="extend_observation_until")
        return max(policy_deadline, requested)

    def to_primitive(self) -> dict[str, int]:
        window = self.minimum_observation_window
        microseconds = ((window.days * 86_400) + window.seconds) * 1_000_000 + window.microseconds
        return {"minimum_observation_microseconds": microseconds}


@dataclass(frozen=True, slots=True)
class Money:
    """A non-negative amount in an ISO currency's smallest unit."""

    minor_units: int
    currency: str

    def __post_init__(self) -> None:
        if isinstance(self.minor_units, bool) or not isinstance(self.minor_units, int):
            raise InvalidValue("money minor_units must be an integer")
        if self.minor_units < 0:
            raise InvalidValue("money cannot be negative")
        if not isinstance(self.currency, str) or not _CURRENCY_PATTERN.fullmatch(self.currency):
            raise InvalidValue("currency must be three uppercase ASCII letters")

    @classmethod
    def zero(cls, currency: str) -> Money:
        return cls(0, currency)

    def _require_same_currency(self, other: Money) -> None:
        if not isinstance(other, Money):
            raise TypeError("money arithmetic requires another Money value")
        if self.currency != other.currency:
            raise InvalidValue(f"currency mismatch: {self.currency} != {other.currency}")

    def __add__(self, other: Money) -> Money:
        self._require_same_currency(other)
        return Money(self.minor_units + other.minor_units, self.currency)

    def __sub__(self, other: Money) -> Money:
        self._require_same_currency(other)
        result = self.minor_units - other.minor_units
        if result < 0:
            raise InvalidValue("money subtraction cannot produce a negative amount")
        return Money(result, self.currency)

    def to_primitive(self) -> dict[str, Any]:
        return {"currency": self.currency, "minor_units": self.minor_units}


@dataclass(frozen=True, slots=True, init=False)
class Probability:
    """An exact decimal probability; binary floats are deliberately rejected."""

    value: Decimal

    def __init__(self, value: Decimal | str | int) -> None:
        if isinstance(value, (bool, float)):
            raise InvalidValue("probability must use Decimal, string, or integer")
        try:
            parsed = value if isinstance(value, Decimal) else Decimal(value)
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise InvalidValue("probability is not a valid decimal") from exc
        if not parsed.is_finite() or parsed < 0 or parsed > 1:
            raise InvalidValue("probability must be finite and within [0, 1]")
        object.__setattr__(self, "value", parsed)

    def __lt__(self, other: Probability) -> bool:
        if not isinstance(other, Probability):
            return NotImplemented
        return self.value < other.value

    def __le__(self, other: Probability) -> bool:
        if not isinstance(other, Probability):
            return NotImplemented
        return self.value <= other.value

    def to_primitive(self) -> str:
        rendered = format(self.value, "f")
        if "." in rendered:
            rendered = rendered.rstrip("0").rstrip(".")
        return rendered or "0"
