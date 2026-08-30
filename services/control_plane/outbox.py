"""Immutable outbox delivery state with fenced leases.

The value object deliberately contains no database code.  A repository must
persist every returned value with compare-and-swap on ``version``.  The lease
token fences workers within a version; the repository CAS provides the final
cross-process fence.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum


class OutboxError(RuntimeError):
    """Base class for outbox contract failures."""


class OutboxTransitionError(OutboxError):
    """The requested state transition is not allowed."""


class OutboxVersionConflict(OutboxError):
    """The caller is not operating on the expected persisted version."""


class OutboxLeaseError(OutboxError):
    """A lease is absent, stale, or owned by another fenced worker."""


class OutboxNotReady(OutboxError):
    """A pending delivery has not reached its availability time."""


class OutboxState(StrEnum):
    PENDING = "pending"
    LEASED = "leased"
    COMPLETED = "completed"
    DEAD_LETTER = "dead_letter"


class RetryMode(StrEnum):
    """Durable direction for the next delivery.

    ``RECONCILE_ONLY`` forbids repeating an uncertain effect.  A completed
    negative lookup can explicitly grant ``RETRY_SAME_EFFECT``; the same
    action key and payload digest still fence that retry.
    """

    NORMAL = "normal"
    RECONCILE_ONLY = "reconcile_only"
    RETRY_SAME_EFFECT = "retry_same_effect"


def _require_utc(value: datetime, *, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field} must be a timezone-aware datetime")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field} must be expressed in UTC")
    return value.astimezone(UTC)


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


@dataclass(frozen=True, slots=True)
class BackoffPolicy:
    """Deterministic, bounded exponential retry schedule."""

    base_delay: timedelta = timedelta(seconds=1)
    maximum_delay: timedelta = timedelta(minutes=5)

    def __post_init__(self) -> None:
        if not isinstance(self.base_delay, timedelta) or self.base_delay <= timedelta(0):
            raise ValueError("base_delay must be a positive timedelta")
        if not isinstance(self.maximum_delay, timedelta) or self.maximum_delay < self.base_delay:
            raise ValueError("maximum_delay must be at least base_delay")

    def delay_after(self, attempts: int) -> timedelta:
        """Return ``min(maximum, base * 2 ** (attempts - 1))`` safely."""

        if type(attempts) is not int or attempts < 1:
            raise ValueError("attempts must be a positive integer")
        delay = self.base_delay
        for _ in range(attempts - 1):
            if delay >= self.maximum_delay / 2:
                return self.maximum_delay
            delay *= 2
        return min(delay, self.maximum_delay)


@dataclass(frozen=True, slots=True)
class OutboxJob:
    """One immutable, optimistically-versioned outbox delivery."""

    job_id: str
    action_key: str
    payload_digest: str
    state: OutboxState
    version: int
    attempts: int
    max_attempts: int
    created_at: datetime
    updated_at: datetime
    available_at: datetime | None
    retry_mode: RetryMode = RetryMode.NORMAL
    lease_owner: str | None = None
    lease_token: str | None = None
    lease_expires_at: datetime | None = None
    last_error: str | None = None
    completion_reference: str | None = None
    dead_letter_reason: str | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        _require_text(self.job_id, field="job_id", maximum=128)
        _require_text(self.action_key, field="action_key", maximum=128)
        if (
            not isinstance(self.payload_digest, str)
            or len(self.payload_digest) != 64
            or any(character not in "0123456789abcdef" for character in self.payload_digest)
        ):
            raise ValueError("payload_digest must be a lowercase SHA-256 digest")
        if not isinstance(self.state, OutboxState):
            raise ValueError("state must be OutboxState")
        if not isinstance(self.retry_mode, RetryMode):
            raise ValueError("retry_mode must be RetryMode")
        for field, value, minimum in (
            ("version", self.version, 0),
            ("attempts", self.attempts, 0),
            ("max_attempts", self.max_attempts, 1),
            ("schema_version", self.schema_version, 1),
        ):
            if type(value) is not int or value < minimum:
                raise ValueError(f"{field} must be an integer >= {minimum}")
        if self.schema_version != 1:
            raise ValueError("unsupported outbox schema_version")
        if self.attempts > self.max_attempts:
            raise ValueError("attempts cannot exceed max_attempts")

        created_at = _require_utc(self.created_at, field="created_at")
        updated_at = _require_utc(self.updated_at, field="updated_at")
        if updated_at < created_at:
            raise ValueError("updated_at cannot be before created_at")
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "updated_at", updated_at)
        if self.available_at is not None:
            object.__setattr__(
                self,
                "available_at",
                _require_utc(self.available_at, field="available_at"),
            )
        if self.lease_expires_at is not None:
            object.__setattr__(
                self,
                "lease_expires_at",
                _require_utc(self.lease_expires_at, field="lease_expires_at"),
            )
        for field in (
            "lease_owner",
            "lease_token",
            "last_error",
            "completion_reference",
            "dead_letter_reason",
        ):
            value = getattr(self, field)
            if value is not None:
                _require_text(value, field=field)

        lease_fields = (self.lease_owner, self.lease_token, self.lease_expires_at)
        if self.state is OutboxState.PENDING:
            if self.available_at is None or any(value is not None for value in lease_fields):
                raise ValueError("pending jobs require available_at and no lease")
            if self.attempts >= self.max_attempts:
                raise ValueError("a max-attempt job cannot remain pending")
            if self.completion_reference is not None or self.dead_letter_reason is not None:
                raise ValueError("pending jobs cannot have terminal metadata")
        elif self.state is OutboxState.LEASED:
            if self.available_at is not None or any(value is None for value in lease_fields):
                raise ValueError("leased jobs require all lease fields and no available_at")
            if self.attempts < 1:
                raise ValueError("leased jobs require at least one attempt")
            if self.lease_expires_at <= self.updated_at:  # type: ignore[operator]
                raise ValueError("lease_expires_at must be after updated_at")
            if self.completion_reference is not None or self.dead_letter_reason is not None:
                raise ValueError("leased jobs cannot have terminal metadata")
        elif self.state is OutboxState.COMPLETED:
            if self.available_at is not None or any(value is not None for value in lease_fields):
                raise ValueError("completed jobs cannot remain schedulable or leased")
            if self.completion_reference is None or self.dead_letter_reason is not None:
                raise ValueError("completed jobs require only a completion reference")
        elif self.state is OutboxState.DEAD_LETTER:
            if self.available_at is not None or any(value is not None for value in lease_fields):
                raise ValueError("dead-letter jobs cannot remain schedulable or leased")
            if self.dead_letter_reason is None or self.completion_reference is not None:
                raise ValueError("dead-letter jobs require only a dead-letter reason")

    @classmethod
    def create(
        cls,
        *,
        job_id: str,
        action_key: str,
        payload_digest: str,
        now: datetime,
        max_attempts: int = 5,
        available_at: datetime | None = None,
    ) -> OutboxJob:
        now = _require_utc(now, field="now")
        return cls(
            job_id=job_id,
            action_key=action_key,
            payload_digest=payload_digest,
            state=OutboxState.PENDING,
            version=0,
            attempts=0,
            max_attempts=max_attempts,
            created_at=now,
            updated_at=now,
            available_at=now if available_at is None else available_at,
        )

    def claim(
        self,
        *,
        worker_id: str,
        now: datetime,
        lease_duration: timedelta,
        expected_version: int,
    ) -> OutboxJob:
        """Acquire a ready job or reclaim an expired lease.

        Reclamation forces reconciliation before another external effect.  If
        no delivery budget remains, the stale delivery is dead-lettered for
        operator reconciliation instead of being executed without a fence.
        """

        self._expect_version(expected_version)
        worker_id = _require_text(worker_id, field="worker_id", maximum=128)
        now = self._transition_time(now)
        if not isinstance(lease_duration, timedelta) or lease_duration <= timedelta(0):
            raise ValueError("lease_duration must be a positive timedelta")
        if self.state in {OutboxState.COMPLETED, OutboxState.DEAD_LETTER}:
            raise OutboxTransitionError(f"cannot claim a {self.state.value} job")
        reclaimed = self.state is OutboxState.LEASED
        if self.state is OutboxState.PENDING:
            if now < self.available_at:  # type: ignore[operator]
                raise OutboxNotReady("job has not reached available_at")
        elif now < self.lease_expires_at:  # type: ignore[operator]
            raise OutboxLeaseError("the current lease has not expired")

        next_attempt = self.attempts + 1
        if next_attempt > self.max_attempts:
            return replace(
                self,
                state=OutboxState.DEAD_LETTER,
                version=self.version + 1,
                updated_at=now,
                available_at=None,
                retry_mode=RetryMode.RECONCILE_ONLY,
                lease_owner=None,
                lease_token=None,
                lease_expires_at=None,
                dead_letter_reason="max_attempts_exhausted_after_stale_lease",
            )

        next_version = self.version + 1
        expires_at = now + lease_duration
        token_material = (
            f"{self.job_id}|{self.action_key}|{next_version}|{next_attempt}|"
            f"{worker_id}|{expires_at.isoformat()}"
        ).encode()
        lease_token = "lease_" + hashlib.sha256(token_material).hexdigest()
        return replace(
            self,
            state=OutboxState.LEASED,
            version=next_version,
            attempts=next_attempt,
            updated_at=now,
            available_at=None,
            retry_mode=(RetryMode.RECONCILE_ONLY if reclaimed else self.retry_mode),
            lease_owner=worker_id,
            lease_token=lease_token,
            lease_expires_at=expires_at,
            dead_letter_reason=None,
        )

    def complete(
        self,
        *,
        worker_id: str,
        lease_token: str,
        now: datetime,
        expected_version: int,
        result_reference: str,
    ) -> OutboxJob:
        """Complete once; replaying the exact terminal result is idempotent."""

        result_reference = _require_text(result_reference, field="result_reference", maximum=512)
        if self.state is OutboxState.COMPLETED:
            if self.completion_reference == result_reference:
                return self
            raise OutboxTransitionError("completed result conflicts with prior completion")
        self._expect_version(expected_version)
        now = self._transition_time(now)
        self.assert_active_lease(worker_id=worker_id, lease_token=lease_token, now=now)
        return replace(
            self,
            state=OutboxState.COMPLETED,
            version=self.version + 1,
            updated_at=now,
            available_at=None,
            lease_owner=None,
            lease_token=None,
            lease_expires_at=None,
            last_error=None,
            completion_reference=result_reference,
        )

    def requeue(
        self,
        *,
        worker_id: str,
        lease_token: str,
        now: datetime,
        expected_version: int,
        reason: str,
        backoff: BackoffPolicy,
        retry_mode: RetryMode,
    ) -> OutboxJob:
        """Record a safe failure and retry, or dead-letter the final attempt."""

        reason = _require_text(reason, field="reason")
        if not isinstance(backoff, BackoffPolicy):
            raise TypeError("backoff must be BackoffPolicy")
        if not isinstance(retry_mode, RetryMode):
            raise TypeError("retry_mode must be RetryMode")
        self._expect_version(expected_version)
        now = self._transition_time(now)
        self.assert_active_lease(worker_id=worker_id, lease_token=lease_token, now=now)
        if self.attempts >= self.max_attempts:
            return replace(
                self,
                state=OutboxState.DEAD_LETTER,
                version=self.version + 1,
                updated_at=now,
                available_at=None,
                retry_mode=retry_mode,
                lease_owner=None,
                lease_token=None,
                lease_expires_at=None,
                last_error=reason,
                dead_letter_reason=f"max_attempts_exhausted:{reason}",
            )
        return replace(
            self,
            state=OutboxState.PENDING,
            version=self.version + 1,
            updated_at=now,
            available_at=now + backoff.delay_after(self.attempts),
            retry_mode=retry_mode,
            lease_owner=None,
            lease_token=None,
            lease_expires_at=None,
            last_error=reason,
        )

    def dead_letter(
        self,
        *,
        worker_id: str,
        lease_token: str,
        now: datetime,
        expected_version: int,
        reason: str,
    ) -> OutboxJob:
        """Fail closed from a current lease for a non-retryable safety fault."""

        reason = _require_text(reason, field="reason")
        if self.state is OutboxState.DEAD_LETTER:
            if self.dead_letter_reason == reason:
                return self
            raise OutboxTransitionError("dead-letter reason conflicts with terminal state")
        self._expect_version(expected_version)
        now = self._transition_time(now)
        self.assert_active_lease(worker_id=worker_id, lease_token=lease_token, now=now)
        return replace(
            self,
            state=OutboxState.DEAD_LETTER,
            version=self.version + 1,
            updated_at=now,
            available_at=None,
            lease_owner=None,
            lease_token=None,
            lease_expires_at=None,
            last_error=reason,
            dead_letter_reason=reason,
        )

    def assert_active_lease(self, *, worker_id: str, lease_token: str, now: datetime) -> None:
        worker_id = _require_text(worker_id, field="worker_id", maximum=128)
        lease_token = _require_text(lease_token, field="lease_token", maximum=128)
        now = _require_utc(now, field="now")
        if self.state is not OutboxState.LEASED:
            raise OutboxLeaseError("job is not leased")
        if self.lease_owner != worker_id or self.lease_token != lease_token:
            raise OutboxLeaseError("worker or fencing token does not own this lease")
        if now >= self.lease_expires_at:  # type: ignore[operator]
            raise OutboxLeaseError("lease has expired")

    def _expect_version(self, expected_version: int) -> None:
        if type(expected_version) is not int or expected_version != self.version:
            raise OutboxVersionConflict(
                f"expected version {expected_version!r}, current version is {self.version}"
            )

    def _transition_time(self, value: datetime) -> datetime:
        value = _require_utc(value, field="now")
        if value < self.updated_at:
            raise ValueError("transition time cannot move backwards")
        return value
