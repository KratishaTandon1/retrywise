"""Fresh Razorpay payment truth and detector-owned method-health readers."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from datetime import UTC, datetime
from typing import Protocol, cast

from ...packages.domain import IncidentState
from .assessment_intent import (
    AssessmentMethodHealthError,
    AssessmentProviderTruthError,
    FreshMethodHealthTruth,
    FreshProviderPaymentTruth,
    MethodHealthQuery,
    ProviderPaymentStatus,
    ProviderTruthQuery,
)
from .postgres_connection import PostgresConnectionPolicy
from .razorpay_account_binding import (
    PostgresRazorpayAccountBindingRepository,
    RazorpayCredentialSecretResolver,
    compose_razorpay_test_mode_adapter,
)
from .razorpay_test_adapter import (
    PaymentRecord,
    PaymentStatus,
    RazorpayReadError,
    RazorpayTestModePaymentLinkAdapter,
)


class PaymentTruthAdapter(Protocol):
    def fetch_payment(
        self,
        *,
        payment_id: str,
        provider_account_id: str,
    ) -> PaymentRecord: ...

    def close(self) -> None: ...


PaymentTruthAdapterFactory = Callable[[str, str], PaymentTruthAdapter]


class BoundRazorpayTestAdapterFactory:
    """Create one version-fenced adapter snapshot for each bounded read/effect."""

    def __init__(
        self,
        *,
        account_bindings: PostgresRazorpayAccountBindingRepository,
        secret_resolver: RazorpayCredentialSecretResolver,
    ) -> None:
        self._account_bindings = account_bindings
        self._secret_resolver = secret_resolver

    def __call__(
        self, merchant_id: str, provider_account_id: str
    ) -> RazorpayTestModePaymentLinkAdapter:
        return compose_razorpay_test_mode_adapter(
            account_bindings=self._account_bindings,
            secret_resolver=self._secret_resolver,
            merchant_id=merchant_id,
            provider_account_id=provider_account_id,
        )


_STATUS_MAP = {
    PaymentStatus.CREATED: ProviderPaymentStatus.CREATED,
    PaymentStatus.AUTHORIZED: ProviderPaymentStatus.AUTHORIZED,
    PaymentStatus.CAPTURED: ProviderPaymentStatus.CAPTURED,
    PaymentStatus.REFUNDED: ProviderPaymentStatus.REFUNDED,
    PaymentStatus.FAILED: ProviderPaymentStatus.FAILED,
}


class RazorpayFreshProviderTruthReader:
    """Fetch one cache-bypassing payment projection with a fresh adapter snapshot."""

    def __init__(
        self,
        *,
        adapter_factory: PaymentTruthAdapterFactory,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not callable(adapter_factory):
            raise TypeError("adapter_factory must be callable")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        self._adapter_factory = adapter_factory
        self._clock = clock or (lambda: datetime.now(UTC))

    def fetch_fresh_payment_truth(self, query: ProviderTruthQuery) -> FreshProviderPaymentTruth:
        if not isinstance(query, ProviderTruthQuery):
            raise TypeError("query must be ProviderTruthQuery")
        adapter: PaymentTruthAdapter | None = None
        try:
            adapter = self._adapter_factory(query.merchant_id, query.provider_account_id)
            if not callable(getattr(adapter, "fetch_payment", None)) or not callable(
                getattr(adapter, "close", None)
            ):
                raise TypeError
            payment = adapter.fetch_payment(
                payment_id=query.provider_payment_id,
                provider_account_id=query.provider_account_id,
            )
            if type(payment) is not PaymentRecord:
                raise TypeError
            if (
                payment.payment_id != query.provider_payment_id
                or payment.order_id != query.provider_order_id
            ):
                raise AssessmentProviderTruthError("fresh_provider_truth_binding_mismatch")
            observed_at = self._clock()
            if (
                not isinstance(observed_at, datetime)
                or observed_at.tzinfo is None
                or observed_at.utcoffset() is None
            ):
                raise TypeError
            return FreshProviderPaymentTruth(
                merchant_id=query.merchant_id,
                provider_account_id=query.provider_account_id,
                credential_binding_version=query.credential_binding_version,
                provider_payment_id=payment.payment_id,
                provider_order_id=payment.order_id,
                status=_STATUS_MAP[payment.status],
                amount_minor=payment.amount_minor,
                currency=payment.currency,
                captured_minor=payment.captured_minor,
                refunded_minor=payment.refunded_minor,
                payment_method=payment.payment_method,
                error_source=payment.error_source,
                error_step=payment.error_step,
                error_reason=payment.error_reason,
                observed_at=observed_at.astimezone(UTC),
            )
        except AssessmentProviderTruthError:
            raise
        except (RazorpayReadError, Exception):
            raise AssessmentProviderTruthError("fresh_provider_truth_unavailable") from None
        finally:
            if adapter is not None:
                with suppress(Exception):
                    adapter.close()


_LOAD_INCIDENT = """
WITH statement AS MATERIALIZED (SELECT clock_timestamp() AS now)
SELECT
    statement.now,
    incident.id::text,
    incident.state::text,
    incident.detector_version,
    incident.threshold_version,
    incident.evidence_observed_at
FROM statement
JOIN retrywise.incidents AS incident
  ON incident.merchant_id = %(merchant_id)s
 AND incident.provider_account_id = %(provider_account_id)s
 AND incident.id = %(incident_id)s
 AND incident.payment_method = %(payment_method)s
 AND incident.state IN ('SUSPECTED', 'CONFIRMED', 'COOLING')
"""

_LOAD_NORMAL_CLOCK = "SELECT clock_timestamp()"


class _Cursor(Protocol):
    def execute(self, query: str, params: Mapping[str, object] | None = None) -> object: ...

    def fetchone(self) -> Sequence[object] | None: ...

    def __enter__(self) -> _Cursor: ...

    def __exit__(self, *args: object) -> bool | None: ...


class _Transaction(Protocol):
    def __enter__(self) -> object: ...

    def __exit__(self, *args: object) -> bool | None: ...


class _Connection(Protocol):
    def cursor(self) -> _Cursor: ...

    def transaction(self) -> _Transaction: ...


class _ConnectionContext(Protocol):
    def __enter__(self) -> _Connection: ...

    def __exit__(self, *args: object) -> bool | None: ...


ConnectionFactory = Callable[[], _ConnectionContext]


def _dsn_factory(dsn: str, *, require_tls: bool) -> ConnectionFactory:
    policy = PostgresConnectionPolicy(require_tls=require_tls)
    policy.validate_dsn(dsn)

    def connect() -> _ConnectionContext:
        return cast(
            _ConnectionContext,
            policy.connect(dsn, component="PostgresMethodHealthReader"),
        )

    return connect


class PostgresFreshMethodHealthReader:
    """Read the exact incident bound to a case, or fresh detector-normal truth."""

    def __init__(
        self,
        *,
        dsn: str | None = None,
        connector: ConnectionFactory | None = None,
        require_tls: bool = False,
        normal_detector_version: str = "incident-detector-v1",
        normal_threshold_version: str = "incident-threshold-v1",
    ) -> None:
        if (dsn is None) == (connector is None):
            raise ValueError("provide exactly one of dsn or connector")
        if dsn is not None:
            self._connector = _dsn_factory(dsn, require_tls=require_tls)
        else:
            if require_tls or not callable(connector):
                raise ValueError("custom connectors cannot attest TLS")
            self._connector = connector
        self._normal_detector_version = normal_detector_version
        self._normal_threshold_version = normal_threshold_version

    def fetch_fresh_method_health(self, query: MethodHealthQuery) -> FreshMethodHealthTruth:
        if not isinstance(query, MethodHealthQuery):
            raise TypeError("query must be MethodHealthQuery")
        try:
            with (
                self._connector() as connection,
                connection.transaction(),
                connection.cursor() as cursor,
            ):
                if query.incident_id is None:
                    cursor.execute(_LOAD_NORMAL_CLOCK)
                    row = cursor.fetchone()
                    if row is None or len(row) != 1:
                        raise ValueError
                    observed_at = row[0]
                    if not isinstance(observed_at, datetime):
                        raise ValueError
                    return FreshMethodHealthTruth(
                        merchant_id=query.merchant_id,
                        provider_account_id=query.provider_account_id,
                        payment_method=query.payment_method,
                        incident_state=IncidentState.NORMAL,
                        observed_at=observed_at,
                        detector_version=self._normal_detector_version,
                        threshold_version=self._normal_threshold_version,
                    )
                cursor.execute(
                    _LOAD_INCIDENT,
                    {
                        "merchant_id": query.merchant_id,
                        "provider_account_id": query.provider_account_id,
                        "payment_method": query.payment_method,
                        "incident_id": query.incident_id,
                    },
                )
                row = cursor.fetchone()
                if row is None or len(row) != 6:
                    raise ValueError
                statement_now, incident_id, state, detector, threshold, evidence_at = row
                if (
                    not isinstance(statement_now, datetime)
                    or not isinstance(evidence_at, datetime)
                    or type(incident_id) is not str
                    or type(state) is not str
                    or type(detector) is not str
                    or type(threshold) is not str
                ):
                    raise ValueError
                observed_at = min(statement_now, evidence_at)
                return FreshMethodHealthTruth(
                    merchant_id=query.merchant_id,
                    provider_account_id=query.provider_account_id,
                    payment_method=query.payment_method,
                    incident_state=IncidentState(str(state).lower()),
                    observed_at=observed_at,
                    detector_version=detector,
                    threshold_version=threshold,
                    incident_id=incident_id,
                )
        except Exception:
            raise AssessmentMethodHealthError("fresh_method_health_unavailable") from None


__all__ = [
    "BoundRazorpayTestAdapterFactory",
    "PaymentTruthAdapter",
    "PaymentTruthAdapterFactory",
    "PostgresFreshMethodHealthReader",
    "RazorpayFreshProviderTruthReader",
]
