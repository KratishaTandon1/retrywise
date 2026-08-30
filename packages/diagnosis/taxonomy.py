"""Closed payment-failure taxonomy emitted by the diagnosis model."""

from enum import StrEnum


class FailureClass(StrEnum):
    """A diagnosis only; these values never authorize a recovery action."""

    PROVIDER_INCIDENT = "provider_incident"
    CUSTOMER_CORRECTABLE = "customer_correctable"
    CREDENTIAL_PERMANENT = "credential_permanent"
    FUNDS_TEMPORARY = "funds_temporary"
    MERCHANT_INTEGRATION = "merchant_integration"
    UNKNOWN = "unknown"


FAILURE_TAXONOMY: tuple[FailureClass, ...] = (
    FailureClass.PROVIDER_INCIDENT,
    FailureClass.CUSTOMER_CORRECTABLE,
    FailureClass.CREDENTIAL_PERMANENT,
    FailureClass.FUNDS_TEMPORARY,
    FailureClass.MERCHANT_INTEGRATION,
    FailureClass.UNKNOWN,
)
