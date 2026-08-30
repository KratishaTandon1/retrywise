"""Razorpay boundary primitives for RetryWise.

This package intentionally contains no transport client and no credentials.  It
owns validation and normalisation at the provider boundary; applications own
secret retrieval, HTTP, persistence, and scheduling.
"""

from .inbox import (
    InboxConflictError,
    InboxRecord,
    InboxWriteResult,
    InMemoryWebhookInbox,
    WebhookInbox,
)
from .payment_links import (
    AmbiguousCreateAction,
    AmbiguousCreateDecision,
    PaymentLinkCustomer,
    PaymentLinkLookupResult,
    PaymentLinkValidationError,
    StandardPaymentLinkRequest,
    decide_ambiguous_create,
)
from .references import ReferenceIdError, make_recovery_reference_id
from .webhooks import (
    AccountMismatchError,
    CanonicalEventType,
    CanonicalWebhookEvent,
    WebhookDecodeError,
    WebhookHeaders,
    WebhookVerificationError,
    calculate_webhook_signature,
    is_valid_webhook_signature,
    normalize_verified_webhook,
    verify_and_normalize_webhook,
    verify_webhook_signature,
)

__all__ = [
    "AccountMismatchError",
    "AmbiguousCreateAction",
    "AmbiguousCreateDecision",
    "CanonicalEventType",
    "CanonicalWebhookEvent",
    "InMemoryWebhookInbox",
    "InboxConflictError",
    "InboxRecord",
    "InboxWriteResult",
    "PaymentLinkCustomer",
    "PaymentLinkLookupResult",
    "PaymentLinkValidationError",
    "ReferenceIdError",
    "StandardPaymentLinkRequest",
    "WebhookDecodeError",
    "WebhookHeaders",
    "WebhookInbox",
    "WebhookVerificationError",
    "calculate_webhook_signature",
    "decide_ambiguous_create",
    "is_valid_webhook_signature",
    "make_recovery_reference_id",
    "normalize_verified_webhook",
    "verify_and_normalize_webhook",
    "verify_webhook_signature",
]
