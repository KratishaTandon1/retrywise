"""Canonical feature fixtures for diagnosis tests."""


def provider_incident_features() -> dict[str, object]:
    return {
        "payment_method": "upi",
        "error_source": "provider",
        "error_step": "processing",
        "error_reason": "provider_unavailable",
        "incident_state": "confirmed",
        "attempt_bucket": "first",
        "failure_age_bucket": "fresh",
    }
