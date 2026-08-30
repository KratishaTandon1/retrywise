"""Stable, non-secret external identifiers for recovery Payment Links."""

from __future__ import annotations

import base64
import hashlib
import re
import unicodedata

_REFERENCE_PREFIX = "rtw_"
_REFERENCE_NAMESPACE = b"retrywise:razorpay:recovery-reference:v1\x00"
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


class ReferenceIdError(ValueError):
    """A stable recovery reference cannot be generated from the inputs."""


def _validated_identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReferenceIdError(f"{field} must be a non-empty string")
    if value != value.strip():
        raise ReferenceIdError(f"{field} cannot contain surrounding whitespace")
    if len(value) > 512:
        raise ReferenceIdError(f"{field} exceeds 512 characters")
    return value


def make_recovery_reference_id(recovery_case_id: str, *, provider_account_id: str) -> str:
    """Build a deterministic Razorpay ``reference_id`` of at most 40 chars.

    The provider account is part of the digest so independently generated case
    ids cannot collide across merchant scopes.  The digest is public identity,
    not a MAC and not an authentication mechanism.
    """

    case_id = _validated_identifier(recovery_case_id, "recovery_case_id")
    account_id = _validated_identifier(provider_account_id, "provider_account_id")

    ascii_case = (
        unicodedata.normalize("NFKD", case_id).encode("ascii", "ignore").decode("ascii").lower()
    )
    slug = _NON_ALNUM.sub("", ascii_case)[:8] or "case"
    digest_input = (
        _REFERENCE_NAMESPACE + account_id.encode("utf-8") + b"\x00" + case_id.encode("utf-8")
    )
    digest = base64.b32encode(hashlib.sha256(digest_input).digest()[:16])
    digest_text = digest.decode("ascii").rstrip("=").lower()
    reference_id = f"{_REFERENCE_PREFIX}{slug}_{digest_text}"
    if len(reference_id) > 40:  # Defensive assertion around format changes.
        raise AssertionError("generated Razorpay reference_id exceeds 40 characters")
    return reference_id
