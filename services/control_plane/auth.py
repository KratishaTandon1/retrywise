"""Operator authentication port and a narrow local bearer adapter."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class AuthContext:
    subject: str
    merchant_id: str
    roles: frozenset[str]


class OperatorAuthorizer(Protocol):
    def authorize(self, authorization_header: str | None) -> AuthContext | None: ...


class DenyAllAuthorizer:
    def authorize(self, authorization_header: str | None) -> None:
        return None


class StaticBearerAuthorizer:
    """Local development adapter that stores only a token digest in memory.

    Deployed environments should replace this with an OIDC/JWT verifier and
    derive tenant scope from verified claims.
    """

    def __init__(self, *, token: bytes, subject: str, merchant_id: str) -> None:
        if not isinstance(token, bytes) or len(token) < 32:
            raise ValueError("local operator token must contain at least 32 bytes")
        if not subject or not merchant_id:
            raise ValueError("subject and merchant_id are required")
        self._token_digest = hashlib.sha256(token).digest()
        self._context = AuthContext(
            subject=subject,
            merchant_id=merchant_id,
            roles=frozenset({"operator"}),
        )

    def authorize(self, authorization_header: str | None) -> AuthContext | None:
        if not isinstance(authorization_header, str):
            return None
        scheme, separator, credential = authorization_header.partition(" ")
        if separator != " " or scheme.lower() != "bearer" or not credential:
            return None
        candidate = hashlib.sha256(credential.encode("utf-8")).digest()
        if not hmac.compare_digest(self._token_digest, candidate):
            return None
        return self._context
