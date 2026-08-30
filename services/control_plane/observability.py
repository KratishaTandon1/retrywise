"""Dependency-light, privacy-safe control-plane observability primitives.

This module intentionally provides process-local counters only. Production
deployments must export the same counter names to a cross-replica metrics
backend rather than aggregating these snapshots.
"""

from __future__ import annotations

import contextvars
import json
import logging
import re
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from threading import Lock
from typing import Any
from uuid import uuid4

REDACTED = "[REDACTED]"
UNMATCHED_ROUTE = "<unmatched>"

_REQUEST_ID = contextvars.ContextVar[str | None]("retrywise_request_id", default=None)
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_EVENT_RE = re.compile(r"^[a-z0-9]+(?:[._][a-z0-9]+)*$")
_WEBHOOK_PATH_RE = re.compile(r"(/api/v1/webhooks/razorpay/)[^\s\"]+", re.IGNORECASE)
_URL_QUERY_RE = re.compile(r"((?:https?://[^\s?\"]+|/[^\s?\"]*))\?[^\s\"]+")
_BEARER_RE = re.compile(r"(?i)\b(Bearer)\s+[^\s,;]+")
_BASIC_RE = re.compile(r"(?i)\b(Basic)\s+[^\s,;]+")
_EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[- ]?)?[6-9]\d{9}(?!\d)")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(authorization|api[_-]?key|password|secret|token)\s*[:=]\s*[^\s,;]+"
)

_SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "address",
        "authorization",
        "body",
        "card",
        "contact",
        "client_ip",
        "cookie",
        "customer",
        "customer_id",
        "customer_name",
        "email",
        "endpoint_token",
        "idempotency_key",
        "key_secret",
        "notes",
        "password",
        "payload",
        "phone",
        "phone_number",
        "ip_address",
        "proxy_authorization",
        "raw_body",
        "razorpay_key_id",
        "razorpay_key_secret",
        "refresh_token",
        "remote_addr",
        "secret",
        "set_cookie",
        "signature",
        "vpa",
        "webhook_secret",
        "x_razorpay_signature",
    }
)


class CounterName(StrEnum):
    """Stable names shared with a future external metrics adapter."""

    WEBHOOK_ACCEPTED = "webhook_accepted_total"
    WEBHOOK_DUPLICATE = "webhook_duplicate_total"
    WEBHOOK_CONFLICT = "webhook_conflict_total"
    WEBHOOK_VERIFICATION_FAILURE = "webhook_verification_failure_total"
    REPLAY_SUBMISSION = "replay_submission_total"


class InProcessCounters:
    """Thread-safe counters for development and single-process tests."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._values = {name.value: 0 for name in CounterName}

    def increment(self, name: CounterName) -> None:
        if not isinstance(name, CounterName):
            raise TypeError("name must be CounterName")
        with self._lock:
            self._values[name.value] += 1

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._values)


class StructuredJsonFormatter(logging.Formatter):
    """Serialize allowlisted log metadata after recursive redaction."""

    def format(self, record: logging.LogRecord) -> str:
        event = getattr(record, "retrywise_event", "application.log")
        fields = getattr(record, "retrywise_fields", {})
        if not isinstance(fields, Mapping):
            fields = {"fields": fields}
        document = _redact_mapping(fields)
        for reserved_key in ("event", "level", "logger", "request_id", "timestamp"):
            document.pop(reserved_key, None)
        document.update(
            {
                "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "event": _safe_event(event),
            }
        )
        request_id = getattr(record, "retrywise_request_id", None)
        if isinstance(request_id, str) and _REQUEST_ID_RE.fullmatch(request_id):
            document["request_id"] = request_id
        return json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


class Observability:
    """Own structured events and local counters without request-data logging."""

    def __init__(
        self,
        logger: logging.Logger | None = None,
        counters: InProcessCounters | None = None,
    ) -> None:
        self._logger = logger or _default_logger()
        self.counters = counters or InProcessCounters()

    def event(
        self,
        name: str,
        *,
        level: int = logging.INFO,
        fields: Mapping[str, object] | None = None,
    ) -> None:
        safe_name = _safe_event(name)
        self._logger.log(
            level,
            safe_name,
            extra={
                "retrywise_event": safe_name,
                "retrywise_fields": dict(fields or {}),
                "retrywise_request_id": current_request_id(),
            },
        )


def choose_request_id(candidate: str | None) -> str:
    """Return a safe caller correlation ID or generate an opaque replacement."""

    if candidate is not None and _REQUEST_ID_RE.fullmatch(candidate):
        return candidate
    return f"req_{uuid4().hex}"


def bind_request_id(request_id: str) -> contextvars.Token[str | None]:
    if not _REQUEST_ID_RE.fullmatch(request_id):
        raise ValueError("request_id is not log-safe")
    return _REQUEST_ID.set(request_id)


def reset_request_id(token: contextvars.Token[str | None]) -> None:
    _REQUEST_ID.reset(token)


def current_request_id() -> str | None:
    return _REQUEST_ID.get()


def disable_unstructured_server_access_log() -> None:
    """Prevent Uvicorn's raw-path access logger from bypassing this boundary."""

    logging.getLogger("uvicorn.access").disabled = True


def safe_route_template(scope: Mapping[str, Any]) -> str:
    """Return only the framework route template; never return the request path."""

    route = scope.get("route")
    route_path = getattr(route, "path", None)
    if not isinstance(route_path, str) or not route_path.startswith("/"):
        return UNMATCHED_ROUTE
    if len(route_path) > 256 or any(character in route_path for character in "\r\n\t"):
        return UNMATCHED_ROUTE
    return _WEBHOOK_PATH_RE.sub(r"\1{endpoint_token}", route_path)


def redact(value: object) -> object:
    """Recursively redact credentials, request bodies, and customer data."""

    if isinstance(value, Mapping):
        return _redact_mapping(value)
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _redact_string(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return f"<{type(value).__name__}>"


def _redact_mapping(value: Mapping[object, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key)
        if _is_sensitive_key(key):
            result[key] = REDACTED
        else:
            result[key] = redact(raw_value)
    return result


def _is_sensitive_key(key: str) -> bool:
    snake_case_key = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    normalized = re.sub(r"[^a-z0-9]+", "_", snake_case_key.casefold()).strip("_")
    return (
        normalized in _SENSITIVE_KEYS
        or normalized.startswith(("card_", "contact_", "customer_"))
        or normalized.endswith(
            (
                "_address",
                "_contact",
                "_email",
                "_notes",
                "_password",
                "_phone",
                "_secret",
                "_token",
                "_vpa",
            )
        )
    )


def _redact_string(value: str) -> str:
    redacted = _WEBHOOK_PATH_RE.sub(r"\1{endpoint_token}", value)
    redacted = _URL_QUERY_RE.sub(r"\1?[REDACTED]", redacted)
    redacted = _BEARER_RE.sub(r"\1 [REDACTED]", redacted)
    redacted = _BASIC_RE.sub(r"\1 [REDACTED]", redacted)
    redacted = _SECRET_ASSIGNMENT_RE.sub(r"\1=[REDACTED]", redacted)
    redacted = _EMAIL_RE.sub(REDACTED, redacted)
    return _PHONE_RE.sub(REDACTED, redacted)


def _safe_event(value: object) -> str:
    if not isinstance(value, str) or not _EVENT_RE.fullmatch(value):
        return "application.invalid_event_name"
    return value


def _default_logger() -> logging.Logger:
    logger = logging.getLogger("retrywise.control_plane")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not any(
        isinstance(handler.formatter, StructuredJsonFormatter) for handler in logger.handlers
    ):
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(StructuredJsonFormatter())
        logger.addHandler(handler)
    return logger
