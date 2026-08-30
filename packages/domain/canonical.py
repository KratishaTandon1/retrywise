"""A deliberately small canonical-JSON profile used by domain hashes.

The profile admits only deterministic JSON values. Floating point values are
rejected so financial or probability evidence cannot acquire platform-specific
representations. Domain value objects may opt in via ``to_primitive``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum
from typing import Any

from .errors import InvalidValue


def require_utc(value: datetime, *, field: str = "timestamp") -> datetime:
    """Return an aware timestamp normalized to UTC."""

    if not isinstance(value, datetime):
        raise InvalidValue(f"{field} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise InvalidValue(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


def canonical_timestamp(value: datetime) -> str:
    """Format UTC with a fixed microsecond precision and trailing ``Z``."""

    return require_utc(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_canonical_timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise InvalidValue("canonical timestamp must be a string")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise InvalidValue("timestamp is not in canonical UTC format") from exc
    return parsed.replace(tzinfo=UTC)


def _decimal_string(value: Decimal) -> str:
    if not value.is_finite():
        raise InvalidValue("non-finite Decimal is not canonical JSON evidence")
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    if rendered in {"", "-0"}:
        return "0"
    return rendered


def to_canonical_primitive(value: Any) -> Any:
    """Normalize a value into the supported deterministic JSON subset."""

    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        raise InvalidValue("float values are forbidden in canonical evidence")
    if isinstance(value, Decimal):
        return _decimal_string(value)
    if isinstance(value, datetime):
        return canonical_timestamp(value)
    if isinstance(value, Enum):
        return to_canonical_primitive(value.value)
    if hasattr(value, "to_primitive"):
        return to_canonical_primitive(value.to_primitive())
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise InvalidValue("canonical JSON object keys must be strings")
            normalized[key] = to_canonical_primitive(item)
        return normalized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [to_canonical_primitive(item) for item in value]
    raise InvalidValue(f"unsupported canonical JSON value type: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """Serialize with sorted keys, UTF-8 characters, and no whitespace."""

    return json.dumps(
        to_canonical_primitive(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def canonical_json_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")
