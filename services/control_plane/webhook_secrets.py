"""Protected-file loading for webhook secret rotation snapshots."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from .private_files import is_private_regular_file


class WebhookSecretFileError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class WebhookSecretSnapshot:
    current: str
    previous: str | None = None
    previous_expires_at: str | None = None

    def __post_init__(self) -> None:
        if not 16 <= len(self.current) <= 512 or self.current != self.current.strip():
            raise ValueError("current webhook secret is invalid")
        if (self.previous is None) != (self.previous_expires_at is None):
            raise ValueError("previous webhook secret and expiry must be paired")
        if self.previous is not None:
            if not 16 <= len(self.previous) <= 512 or self.previous != self.previous.strip():
                raise ValueError("previous webhook secret is invalid")
            if self.previous == self.current:
                raise ValueError("webhook rotation secrets must differ")

    def __repr__(self) -> str:
        return "WebhookSecretSnapshot(current=<redacted>, previous=<redacted>)"


def load_webhook_secret_file(path_value: str) -> WebhookSecretSnapshot:
    """Load one exact non-symlink, owner-only JSON file without leaking contents."""

    try:
        path = Path(path_value)
        if not path.is_absolute():
            raise ValueError
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not is_private_regular_file(metadata):
                raise ValueError
            if not 1 <= metadata.st_size <= 4096:
                raise ValueError
            raw = os.read(descriptor, 4097)
            if len(raw) != metadata.st_size:
                raise ValueError
        finally:
            os.close(descriptor)
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError
        allowed = {"current", "previous", "previous_expires_at"}
        if not {"current"} <= set(value) <= allowed:
            raise ValueError
        return WebhookSecretSnapshot(
            current=value["current"],
            previous=value.get("previous"),
            previous_expires_at=value.get("previous_expires_at"),
        )
    except Exception:
        raise WebhookSecretFileError("webhook_secret_file_unavailable") from None


__all__ = [
    "WebhookSecretFileError",
    "WebhookSecretSnapshot",
    "load_webhook_secret_file",
]
