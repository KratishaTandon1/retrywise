"""Hardened local-file resolver for Razorpay Test Mode credential material.

The resolver is intended for local rehearsal and container secret mounts.  It
accepts only ``file:<basename>.json`` references rooted in one configured
directory, opens files without following symlinks, requires owner-only
permissions, bounds the bytes read, and parses an exact JSON schema.  Secret
values are never included in exceptions or representations.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Final

from .private_files import is_private_regular_file
from .razorpay_account_binding import (
    RazorpayCredentialMaterial,
    RazorpayCredentialResolutionError,
)

_REFERENCE_RE: Final = re.compile(r"^file:([A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.json)$")
_MAX_SECRET_BYTES: Final = 8 * 1024
_FIELDS: Final = frozenset(
    {
        "merchant_id",
        "provider_account_id",
        "provider_account_identifier",
        "environment",
        "enabled",
        "credential_binding_version",
        "key_id",
        "key_secret",
    }
)


def _private_file_metadata(metadata: os.stat_result, *, platform_name: str = os.name) -> bool:
    return is_private_regular_file(metadata, platform_name=platform_name)


class FileRazorpayCredentialSecretResolver:
    """Resolve one exact Test credential snapshot from a protected directory."""

    def __init__(self, *, secret_root: str | Path) -> None:
        root = Path(secret_root)
        if not root.is_absolute():
            raise ValueError("secret_root must be absolute")
        try:
            resolved = root.resolve(strict=True)
        except OSError as exc:
            raise ValueError("secret_root must exist") from exc
        if not resolved.is_dir() or resolved.is_symlink():
            raise ValueError("secret_root must be a real directory")
        self._secret_root = resolved

    def __repr__(self) -> str:
        return "FileRazorpayCredentialSecretResolver(secret_root=<redacted>)"

    def resolve(self, *, credential_secret_ref: str) -> RazorpayCredentialMaterial:
        """Return validated material or one sanitized resolution failure."""

        try:
            if type(credential_secret_ref) is not str:
                raise ValueError
            matched = _REFERENCE_RE.fullmatch(credential_secret_ref)
            if matched is None:
                raise ValueError
            path = self._secret_root / matched.group(1)
            flags = os.O_RDONLY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
            try:
                metadata = os.fstat(descriptor)
                if not _private_file_metadata(metadata):
                    raise ValueError
                if not 1 <= metadata.st_size <= _MAX_SECRET_BYTES:
                    raise ValueError
                raw = os.read(descriptor, _MAX_SECRET_BYTES + 1)
                if len(raw) != metadata.st_size or len(raw) > _MAX_SECRET_BYTES:
                    raise ValueError
            finally:
                os.close(descriptor)

            decoded = json.loads(raw.decode("utf-8"))
            if not isinstance(decoded, dict) or set(decoded) != _FIELDS:
                raise ValueError
            return RazorpayCredentialMaterial(
                merchant_id=decoded["merchant_id"],
                provider_account_id=decoded["provider_account_id"],
                provider_account_identifier=decoded["provider_account_identifier"],
                environment=decoded["environment"],
                enabled=decoded["enabled"],
                credential_secret_ref=credential_secret_ref,
                credential_binding_version=decoded["credential_binding_version"],
                key_id=decoded["key_id"],
                key_secret=decoded["key_secret"],
            )
        except RazorpayCredentialResolutionError:
            raise
        except Exception:
            raise RazorpayCredentialResolutionError(
                "razorpay_credential_resolution_failed"
            ) from None


__all__ = ["FileRazorpayCredentialSecretResolver"]
