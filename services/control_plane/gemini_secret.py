"""Owner-only Gemini API key file loading."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .private_files import is_private_regular_file


class GeminiSecretFileError(RuntimeError):
    pass


def load_gemini_api_key_file(path_value: str) -> str:
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
            if not 1 <= metadata.st_size <= 2048:
                raise ValueError
            raw = os.read(descriptor, 2049)
            if len(raw) != metadata.st_size:
                raise ValueError
        finally:
            os.close(descriptor)
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or set(value) != {"api_key"}:
            raise ValueError
        api_key = value["api_key"]
        if not isinstance(api_key, str) or not 16 <= len(api_key) <= 512:
            raise ValueError
        if api_key != api_key.strip():
            raise ValueError
        return api_key
    except Exception:
        raise GeminiSecretFileError("gemini_secret_file_unavailable") from None


__all__ = ["GeminiSecretFileError", "load_gemini_api_key_file"]
