"""Cross-platform metadata checks for externally ACL-protected secret files."""

from __future__ import annotations

import os
import stat


def is_private_regular_file(
    metadata: os.stat_result,
    *,
    platform_name: str = os.name,
) -> bool:
    """Validate file type and the permission representation available to Python."""

    if not stat.S_ISREG(metadata.st_mode):
        return False
    if platform_name == "nt":
        # NTFS authority is held in the DACL, not POSIX mode bits. Enrollment
        # and the runbook provision an inheritance-free operator-only DACL.
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        return not bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag)
    return metadata.st_uid in {0, os.getuid()} and not bool(stat.S_IMODE(metadata.st_mode) & 0o077)


__all__ = ["is_private_regular_file"]
