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

    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o7000 or not mode & stat.S_IRUSR:
        return False

    effective_uid = os.getuid()
    if metadata.st_uid not in {0, effective_uid}:
        return False

    # Locally enrolled files remain exact owner-only snapshots. Managed
    # platforms such as Render mount secret files as root-owned 0640 and place
    # the service process in the file's group. Accept only that narrow managed
    # boundary: the current process must belong to the group, group access is
    # read-only, and no permission is granted to other users.
    if not mode & 0o077:
        return True
    process_groups = {os.getgid(), *os.getgroups()}
    return (
        metadata.st_uid == 0
        and metadata.st_gid in process_groups
        and bool(mode & stat.S_IRGRP)
        and not bool(mode & (stat.S_IWGRP | stat.S_IXGRP | stat.S_IRWXO))
    )


__all__ = ["is_private_regular_file"]
