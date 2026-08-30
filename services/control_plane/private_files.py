"""Cross-platform metadata checks for externally ACL-protected secret files."""

from __future__ import annotations

import os
import stat
from pathlib import Path


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


def _is_trusted_managed_symlink(
    link_metadata: os.stat_result,
    parent_metadata: os.stat_result,
    *,
    platform_name: str = os.name,
) -> bool:
    """Recognize a root-controlled managed secret link without trusting its target yet."""

    if platform_name == "nt" or not stat.S_ISLNK(link_metadata.st_mode):
        return False
    parent_mode = stat.S_IMODE(parent_metadata.st_mode)
    return (
        link_metadata.st_uid == 0
        and stat.S_ISDIR(parent_metadata.st_mode)
        and parent_metadata.st_uid == 0
        and not bool(parent_mode & (stat.S_IWGRP | stat.S_IWOTH))
    )


def open_private_regular_file(path_value: str | Path) -> tuple[int, os.stat_result]:
    """Open a private file or a root-controlled managed secret link atomically.

    Ordinary links remain fail-closed. Managed platforms may expose secrets as
    root-owned links inside a root-owned, non-writable directory. In that case
    the opened target must still pass the private regular-file boundary before
    its descriptor is returned.
    """

    path = Path(path_value)
    link_metadata = os.lstat(path)
    is_link = stat.S_ISLNK(link_metadata.st_mode)
    if is_link:
        parent_metadata = os.stat(path.parent, follow_symlinks=False)
        if not _is_trusted_managed_symlink(link_metadata, parent_metadata):
            raise OSError("untrusted secret-file link")

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if not is_link and hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not is_private_regular_file(metadata):
            raise OSError("secret-file target is not private")
        return descriptor, metadata
    except Exception:
        os.close(descriptor)
        raise


__all__ = ["is_private_regular_file", "open_private_regular_file"]
