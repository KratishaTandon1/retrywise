from __future__ import annotations

import os
import stat
import unittest
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

from retrywise.services.control_plane import private_files


class PrivateFileMetadataTests(unittest.TestCase):
    def test_accepts_only_current_owner_or_render_managed_group_read(self) -> None:
        def metadata(mode: int, *, uid: int, gid: int) -> os.stat_result:
            return cast(
                os.stat_result,
                SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=uid, st_gid=gid),
            )

        with (
            patch.object(private_files.os, "getuid", return_value=1000, create=True),
            patch.object(private_files.os, "getgid", return_value=2000, create=True),
            patch.object(private_files.os, "getgroups", return_value=[2000], create=True),
        ):
            self.assertTrue(
                private_files.is_private_regular_file(
                    metadata(0o600, uid=1000, gid=2000), platform_name="posix"
                )
            )
            self.assertTrue(
                private_files.is_private_regular_file(
                    metadata(0o640, uid=0, gid=2000), platform_name="posix"
                )
            )
            self.assertFalse(
                private_files.is_private_regular_file(
                    metadata(0o640, uid=1000, gid=2000), platform_name="posix"
                )
            )
            self.assertFalse(
                private_files.is_private_regular_file(
                    metadata(0o640, uid=0, gid=3000), platform_name="posix"
                )
            )
            self.assertFalse(
                private_files.is_private_regular_file(
                    metadata(0o660, uid=0, gid=2000), platform_name="posix"
                )
            )
            self.assertFalse(
                private_files.is_private_regular_file(
                    metadata(0o644, uid=0, gid=2000), platform_name="posix"
                )
            )
            self.assertFalse(
                private_files.is_private_regular_file(
                    metadata(0o4600, uid=1000, gid=2000), platform_name="posix"
                )
            )

    def test_rejects_non_regular_files(self) -> None:
        metadata = cast(
            os.stat_result,
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o600, st_uid=0, st_gid=0),
        )
        self.assertFalse(private_files.is_private_regular_file(metadata, platform_name="posix"))


if __name__ == "__main__":
    unittest.main()
