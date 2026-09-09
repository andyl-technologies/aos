"""Regression tests for complete EROFS SELinux context verification."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import verify_context_dump


class ContextDumpVerificationTest(unittest.TestCase):
    """Covers dump escaping, inode kinds, and fail-closed comparison."""

    def write_fixture(
        self, directory: Path, dump: str, entries: list[dict[str, object]]
    ) -> tuple[Path, Path]:
        dump_path = directory / "image.dump"
        expected_path = directory / "expected.json"
        dump_path.write_text(dump, encoding="ascii")
        expected_path.write_text(
            json.dumps({"version": 1, "entries": entries}), encoding="utf-8"
        )
        return dump_path, expected_path

    def test_space_and_tab_paths_and_three_field_contexts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dump_path, expected_path = self.write_fixture(
                Path(temporary),
                "/etc/space\\x20name 1 100644 1 0 0 0 0.0 - - - "
                "security.selinux=system_u:object_r:etc_t\\x00\n"
                "/etc/tab\\x09name 1 120777 1 0 0 0 0.0 target - - "
                "security.selinux=system_u:object_r:etc_t\\x00\n",
                [
                    {
                        "path": "/etc/space name",
                        "kind": "regular",
                        "context": "system_u:object_r:etc_t",
                    },
                    {
                        "path": "/etc/tab\tname",
                        "kind": "symlink",
                        "context": "system_u:object_r:etc_t",
                    },
                ],
            )
            verify_context_dump.verify(dump_path, expected_path)

    def test_missing_label_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dump_path, expected_path = self.write_fixture(
                Path(temporary),
                "/etc 4096 40755 1 0 0 0 0.0 - - -\n",
                [
                    {
                        "path": "/etc",
                        "kind": "directory",
                        "context": "system_u:object_r:etc_t",
                    }
                ],
            )
            with self.assertRaisesRegex(
                verify_context_dump.VerificationError, "contexts differ"
            ):
                verify_context_dump.verify(dump_path, expected_path)

    def test_unexpected_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dump_path, expected_path = self.write_fixture(
                Path(temporary),
                "/extra 1 100644 1 0 0 0 0.0 - - - "
                "security.selinux=system_u:object_r:usr_t\\x00\n",
                [],
            )
            with self.assertRaisesRegex(
                verify_context_dump.VerificationError, "path set differs"
            ):
                verify_context_dump.verify(dump_path, expected_path)


if __name__ == "__main__":
    unittest.main()
