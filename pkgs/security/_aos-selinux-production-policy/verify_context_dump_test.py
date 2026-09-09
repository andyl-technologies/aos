"""Regression tests for complete EROFS SELinux context verification."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import verify_context_dump


class ContextDumpVerificationTest(unittest.TestCase):
    """Covers dump escaping, structure, and fail-closed comparison."""

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
                "/ 4096 40755 1 0 0 0 0.0 - - - "
                "security.selinux=system_u:object_r:root_t\\x00\n"
                "/etc 4096 40755 1 0 0 0 0.0 - - - "
                "security.selinux=system_u:object_r:etc_t\\x00\n"
                "/etc/space\\x20name 1 100644 1 0 0 0 0.0 - - - "
                "security.selinux=system_u:object_r:etc_t\\x00\n"
                "/etc/tab\\x09name 1 120777 1 0 0 0 0.0 target - - "
                "security.selinux=system_u:object_r:etc_t\\x00\n",
                [
                    {
                        "path": "/",
                        "kind": "directory",
                        "context": "system_u:object_r:root_t",
                    },
                    {
                        "path": "/etc",
                        "kind": "directory",
                        "context": "system_u:object_r:etc_t",
                    },
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
                "/ 4096 40755 1 0 0 0 0.0 - - - "
                "security.selinux=system_u:object_r:root_t\\x00\n"
                "/etc 4096 40755 1 0 0 0 0.0 - - -\n",
                [
                    {
                        "path": "/",
                        "kind": "directory",
                        "context": "system_u:object_r:root_t",
                    },
                    {
                        "path": "/etc",
                        "kind": "directory",
                        "context": "system_u:object_r:etc_t",
                    },
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
                "/ 4096 40755 1 0 0 0 0.0 - - - "
                "security.selinux=system_u:object_r:root_t\\x00\n"
                "/extra 1 100644 1 0 0 0 0.0 - - - "
                "security.selinux=system_u:object_r:usr_t\\x00\n",
                [
                    {
                        "path": "/",
                        "kind": "directory",
                        "context": "system_u:object_r:root_t",
                    }
                ],
            )
            with self.assertRaisesRegex(
                verify_context_dump.VerificationError, "path set differs"
            ):
                verify_context_dump.verify(dump_path, expected_path)

    def test_noncanonical_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dump_path, expected_path = self.write_fixture(
                Path(temporary),
                "/ 4096 40755 1 0 0 0 0.0 - - -\n"
                "/etc/../var 1 100644 1 0 0 0 0.0 - - -\n",
                [],
            )
            with self.assertRaisesRegex(
                verify_context_dump.VerificationError, "not canonical"
            ):
                verify_context_dump.verify(dump_path, expected_path)

    def test_noncanonical_numeric_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dump_path, expected_path = self.write_fixture(
                Path(temporary),
                "/ 04096 40755 1 0 0 0 0.0 - - -\n",
                [],
            )
            with self.assertRaisesRegex(
                verify_context_dump.VerificationError, "noncanonical file size"
            ):
                verify_context_dump.verify(dump_path, expected_path)

    def test_duplicate_path_with_different_kind_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dump_path, expected_path = self.write_fixture(
                Path(temporary),
                "/ 4096 40755 1 0 0 0 0.0 - - -\n"
                "/entry 1 100644 1 0 0 0 0.0 - - -\n"
                "/entry 100 120777 1 0 0 0 0.0 target - -\n",
                [],
            )
            with self.assertRaisesRegex(
                verify_context_dump.VerificationError, "duplicate image path"
            ):
                verify_context_dump.verify(dump_path, expected_path)

    def test_missing_parent_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dump_path, expected_path = self.write_fixture(
                Path(temporary),
                "/ 4096 40755 1 0 0 0 0.0 - - -\n"
                "/missing/child 1 100644 1 0 0 0 0.0 - - -\n",
                [],
            )
            with self.assertRaisesRegex(
                verify_context_dump.VerificationError, "no explicit parent"
            ):
                verify_context_dump.verify(dump_path, expected_path)

    def test_symlink_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dump_path, expected_path = self.write_fixture(
                Path(temporary),
                "/ 4096 40755 1 0 0 0 0.0 - - -\n"
                "/link 100 120777 1 0 0 0 0.0 target - -\n"
                "/link/child 1 100644 1 0 0 0 0.0 - - -\n",
                [],
            )
            with self.assertRaisesRegex(
                verify_context_dump.VerificationError, "non-directory parent"
            ):
                verify_context_dump.verify(dump_path, expected_path)


if __name__ == "__main__":
    unittest.main()
