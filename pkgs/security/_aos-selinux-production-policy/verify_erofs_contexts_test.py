# SPDX-License-Identifier: GPL-2.0-or-later
"""Regression tests for native EROFS SELinux xattr verification."""

from __future__ import annotations

import stat
import unittest

import verify_erofs_contexts


class RecordParsingTest(unittest.TestCase):
    """Covers the versioned marker's present, absent, and malformed states."""

    def test_present_record_preserves_trailing_nul(self) -> None:
        record = verify_erofs_contexts.parse_record(
            b"human output\n"
            b"EROFS_XATTR_V1\tmode=0100644\tstatus=present\t"
            b"value=73797374656d5f753a6f626a6563745f723a6574635f7400\n"
        )
        self.assertEqual(record.mode, stat.S_IFREG | 0o644)
        self.assertEqual(record.value, b"system_u:object_r:etc_t\x00")

    def test_absent_record_is_distinct(self) -> None:
        record = verify_erofs_contexts.parse_record(
            b"EROFS_XATTR_V1\tmode=0040755\tstatus=absent\tvalue=-\n"
        )
        self.assertIsNone(record.value)
        verify_erofs_contexts.verify_record(record, "/proc", "directory", None)

    def test_missing_marker_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            verify_erofs_contexts.VerificationError, "expected one"
        ):
            verify_erofs_contexts.parse_record(b"Path : /etc\n")

    def test_truncated_hexadecimal_value_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            verify_erofs_contexts.VerificationError, "hexadecimal"
        ):
            verify_erofs_contexts.parse_record(
                b"EROFS_XATTR_V1\tmode=0100644\tstatus=present\tvalue=0\n"
            )

    def test_unterminated_context_matches_erofs_utils_writer(self) -> None:
        record = verify_erofs_contexts.XattrRecord(
            stat.S_IFREG | 0o644,
            b"system_u:object_r:etc_t",
        )
        verify_erofs_contexts.verify_record(
            record,
            "/etc/sample",
            "regular",
            "system_u:object_r:etc_t",
        )

    def test_wrong_context_is_rejected(self) -> None:
        record = verify_erofs_contexts.XattrRecord(
            stat.S_IFREG | 0o644,
            b"system_u:object_r:usr_t",
        )
        with self.assertRaisesRegex(
            verify_erofs_contexts.VerificationError, "context differs"
        ):
            verify_erofs_contexts.verify_record(
                record,
                "/etc/sample",
                "regular",
                "system_u:object_r:etc_t",
            )

    def test_trailing_nul_is_rejected(self) -> None:
        record = verify_erofs_contexts.XattrRecord(
            stat.S_IFREG | 0o644,
            b"system_u:object_r:etc_t\x00",
        )
        with self.assertRaisesRegex(
            verify_erofs_contexts.VerificationError, "context differs"
        ):
            verify_erofs_contexts.verify_record(
                record,
                "/etc/sample",
                "regular",
                "system_u:object_r:etc_t",
            )


if __name__ == "__main__":
    unittest.main()
