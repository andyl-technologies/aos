"""Unit tests for the offline SELinux policy-coverage comparator."""

import tempfile
import unittest
from pathlib import Path

from coverage import CoverageError, check_policy


class PolicyCoverageTests(unittest.TestCase):
    """Exercises fail-closed parsing and ordered-prefix comparison."""

    def check_fixture(self, expected: str, cil: str) -> None:
        """Runs the comparator against one temporary evidence fixture."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            expected_path = root / "expected.tsv"
            cil_path = root / "policy.cil"
            observed_path = root / "observed.tsv"

            expected_path.write_text(expected)
            cil_path.write_text(cil)

            check_policy(expected_path, cil_path, observed_path)

    def test_matching_prefix_allows_trailing_userspace_extension(self) -> None:
        self.check_fixture(
            "socket\tread\twrite\tconnect\n",
            """
            (common socket_common (read write))
            (class socket (connect userspace_extension))
            (classcommon socket socket_common)
            (handleunknown reject)
            """,
        )

    def test_reordered_permission_is_rejected(self) -> None:
        with self.assertRaisesRegex(CoverageError, "ordered permissions differ"):
            self.check_fixture(
                "socket\tread\twrite\tconnect\n",
                """
                (common socket_common (write read))
                (class socket (connect))
                (classcommon socket socket_common)
                (handleunknown reject)
                """,
            )

    def test_missing_class_is_rejected(self) -> None:
        with self.assertRaisesRegex(CoverageError, "missing kernel class"):
            self.check_fixture(
                "socket\tread\n",
                """
                (class file (read))
                (handleunknown reject)
                """,
            )

    def test_duplicate_declaration_is_rejected(self) -> None:
        with self.assertRaisesRegex(CoverageError, "duplicate class declaration"):
            self.check_fixture(
                "socket\tread\n",
                """
                (class socket (read))
                (class socket (read))
                (handleunknown reject)
                """,
            )

    def test_allow_and_deny_handle_unknown_are_rejected(self) -> None:
        for value in ("allow", "deny"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(CoverageError, "handleunknown reject"):
                    self.check_fixture(
                        "socket\tread\n",
                        f"""
                        (class socket (read))
                        (handleunknown {value})
                        """,
                    )


if __name__ == "__main__":
    unittest.main()
