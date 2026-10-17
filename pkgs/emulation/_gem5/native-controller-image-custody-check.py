# SPDX-License-Identifier: MIT
"""Exercises finite preflight and unchanged-file custody for native witnesses."""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "crucible_native_image_custody", Path(__file__).with_name("native-controller-image-check.py"))
custody = importlib.util.module_from_spec(spec)
spec.loader.exec_module(custody)


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.original_limits = custody.MAX_FILE_BYTES, custody.MAX_TOTAL_BYTES, custody.MAX_FILES
        custody.MAX_FILE_BYTES, custody.MAX_TOTAL_BYTES, custody.MAX_FILES = 16, 24, 2

    def tearDown(self):
        custody.MAX_FILE_BYTES, custody.MAX_TOTAL_BYTES, custody.MAX_FILES = self.original_limits
        self.temporary.cleanup()

    def file(self, name, data=b"original"):
        target = self.root / name
        target.write_bytes(data)
        target.chmod(0o600)
        return target

    def test_symlink_refused_before_destination(self):
        source = self.file("source")
        (self.root / "symbolic").symlink_to(source)
        with self.assertRaises(OSError):
            custody.checked_file(self.root / "symbolic")

    def test_shared_inode_refused(self):
        source = self.file("source")
        os.link(source, self.root / "linked")
        with self.assertRaises(ValueError):
            custody.checked_file(source)

    def test_count_refused_before_copy(self):
        source = self.root / "tree"
        source.mkdir()
        for index in range(3):
            (source / str(index)).write_bytes(b"x")
        destination = self.root / "copy"
        with self.assertRaises(ValueError):
            custody.copy_tree(source, destination)
        self.assertFalse(destination.exists())

    def test_total_refused_before_copy(self):
        source = self.root / "tree"
        source.mkdir()
        for index in range(2):
            (source / str(index)).write_bytes(b"x" * 13)
        destination = self.root / "copy"
        with self.assertRaises(ValueError):
            custody.copy_tree(source, destination)
        self.assertFalse(destination.exists())

    def test_oversize_refused(self):
        with self.assertRaises(ValueError):
            custody.checked_file(self.file("source", b"x" * 17))

    def test_changed_source_refused_before_destination(self):
        source = self.file("source")
        descriptor, original = custody.checked_file(source)
        os.close(descriptor)
        source.write_bytes(b"new extent")
        destination = self.root / "copy"
        with self.assertRaises(ValueError):
            custody.copy_file(source, destination, original, 0o400)
        self.assertFalse(destination.exists())

    def test_fresh_inode_exact_bytes_and_private_mode(self):
        source = self.file("source")
        descriptor, original = custody.checked_file(source)
        os.close(descriptor)
        destination = self.root / "copy"

        measured = custody.copy_file(source, destination, original, 0o400)

        self.assertEqual(measured, custody.digest(source))
        self.assertEqual(destination.read_bytes(), b"original")
        self.assertNotEqual(source.stat().st_ino, destination.stat().st_ino)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o400)


class LeaderCustodyTests(unittest.TestCase):
    def setUp(self):
        self.process = SimpleNamespace(pid=301, returncode=None)
        self.effects = []
        self.patches = [
            patch.object(custody, "kernel_identity", return_value=(301, 301, "1234")),
            patch.object(custody.os, "getpgid", return_value=301),
            patch.object(custody.os, "waitid", return_value=SimpleNamespace(
                si_pid=301, si_code=os.CLD_EXITED, si_status=0)),
            patch.object(custody.os, "killpg", side_effect=lambda *args: self.effects.append("signal")),
            patch.object(custody.os, "waitpid", side_effect=self.waitpid),
            patch.object(custody, "group_members", return_value=[]),
        ]
        for mocked in self.patches:
            mocked.start()
        self.addCleanup(lambda: [mocked.stop() for mocked in reversed(self.patches)])

    def waitpid(self, pid, flags):
        self.effects.append("wait")
        return pid, 0

    def test_failed_initial_enrollment_retries_only_guarded_anchor_custody(self):
        with patch.object(custody, "kernel_identity", side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                try:
                    custody.own_process(self.process)
                finally:
                    custody.reclaim(self.process)
        self.assertEqual(self.effects, [])
        self.assertTrue(custody.reclaim(self.process))
        self.assertEqual(self.effects, ["signal", "wait"])

    def test_exit_observation_does_not_reap_leader(self):
        self.assertEqual(custody.wait_exited(self.process), 0)
        self.assertIsNone(self.process.returncode)
        self.assertEqual(self.effects, [])

    def test_signal_precedes_single_wait_and_double_cleanup_is_effect_free(self):
        custody.own_process(self.process)
        self.assertTrue(custody.reclaim(self.process))
        self.assertTrue(custody.reclaim(self.process))
        self.assertEqual(self.effects, ["signal", "wait"])
        self.assertEqual(self.process.returncode, 0)

    def test_previously_reaped_leader_is_unknown_not_absent(self):
        self.process.returncode = 0
        with self.assertRaises(ValueError):
            custody.reclaim(self.process)
        self.assertEqual(self.effects, [])

    def test_reused_identity_cannot_be_signalled(self):
        custody.own_process(self.process)
        with patch.object(custody, "kernel_identity", return_value=(301, 301, "changed")):
            with self.assertRaises(ValueError):
                custody.reclaim(self.process)
        self.assertEqual(self.effects, [])

    def test_echild_before_signal_never_becomes_cleanup_success(self):
        custody.own_process(self.process)
        with patch.object(custody.os, "waitid", side_effect=ChildProcessError):
            with self.assertRaises(ChildProcessError):
                custody.reclaim(self.process)
        self.assertEqual(self.effects, [])

    def test_failed_wait_retains_unknown_custody_without_second_signal(self):
        custody.own_process(self.process)
        with patch.object(custody.os, "waitpid", side_effect=ChildProcessError):
            with self.assertRaises(ChildProcessError):
                custody.reclaim(self.process)
        with self.assertRaises(ValueError):
            custody.reclaim(self.process)
        self.assertEqual(self.effects, ["signal"])

    def test_census_retry_never_signals_a_retired_group(self):
        custody.own_process(self.process)
        with patch.object(custody, "group_members", side_effect=ValueError("census refused")):
            with self.assertRaises(ValueError):
                custody.reclaim(self.process)
        self.assertTrue(custody.reclaim(self.process))
        self.assertEqual(self.effects, ["signal", "wait"])

    def test_exit_timeout_retry_does_not_repeat_original_signal(self):
        custody.own_process(self.process)
        with patch.object(custody, "wait_exited", side_effect=TimeoutError):
            with self.assertRaises(TimeoutError):
                custody.reclaim(self.process)
        self.assertTrue(custody.reclaim(self.process))
        self.assertEqual(self.effects, ["signal", "wait"])

    def test_foreign_exit_status_retains_unknown_wait_custody(self):
        custody.own_process(self.process)
        with patch.object(custody.os, "waitid", return_value=SimpleNamespace(
                si_pid=999, si_code=os.CLD_EXITED, si_status=0)):
            with self.assertRaises(ValueError):
                custody.reclaim(self.process)
        self.assertEqual(self.effects, [])

    def test_nonterminal_status_never_becomes_exit_or_group_signal(self):
        custody.own_process(self.process)
        with patch.object(custody.os, "waitid", return_value=SimpleNamespace(
                si_pid=301, si_code=os.CLD_STOPPED, si_status=19)):
            with self.assertRaises(ValueError):
                custody.reclaim(self.process)
        self.assertEqual(self.effects, [])


if __name__ == "__main__":
    unittest.main()
