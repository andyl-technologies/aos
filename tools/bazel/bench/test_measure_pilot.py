"""Checks measurement failures and cleanup without starting a JVM."""

import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "metadata"))
import measure_pilot


class MeasurementTests(unittest.TestCase):
    def test_failed_shutdown_does_not_skip_other_servers_or_mask_the_sample_failure(self):
        def fail_measurement(*arguments):
            arguments[-1].extend([["launcher", "first"], ["launcher", "second"]])
            raise ValueError("original measurement failure")

        with (
            patch.object(measure_pilot, "measure_series", side_effect=fail_measurement),
            patch.object(measure_pilot.subprocess, "run", side_effect=[subprocess.CalledProcessError(1, "first"), None]) as shutdown,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaisesRegex(ValueError, "original measurement failure"):
                measure_pilot.run_series({}, "bazel-server", 0, None, None)
        self.assertEqual(shutdown.call_count, 2)

    def test_failed_shutdown_rejects_an_otherwise_successful_measurement(self):
        def finish_measurement(*arguments):
            arguments[-1].extend([["launcher", "first"], ["launcher", "second"]])
            return []

        with (
            patch.object(measure_pilot, "measure_series", side_effect=finish_measurement),
            patch.object(measure_pilot.subprocess, "run", side_effect=[subprocess.CalledProcessError(1, "first"), None]) as shutdown,
        ):
            with self.assertRaisesRegex(RuntimeError, "private server shutdown failed"):
                measure_pilot.run_series({}, "bazel-server", 0, None, None)
        self.assertEqual(shutdown.call_count, 2)

    def test_worktree_copy_excludes_execution_trees_and_preserves_the_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "lib.rs").write_text("source")
            (source / "lib.rs").chmod(0o444)
            (source / "target").mkdir()
            (source / "target/artifact").write_text("cached output")
            (source / "bazel-out").symlink_to(source / "target", target_is_directory=True)

            measure_pilot.copy_workspace(source, root / "copy")

            self.assertEqual((root / "copy/lib.rs").read_text(), "source")
            self.assertFalse((root / "copy/target").exists())
            self.assertFalse((root / "copy/bazel-out").exists())
            self.assertEqual((source / "lib.rs").stat().st_mode & 0o777, 0o444)

    def test_failed_child_rejects_the_sample(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stderr(io.StringIO()):
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "measurement command failed \\(3\\)"):
                measure_pilot.measure([sys.executable, "-c", "raise SystemExit(3)"], root, {}, root / "command.log")


if __name__ == "__main__":
    unittest.main()
