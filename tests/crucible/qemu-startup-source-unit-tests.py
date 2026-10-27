"""Checks runner validation and failure custody without compiling or running QEMU."""

import ctypes
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "startup_unit", Path(__file__).with_name("qemu-startup-source-unit.py")
)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)

PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37


class RegistrationTests(unittest.TestCase):
    """Corroborates the registration predicate without supplying build evidence."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.build = Path(self.directory.name) / "build"
        (self.build / "meson-info").mkdir(parents=True)
        self.test = {
            "name": "test-crucible-startup-source",
            "cmd": [str(self.build / RUNNER.TARGET), "--tap", "-k"],
            "timeout": 60,
            "protocol": "tap",
            "is_parallel": True,
            "env": {"G_TEST_SRCDIR": "/fixture-source/tests/unit"},
        }

    def publish(self, tests):
        (self.build / "meson-info/intro-tests.json").write_text(json.dumps(tests))

    def test_exact_registration_preserves_actual_environment(self):
        self.publish([self.test])
        self.assertEqual(RUNNER.registered_test(self.build), self.test)

    def test_missing_duplicate_or_substituted_registration_refuses(self):
        for tests in ([], [self.test, self.test], [self.test | {"name": "other-unit"}]):
            with self.subTest(tests=tests):
                self.publish(tests)
                with self.assertRaises(ValueError):
                    RUNNER.registered_test(self.build)

    def test_timeout_argv_protocol_or_environment_drift_refuses(self):
        for change in (
            {"timeout": 61},
            {"cmd": [str(self.build / RUNNER.TARGET), "--tap"]},
            {"protocol": "exitcode"},
            {"env": ["G_TEST_SRCDIR=/fixture"]},
            {"extra_paths": ["/foreign-bin"]},
        ):
            with self.subTest(change=change):
                self.publish([self.test | change])
                with self.assertRaises(ValueError):
                    RUNNER.registered_test(self.build)


class TapTests(unittest.TestCase):
    """Rejects partial success while preserving real GLib comments/directives."""

    def test_complete_plan_accepts_front_or_tail_and_preserves_skip(self):
        results = "# Start of fixture tests\nok 1 /first\nok 2 /optional # SKIP unavailable\n"
        for tap in ("1..2\n" + results, results + "1..2\n"):
            self.assertEqual(
                RUNNER.validate_tap(tap), {"planned": 2, "results": 2, "skipped": 1},
            )

    def test_middle_plan_and_explicit_old_version_refuse(self):
        for tap in (
            "ok 1 /first\n1..2\nok 2 /second\n",
            "TAP version 12\n1..1\nok 1 /first\n",
        ):
            with self.subTest(tap=tap), self.assertRaises(ValueError):
                RUNNER.validate_tap(tap)

    def test_explicit_version13_and_unknown_lines_keep_their_grammar(self):
        tap = (
            "TAP version 13\n1..1\n"
            "not\tok 2 is an unknown line\n"
            "  Bail out! is also an unknown line\n"
            "ok 1 /first\n"
        )
        self.assertEqual(
            RUNNER.validate_tap(tap), {"planned": 1, "results": 1, "skipped": 0},
        )

    def test_missing_mismatched_reordered_duplicate_or_empty_rows_refuse(self):
        for tap in (
            "1..2\n",
            "1..2\nok 1 /first\n",
            "1..1\nok 1 /first\nok 2 /extra\n",
            "1..2\nok 2 /second\nok 1 /first\n",
            "1..2\nok 1 /first\nok 1 /duplicate\n",
            "ok 1 /first\n",
            "1..1\n1..1\nok 1 /first\n",
            "1..0 # SKIP all unavailable\n",
            "1..1\nok /without-number\n",
            "1..bad\nok 1 /first\n",
            "1..1\nnot ok 1 /failed # TODO later\n",
            "1..1\nok 1 /first\nBail out!\n",
            "1..18446744073709551615\nok 1 /first\n",
        ):
            with self.subTest(tap=tap), self.assertRaises(ValueError):
                RUNNER.validate_tap(tap)


class EvidenceTests(unittest.TestCase):
    """Checks source ownership and negative process journals using Python alone."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_manifest_binds_source_and_symlink_without_build_output(self):
        (self.root / "source.c").write_text("fixture source")
        (self.root / "build").mkdir()
        (self.root / "build/object.o").write_text("fixture build output")
        (self.root / "external").symlink_to("/does-not-exist", target_is_directory=True)

        manifest = RUNNER.source_manifest(self.root)

        self.assertEqual(set(manifest), {"source.c", "external"})
        self.assertEqual(manifest["external"], {"symlink": "/does-not-exist"})
        self.assertEqual(manifest["source.c"]["sha256"], RUNNER.digest(self.root / "source.c"))

    def test_process_failure_keeps_exact_status_and_output(self):
        with self.assertRaises(SystemExit) as failure:
            RUNNER.run_group(
                [sys.executable, "-c", "print('initiating failure'); raise SystemExit(7)"],
                self.root, os.environ.copy(), 5, self.root, "failed",
            )

        self.assertEqual(failure.exception.code, 7)
        record = json.loads((self.root / "failed.json").read_text())
        self.assertEqual(record["returncode"], 7)
        self.assertFalse(record["timed_out"])
        self.assertIn("initiating failure", (self.root / "failed.stdout").read_text())

    def test_nonzero_and_signal_exit_kill_and_reap_actual_descendant(self):
        # This fixture retains orphaned descendants as our own waitable children.
        # It grants no native authority and restores the process's prior setting.
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        self.assertEqual(libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(previous), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0), 0)
        try:
            for name, exit_code, natural in (("nonzero", 7, 7), ("signal", None, -signal.SIGTERM)):
                with self.subTest(disposition=name):
                    self.run_descendant_failure(name, exit_code, natural)
        finally:
            self.assertEqual(libc.prctl(PR_SET_CHILD_SUBREAPER, previous.value, 0, 0, 0), 0)

    def run_descendant_failure(self, name, exit_code, natural):
        pid_file = self.root / (name + ".pid")
        attempts = self.root / (name + ".attempts")
        child = (
            "import os, time; from pathlib import Path; "
            f"Path({str(pid_file)!r}).write_text(str(os.getpid())); time.sleep(30)"
        )
        terminate = (
            f"raise SystemExit({exit_code})" if exit_code is not None
            else "os.kill(os.getpid(), signal.SIGTERM)"
        )
        parent = (
            "import os, signal, subprocess, sys, time; from pathlib import Path\n"
            f"with Path({str(attempts)!r}).open('a') as journal: "
            "journal.write(str(os.getpid()) + '\\n')\n"
            f"subprocess.Popen([sys.executable, '-c', {child!r}])\n"
            f"while not Path({str(pid_file)!r}).exists(): time.sleep(0.01)\n"
            + terminate
        )
        child_pid = None
        reaped = False
        try:
            with self.assertRaises(SystemExit) as failure:
                RUNNER.run_group(
                    [sys.executable, "-c", parent], self.root, os.environ.copy(),
                    5, self.root, name,
                )
            child_pid = int(pid_file.read_text())
            self.assertEqual(failure.exception.code, natural if natural > 0 else 128 - natural)
            record = json.loads((self.root / (name + ".json")).read_text())
            self.assertEqual(record["returncode"], natural)
            self.assertFalse(record["timed_out"])
            self.assertEqual(len(attempts.read_text().splitlines()), 1)

            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                waited, status = os.waitpid(child_pid, os.WNOHANG)
                if waited:
                    reaped = True
                    self.assertTrue(os.WIFSIGNALED(status))
                    self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                    break
                time.sleep(0.01)
            self.assertTrue(reaped, "actual descendant survived leader failure")
            self.assertEqual(record["leader_returncode"], natural)
            self.assertEqual(record["group_cleanup"], "signal-delivered")
        finally:
            # A failed control must still dispose only this fixture's own child.
            if child_pid is None and pid_file.exists():
                child_pid = int(pid_file.read_text())
            if child_pid is not None and not reaped:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(child_pid, 0)

    def test_timeout_is_terminal_and_does_not_retry(self):
        with self.assertRaises(SystemExit) as failure:
            RUNNER.run_group(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                self.root, os.environ.copy(), 0.1, self.root, "expired",
            )

        self.assertEqual(failure.exception.code, 124)
        record = json.loads((self.root / "expired.json").read_text())
        self.assertTrue(record["timed_out"])
        self.assertLess(record["elapsed_seconds"], 5)
        self.assertEqual(record["timeout_seconds"], 0.1)

    def test_failed_constructor_keeps_no_started_journal(self):
        with self.assertRaises(FileNotFoundError):
            RUNNER.run_group(
                [str(self.root / "absent")], self.root, os.environ.copy(), 5,
                self.root, "not-born",
            )

        record = json.loads((self.root / "not-born.json").read_text())
        self.assertFalse(record["started"])


if __name__ == "__main__":
    unittest.main()
