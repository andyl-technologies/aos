"""Exercises campaign-mode count validation with actual libtest executables."""

import importlib.util
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "campaign_mode_libtest", Path(__file__).with_name("_phase9-campaign-mode-libtest.py")
)
campaign_mode_libtest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign_mode_libtest)


_FIXTURE_SOURCE = """
#[cfg(not(empty))]
#[test]
fn ordinary() {}

#[cfg(not(empty))]
#[test]
fn another() {}

#[cfg(rejections)]
#[test]
#[ignore]
fn ignored() {}

#[cfg(rejections)]
#[test]
fn failing() {
    panic!("runner must reject unsuccessful exits");
}
"""


class CampaignModeLibtestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        root = Path(cls.directory.name)
        source = root / "fixture.rs"
        source.write_text(_FIXTURE_SOURCE)

        cls.executables = {}
        fixtures = [
            ("ordinary", []),
            ("rejections", ["rejections"]),
            ("empty", ["empty"]),
        ]
        for name, cfg in fixtures:
            executable = root / name
            command = [os.environ["RUSTC"], "--test", str(source), "-o", str(executable)]
            for option in cfg:
                command.extend(["--cfg", option])
            subprocess.run(command, check=True, capture_output=True, text=True)
            cls.executables[name] = str(executable)

    def setUp(self):
        self.invocations = []

    def run_command(self, command, *, timeout):
        self.assertEqual(timeout, 900)
        self.invocations.append(shlex.split(command))
        result = subprocess.run(
            shlex.split(command),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        return result.stdout

    def run_test(self, arguments, expected_count=1, fixture="ordinary", runner=None):
        return campaign_mode_libtest.run_campaign_mode_test(
            self.executables[fixture],
            arguments,
            "fixture_evidence",
            expected_count,
            runner or self.run_command,
        )

    def test_exact_positive_runs_original_selector_and_records_evidence(self):
        command, transcript, evidence = self.run_test(["--exact", "ordinary"])

        self.assertEqual(evidence, "fixture_evidence=PASS")
        self.assertIn("1 passed; 0 failed; 0 ignored", transcript)
        self.assertEqual(
            self.invocations,
            [
                [
                    self.executables["ordinary"],
                    "--exact",
                    "ordinary",
                    "--list",
                    "--format",
                    "terse",
                ],
                [
                    self.executables["ordinary"],
                    "--exact",
                    "ordinary",
                    "--test-threads=1",
                ],
            ],
        )
        self.assertEqual(shlex.split(command), self.invocations[1])

    def test_whole_binary_uses_positive_enumerated_count(self):
        _, transcript, evidence = self.run_test([], expected_count=None)

        self.assertIn("2 passed; 0 failed; 0 ignored", transcript)
        self.assertEqual(evidence, "fixture_evidence=PASS")

    def test_absent_exact_selector_is_rejected_before_execution(self):
        with self.assertRaisesRegex(ValueError, "fixture_evidence: no tests selected"):
            self.run_test(["--exact", "absent"])

        self.assertEqual(len(self.invocations), 1)

    def test_ignored_exact_selector_lists_one_but_runs_zero_and_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "passed=0, failed=0, ignored=1"):
            self.run_test(["--exact", "ignored"], fixture="rejections")

        self.assertEqual(len(self.invocations), 2)

    def test_empty_whole_binary_is_rejected_before_execution(self):
        with self.assertRaisesRegex(ValueError, "no tests selected"):
            self.run_test([], expected_count=None, fixture="empty")

        self.assertEqual(len(self.invocations), 1)

    def test_wrong_declared_count_is_rejected_before_execution(self):
        with self.assertRaisesRegex(ValueError, "listed 1 tests, expected 2"):
            self.run_test(["--exact", "ordinary"], expected_count=2)

        self.assertEqual(len(self.invocations), 1)

    def test_nonpositive_declared_count_is_rejected_before_execution(self):
        with self.assertRaisesRegex(ValueError, "listed 1 tests, expected 0"):
            self.run_test(["--exact", "ordinary"], expected_count=0)

        self.assertEqual(len(self.invocations), 1)

    def test_unsuccessful_runner_exit_cannot_record_evidence(self):
        with self.assertRaises(subprocess.CalledProcessError) as error:
            self.run_test(["--exact", "failing"], fixture="rejections")

        self.assertNotEqual(error.exception.returncode, 0)
        self.assertIn("test result: FAILED", error.exception.output)

    def test_list_only_runner_has_no_execution_summary_and_is_rejected(self):
        def list_only(command, *, timeout):
            arguments = shlex.split(command)
            if "--test-threads=1" in arguments:
                arguments.remove("--test-threads=1")
                arguments.extend(["--list", "--format", "terse"])
            return self.run_command(shlex.join(arguments), timeout=timeout)

        with self.assertRaisesRegex(ValueError, "success summary, found 0"):
            self.run_test(["--exact", "ordinary"], runner=list_only)

        self.assertEqual(len(self.invocations), 2)

    def test_duplicate_success_summary_is_rejected(self):
        # Supplement the subprocess cases with an ambiguous-summary parser case.
        def duplicate_summary(command, *, timeout):
            transcript = self.run_command(command, timeout=timeout)
            if "--test-threads=1" in shlex.split(command):
                transcript += transcript
            return transcript

        with self.assertRaisesRegex(ValueError, "success summary, found 2"):
            self.run_test(["--exact", "ordinary"], runner=duplicate_summary)


if __name__ == "__main__":
    unittest.main()
