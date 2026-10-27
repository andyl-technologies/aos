"""Checks configured registration and exact negative-result validation.

These controls exercise the gate, without compiling or running QEMU fixtures.
"""

import importlib.util
import json
from pathlib import Path
import signal
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "cached_writer_unit", Path(__file__).with_name("qemu-cached-writer-unit.py")
)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class RegistrationTests(unittest.TestCase):
    """Exercises failures which otherwise leave an apparently green subset."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source = Path(self.directory.name)
        self.build = self.source / "build"
        (self.build / "meson-info").mkdir(parents=True)
        (self.build / "config-host.mak").write_text(f"PYTHON={sys.executable} -B\n")
        self.tests = []
        self.targets = {}
        for name, (binary, arguments) in RUNNER.expected_tests().items():
            executable = str(self.build / "tests/unit" / binary)
            self.tests.append({
                "name": name,
                "cmd": [sys.executable, str(self.source / "tests/unit/run-crucible-cached-writer.py"),
                        executable, *arguments],
                "suite": ["qemu:unit", "qemu:crucible-cached-writer"],
                "timeout": 15, "protocol": "exitcode", "is_parallel": True,
                "env": {}, "extra_paths": [], "workdir": None,
            })
            self.targets[binary] = {
                "name": binary, "type": "executable", "filename": [executable], "installed": False,
            }

    def publish(self):
        (self.build / "meson-info/intro-tests.json").write_text(json.dumps(self.tests))
        (self.build / "meson-info/intro-targets.json").write_text(json.dumps(list(self.targets.values())))

    def check(self):
        self.publish()
        return RUNNER.registered_tests(self.source, self.build)

    def test_complete_registration_selects_all_eleven_actual_targets(self):
        tests, binaries = self.check()
        self.assertEqual(len(tests), 35)
        self.assertEqual(len(binaries), 11)
        self.assertIn("tests/unit/test-crucible-cached-writer-omission-9", binaries)

    def test_meson_relative_file_arguments_keep_the_real_command(self):
        for test in self.tests:
            test["cmd"][1] = "../tests/unit/run-crucible-cached-writer.py"
            test["cmd"][2] = str(Path(test["cmd"][2]).relative_to(self.build))
        tests, _binaries = self.check()
        self.assertTrue(all(test["cmd"][1].startswith("../") for test in tests))
        for test in self.tests:
            test["cmd"].insert(1, "-B")
        self.check()

    def test_missing_or_duplicate_test_cannot_pass_as_complete_suite(self):
        original = list(self.tests)
        for replacement in (original[:-1], original + [original[0]]):
            self.tests = replacement
            with self.subTest(count=len(replacement)), self.assertRaises(ValueError):
                self.check()

    def test_omission_disposition_cannot_be_replaced_by_broad_failure(self):
        test = next(t for t in self.tests if t["name"].endswith("-omission-3"))
        test["cmd"][-2:] = ["success", ""]
        with self.assertRaises(ValueError):
            self.check()

    def test_wrong_binary_or_missing_configured_target_refuses(self):
        binary = "test-crucible-cached-writer-omission-9"
        del self.targets[binary]
        with self.assertRaises(ValueError):
            self.check()
        self.targets[binary] = {
            "name": binary, "type": "executable",
            "filename": [str(self.build / "unrelated-fixture")], "installed": False,
        }
        with self.assertRaises(ValueError):
            self.check()

    def test_protocol_timeout_environment_and_expected_failure_drift_refuse(self):
        original = dict(self.tests[0])
        for change in (
            {"protocol": "tap"}, {"timeout": 60}, {"should_fail": True},
            {"env": {"SKIP_TEST": "1"}}, {"extra_paths": ["/unrelated"]},
        ):
            self.tests[0] = original | change
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check()


class ChildDispositionTests(unittest.TestCase):
    """Distinguishes intended failures from unrelated assertion/setup errors."""

    def report(self, arguments, status, stdout="", stderr="", **extra):
        return json.dumps({
            "case": arguments[0], "expected": arguments[1],
            "returncode": status, "stdout": stdout, "stderr": stderr, **extra,
        })

    def test_real_success_and_exact_intended_abort_are_distinct(self):
        success = ["cpu-cached", "success"]
        RUNNER.validate_outcome(self.report(success, 0, "completed"), success)
        abort = ["self-cpu", "deadlock"]
        RUNNER.validate_outcome(self.report(
            abort, -signal.SIGABRT,
            stderr="qemu: qemu_thread_ram_writer_enter: Resource deadlock avoided\n",
        ), abort)

    def test_skip_and_setup_failure_never_count_as_expected_negative(self):
        for arguments in (["cpu-cached", "success"], ["self-cpu", "deadlock"],
                          ["self-cpu", "omitted-deadlock", ""]):
            for status in (77, 1, -signal.SIGSEGV):
                with self.subTest(arguments=arguments, status=status), self.assertRaises(ValueError):
                    RUNNER.validate_outcome(self.report(arguments, status, stderr="setup failed"), arguments)
        with self.assertRaises(ValueError):
            RUNNER.validate_outcome(self.report(["cpu-cached", "success"], 0, skipped=True),
                                    ["cpu-cached", "success"])

    def test_wrong_assertion_is_not_a_causal_omission_result(self):
        arguments = ["cpu-promotion", "assertion", "!ram_writer_cpus && ram_writer_io == 1"]
        with self.assertRaises(ValueError):
            RUNNER.validate_outcome(self.report(
                arguments, -signal.SIGABRT, stderr="Assertion `setup_ready' failed.",
            ), arguments)
        RUNNER.validate_outcome(self.report(
            arguments, -signal.SIGABRT,
            stderr="Assertion `!ram_writer_cpus && ram_writer_io == 1' failed.",
        ), arguments)

    def test_partial_or_multiple_wrapper_reports_refuse(self):
        arguments = ["cpu-cached", "success"]
        for text in ("", "{}", "SKIP unavailable", self.report(arguments, 0) * 2):
            with self.subTest(text=text), self.assertRaises(ValueError):
                RUNNER.validate_outcome(text, arguments)

    def test_intentionally_omitted_deadlock_requires_empty_success(self):
        arguments = ["self-cpu", "omitted-deadlock", ""]
        RUNNER.validate_outcome(self.report(arguments, 0), arguments)
        with self.assertRaises(ValueError):
            RUNNER.validate_outcome(self.report(arguments, 0, "SKIP unavailable"), arguments)


if __name__ == "__main__":
    unittest.main()
