"""Exercises whole-body deadlines without starting a virtual machine."""

import json
import os
from pathlib import Path
import signal
import socket
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from aos_test_driver import __main__ as driver


class BodyDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.cwd = Path.cwd()
        self.handler = signal.getsignal(signal.SIGALRM)
        self.timer = signal.setitimer(signal.ITIMER_REAL, 0)

    def tearDown(self):
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, self.handler)
        signal.setitimer(signal.ITIMER_REAL, *self.timer)
        os.chdir(self.cwd)
        self.directory.cleanup()

    def script(self, text):
        path = self.root / "test.py"
        path.write_text(text)
        return path

    def test_sleep_is_interrupted(self):
        started = time.monotonic()
        with self.assertRaisesRegex(driver._TestBodyTimeout, "deadline"):
            driver._run_test(self.script("import time\ntime.sleep(5)"), {}, 0.05)
        self.assertLess(time.monotonic() - started, 1)

    def test_blocking_socket_is_interrupted(self):
        reader, writer = socket.socketpair()
        with reader, writer:
            with self.assertRaises(driver._TestBodyTimeout):
                driver._run_test(self.script("reader.recv(1)"), {"reader": reader}, 0.05)

    def test_ordinary_exception_retry_cannot_swallow_timeout(self):
        script = self.script(
            "import time\nwhile True:\n    try:\n        time.sleep(5)"
            "\n    except Exception:\n        pass"
        )
        with self.assertRaises(driver._TestBodyTimeout):
            driver._run_test(script, {}, 0.05)

    def test_caught_timeout_cannot_report_success(self):
        script = self.script(
            "import time\ntry:\n    time.sleep(5)\nexcept BaseException:\n    pass"
        )
        with self.assertRaises(driver._TestBodyTimeout):
            driver._run_test(script, {}, 0.05)

    def test_fast_success_preserves_globals(self):
        observed = []
        driver._run_test(
            self.script("observed.append('completed')"), {"observed": observed}, 1
        )
        self.assertEqual(observed, ["completed"])
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0, 0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), self.handler)

    def test_prior_alarm_state_is_restored_on_every_exit(self):
        def prior_handler(_signum, _frame):
            self.fail("the previous alarm fired during the test")

        cases = [
            ("pass", None),
            ("raise ValueError('body')", ValueError),
            ("import time\ntime.sleep(5)", driver._TestBodyTimeout),
        ]
        for text, error in cases:
            with self.subTest(text=text):
                signal.signal(signal.SIGALRM, prior_handler)
                signal.setitimer(signal.ITIMER_REAL, 20, 3)
                if error is None:
                    driver._run_test(self.script(text), {}, 0.05)
                else:
                    with self.assertRaises(error):
                        driver._run_test(self.script(text), {}, 0.05)
                remaining, interval = signal.getitimer(signal.ITIMER_REAL)
                self.assertGreater(remaining, 19)
                self.assertLessEqual(remaining, 20)
                self.assertEqual(interval, 3)
                self.assertIs(signal.getsignal(signal.SIGALRM), prior_handler)

    def test_deadline_starts_after_readiness_and_failure_stops_machine(self):
        machine = Mock(name="owned-machine")
        machine.name = "vm"
        manifest = {"name": "deadline", "timeout": 0.05, "machines": [{}]}
        script = self.script("import time\ntime.sleep(5)")

        def ready(_machines, _deadline):
            self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0, 0))
            time.sleep(0.1)

        with (
            patch.object(driver, "_load_manifest", return_value=manifest),
            patch.object(driver, "_build_machine", return_value=machine),
            patch.object(driver, "_wait_agents", side_effect=ready),
            patch.object(driver, "_wait_system_ready"),
            patch.object(driver, "_dump_serial_logs") as dump,
            patch.dict(os.environ, {"TMPDIR": str(self.root)}),
        ):
            result = driver.main(["--manifest", "unused", "--test", str(script)])

        self.assertEqual(result, 1)
        machine.start.assert_called_once()
        machine.stop.assert_called_once()
        machine.shutdown.assert_not_called()
        dump.assert_called_once_with([machine])
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0, 0))

    def test_malformed_manifest_timeouts_are_rejected(self):
        machine = {
            "name": "vm",
            "transport": "qemu",
            "kernel": "kernel",
            "initrd": "initrd",
            "disk": "disk",
            "metadata": None,
            "memory_mib": 256,
            "vcpu_count": 1,
            "kernel_params": [],
            "mac": "mac",
            "ip": "ip",
        }
        path = self.root / "manifest.json"
        for timeout in [None, True, False, 0, -1, "30", [], float("nan"), float("inf"), 10**400]:
            with self.subTest(timeout=str(timeout)):
                path.write_text(
                    json.dumps({"name": "bad", "timeout": timeout, "machines": [machine]})
                )
                with self.assertRaisesRegex(SystemExit, "finite positive"):
                    driver._load_manifest(path)


if __name__ == "__main__":
    unittest.main()
