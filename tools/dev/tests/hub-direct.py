"""Checks failure propagation and descendant cleanup in the fast Direct loop."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest


specification = importlib.util.spec_from_file_location(
    "hub_direct", Path(__file__).resolve().parents[1] / "hub-direct.py")
runner = importlib.util.module_from_spec(specification)
specification.loader.exec_module(runner)


class PhaseTests(unittest.TestCase):
    def run_check(self, root, program, timeout=5):
        results = []
        with contextlib.redirect_stdout(io.StringIO()):
            runner.run_phase("probe", [sys.executable, "-c", program], root, results, timeout=timeout)
        return results

    def test_failure_retains_output_and_cannot_report_success(self):
        with tempfile.TemporaryDirectory(prefix="aos-direct-runner-", dir="/tmp") as directory:
            root = Path(directory)
            with self.assertRaises(runner.CheckFailure):
                self.run_check(root, "print('private failure detail'); raise SystemExit(7)")

            result = json.loads((root / "results.json").read_text())[0]
            self.assertFalse(result["passed"])
            self.assertFalse(result["timedOut"])
            self.assertIn("private failure detail", (root / "probe.log").read_text())

    def test_timeout_kills_the_spawned_runtime_too(self):
        with tempfile.TemporaryDirectory(prefix="aos-direct-runner-", dir="/tmp") as directory:
            root = Path(directory)
            pid_file = root / "child.pid"
            program = (
                "import subprocess,sys,time; from pathlib import Path; "
                "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
                f"Path({str(pid_file)!r}).write_text(str(child.pid)); time.sleep(60)"
            )
            with self.assertRaises(runner.CheckFailure):
                self.run_check(root, program, timeout=0.5)

            result = json.loads((root / "results.json").read_text())[0]
            self.assertTrue(result["timedOut"])
            child = Path("/proc") / pid_file.read_text()
            deadline = time.monotonic() + 2
            while child.exists():
                try:
                    state = (child / "stat").read_text().rsplit(")", 1)[1].split()[0]
                except FileNotFoundError:
                    break
                if state == "Z":
                    break
                self.assertLess(time.monotonic(), deadline, "runtime survived its phase deadline")
                time.sleep(0.01)

    def test_disk_exhaustion_stops_even_if_command_exits_zero(self):
        with tempfile.TemporaryDirectory(prefix="aos-direct-runner-", dir="/tmp") as directory:
            root = Path(directory)
            with self.assertRaises(runner.CheckFailure):
                self.run_check(root, "print('No space left on device')")

            result = json.loads((root / "results.json").read_text())[0]
            self.assertTrue(result["noSpace"])
            self.assertFalse(result["passed"])


if __name__ == "__main__":
    unittest.main()
