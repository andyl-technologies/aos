"""Check restart ownership fences using disposable source-built processes.

The local Python child is a controlled process fixture, not workerd or a queue
delivery. Authenticated-record inputs below are synthetic refusal cases only.
"""

import copy
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


path = Path(__file__).with_name("_hub-direct-queue-restart.py")
specification = importlib.util.spec_from_file_location("queue_restart", path)
restart = importlib.util.module_from_spec(specification)
specification.loader.exec_module(restart)
restart._closed_review_json = json.loads


def controlled_guest(_machine, python, body, selected, timeout=60):
    """Execute the fixture's unchanged guest program with private controlled inputs."""
    import textwrap

    program = "import json\nselected = json.loads(input())\n" + textwrap.dedent(body)
    result = subprocess.run([python, "-c", program], input=json.dumps(selected),
        text=True, capture_output=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise ValueError("controlled guest program refused")
    return result.stdout


class RestartFences(unittest.TestCase):
    def test_foreign_source_and_changed_inspection_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            run_id = "a" * 64
            identity = {"sourceDigest": "b" * 64, "scriptVersion": "emulated-" + "b" * 64,
                        "publicOrigin": "https://fixture.test"}
            source = {"byte_size": 2147483648, "sha256": "c" * 64}
            value = {"result": {"original": {"runId": run_id, **identity,
                "objects": [{"objectId": "d" * 64, "metadata": False,
                    "byteSize": "2147483648", "expectedSha256": "c" * 64}]},
                "objectId": "d" * 64, "closed": {"controlled": True},
                "attempts": [{"attempt": {"nonce": "e" * 64}, "receipt": None}]}}
            selected = Path(directory) / "00001-inspect-capture.json"
            def observation(document):
                body = json.dumps(document).encode()
                selected.write_bytes(body)
                return {"retained": {"directory": directory,
                    "files": [{"name": selected.name, "sha256": hashlib.sha256(body).hexdigest()}]}}

            self.assertEqual(len(restart.direct_restart_records(
                observation(value), run_id, source, identity)), 1)
            for field in ("runId", "sourceDigest", "scriptVersion", "publicOrigin"):
                changed = copy.deepcopy(value)
                changed["result"]["original"][field] = "foreign"
                with self.assertRaises(ValueError):
                    restart.direct_restart_records(observation(changed), run_id, source, identity)
            changed = observation(value)
            selected.write_bytes(b"changed private observation")
            with self.assertRaises(ValueError):
                restart.direct_restart_records(changed, run_id, source, identity)
            unclosed = copy.deepcopy(value)
            unclosed["result"]["closed"] = None
            self.assertEqual(restart.direct_restart_records(
                observation(unclosed), run_id, source, identity), [])

    def test_stale_child_fence_then_exact_controlled_crash(self):
        if Path("/var/lib/hybrid-worker/acceptance-control.sock").exists():
            self.fail("controlled host test refuses an existing fleet control socket")
        python = str(Path(sys.executable).resolve())
        restart.direct_guest_python = controlled_guest
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configuration = root / "configuration.json"
            configuration.write_bytes(b"{}")
            child_pid_file = root / "child.pid"
            program = (
                "import subprocess,sys,time;from pathlib import Path;"
                "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)']);"
                "Path(sys.argv[1]).write_text(str(child.pid));time.sleep(120)"
            )
            arguments = [python, "-c", program, str(child_pid_file)]
            parent = subprocess.Popen(arguments, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            child_pid = None
            try:
                deadline = time.monotonic() + 10
                while not child_pid_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                child_pid = int(child_pid_file.read_text())
                parent_path = Path("/proc") / str(parent.pid)
                child_path = Path("/proc") / str(child_pid)
                parent_start = parent_path.joinpath("stat").read_text().rpartition(") ")[2].split()[19]
                child_start = child_path.joinpath("stat").read_text().rpartition(") ")[2].split()[19]
                process = {"pid": parent.pid, "startTicks": parent_start, "ownerUid": os.getuid(),
                    "arguments": arguments, "configurationFile": str(configuration),
                    "configurationSha256": hashlib.sha256(configuration.read_bytes()).hexdigest()}
                counters = {"processes": {"workerd": {"pid": child_pid,
                    "start_ticks": int(child_start), "exe": python}}}
                stale = copy.deepcopy(counters)
                stale["processes"]["workerd"]["start_ticks"] += 1
                with self.assertRaises(ValueError):
                    restart.crash_direct_recorded_runtime(None, {"python": python, "workerd": python}, process, stale)
                self.assertIsNone(parent.poll())
                os.kill(child_pid, 0)
                changed = copy.deepcopy(process)
                changed["configurationSha256"] = "0" * 64
                with self.assertRaises(ValueError):
                    restart.crash_direct_recorded_runtime(None, {"python": python, "workerd": python}, changed, counters)
                os.kill(child_pid, 0)
                actual = restart.crash_direct_recorded_runtime(
                    None, {"python": python, "workerd": python}, process, counters)
                self.assertEqual(actual["runtimeSignal"], "SIGKILL")
                self.assertFalse(actual["persistenceRemoved"])
                parent.wait(timeout=5)
                self.assertEqual(parent.returncode, -signal.SIGTERM)
                self.assertEqual(configuration.read_bytes(), b"{}")
            finally:
                if parent.poll() is None:
                    parent.terminate()
                    parent.wait(timeout=5)
                if child_pid is not None:
                    try:
                        fields = (Path("/proc") / str(child_pid) / "stat").read_text().rpartition(") ")[2].split()
                        if fields[19] == child_start and fields[0] != "Z":
                            os.kill(child_pid, signal.SIGTERM)
                    except FileNotFoundError:
                        pass


class RestartReadiness(unittest.TestCase):
    @contextmanager
    def driver(self):
        """Hold a real child until its stdin selects an actual terminal status."""
        python = str(Path(sys.executable).resolve())
        with tempfile.TemporaryDirectory() as directory:
            run_id = "f" * 64
            root = Path(directory) / ("restart-" + run_id)
            root.mkdir(mode=0o700)
            outputs = []
            for name in ("stdout.log", "stderr.log"):
                descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                outputs.append(os.fdopen(descriptor, "wb"))
            program = (
                "import sys;from pathlib import Path;"
                "Path('/proc/self/comm').write_text('ready) (child');"
                "status=int(sys.stdin.readline());"
                "sys.stderr.write('Private inputs must be owner-only regular files within bounds. '"
                "'private-output-sentinel\\n' if status else '');sys.stderr.flush();raise SystemExit(status)"
            )
            try:
                process = subprocess.Popen([python, "-c", program], stdin=subprocess.PIPE,
                    stdout=outputs[0], stderr=outputs[1])
            finally:
                for output in outputs:
                    output.close()
            start = (Path("/proc") / str(process.pid) / "stat").read_bytes().rpartition(b") ")[2].split()[19]
            driver = {"runId": run_id, "root": str(root), "pid": process.pid,
                "ownerUid": os.getuid(), "startTicks": start.decode()}
            previous = getattr(restart, "direct_guest_python", None)
            previous_retainer = getattr(restart, "retain_direct_flow", None)
            restart.direct_guest_python = controlled_guest
            try:
                yield driver, process, {"python": python}
            finally:
                restart.direct_guest_python = previous
                restart.retain_direct_flow = previous_retainer
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=5)
                if process.stdin is not None and not process.stdin.closed:
                    process.stdin.close()

    def exit_without_reaping(self, process, status):
        process.stdin.write(str(status).encode() + b"\n")
        process.stdin.flush()
        process.stdin.close()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            fields = (Path("/proc") / str(process.pid) / "stat").read_bytes().rpartition(b") ")[2].split()
            if fields[0] == b"Z":
                return
            time.sleep(0.01)
        self.fail("controlled child did not reach an actual zombie state")

    def original(self, driver):
        evidence = Path(driver["root"]) / "evidence"
        evidence.mkdir(mode=0o700)
        descriptor = os.open(evidence / "original.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(b'{"controlled":true}\n')
        return evidence / "original.json"

    def test_live_child_without_original_continues_without_reading_logs(self):
        with self.driver() as (driver, process, tools):
            observation = restart.observe_direct_restart_readiness(None, tools, driver)
            self.assertEqual(observation["category"], "waiting_for_original")
            self.assertTrue(observation["custody"])
            self.assertFalse(observation["ready"])
            self.assertIsNone(observation["exitCode"])
            self.assertEqual(observation["stderrReadBytes"], 0)
            self.assertIsNone(observation["stderrEof"])
            self.assertFalse(restart.direct_restart_readiness(None, tools, driver))
            self.assertIsNone(process.poll())

    def test_owned_exit_retains_safe_failure_before_raising(self):
        with self.driver() as (driver, process, tools):
            self.exit_without_reaping(process, 9)
            retained = []
            restart.retain_direct_flow = lambda name, value: retained.append((name, value))
            with self.assertRaises(AssertionError):
                restart.direct_restart_readiness(None, tools, driver)
            name, observation = retained[0]
            self.assertEqual(name, "queue-restart-readiness-failure.json")
            self.assertEqual(observation["category"], "driver_exited_before_original")
            self.assertEqual(observation["processState"], "Z")
            self.assertEqual(observation["exitCode"], 9)
            self.assertEqual(observation["stderrCategory"], "private_input_refused")
            self.assertTrue(observation["stderrEof"])
            self.assertGreater(observation["stderrReadBytes"], 0)
            self.assertNotIn("private-output-sentinel", json.dumps(observation))
            stderr = Path(driver["root"]) / "stderr.log"
            with stderr.open("ab") as output:
                output.write(b"x" * 65537)
            overflow = restart.observe_direct_restart_readiness(None, tools, driver)
            self.assertEqual(overflow["stderrReadBytes"], 65537)
            self.assertFalse(overflow["stderrEof"])
            self.assertEqual(overflow["stderrCategory"], "stderr_bound_exceeded")
            self.assertEqual(process.wait(timeout=5), observation["exitCode"])

    def test_post_start_exit_retains_failure_and_missing_status_stays_unknown(self):
        with self.driver() as (driver, process, tools):
            original = self.original(driver)
            before = original.read_bytes()
            self.exit_without_reaping(process, 9)
            retained = []
            restart.retain_direct_flow = lambda name, value: retained.append(value)

            with self.assertRaises(AssertionError):
                restart.direct_restart_readiness(None, tools, driver)
            observed = retained[-1]
            self.assertEqual(observed["category"], "driver_exited_after_original")
            self.assertTrue(observed["ready"])
            self.assertTrue(observed["custody"])
            self.assertEqual(observed["exitCode"], 9)
            self.assertEqual(observed["stderrCategory"], "private_input_refused")
            self.assertTrue(observed["stderrEof"])
            self.assertNotIn("private-output-sentinel", json.dumps(observed))
            self.assertEqual(original.read_bytes(), before)

            self.assertEqual(process.wait(timeout=5), 9)
            with self.assertRaises(AssertionError):
                restart.direct_restart_readiness(None, tools, driver)
            observed = retained[-1]
            self.assertEqual(observed["category"], "driver_status_unknown_after_original")
            self.assertTrue(observed["ready"])
            self.assertFalse(observed["custody"])
            self.assertIsNone(observed["exitCode"])
            self.assertEqual(observed["stderrCategory"], "private_input_refused")
            self.assertEqual(original.read_bytes(), before)

    def test_reaped_exit_has_unknown_status_and_unknown_observation_refuses(self):
        with self.driver() as (driver, process, tools):
            self.exit_without_reaping(process, 7)
            self.assertEqual(process.wait(timeout=5), 7)
            observation = restart.observe_direct_restart_readiness(None, tools, driver)
            self.assertEqual(observation["category"], "driver_missing")
            self.assertIsNone(observation["exitCode"])
            self.assertFalse(observation["custody"])
            self.assertEqual(observation["stderrCategory"], "private_input_refused")
            restart.direct_guest_python = lambda *args, **kwargs: (_ for _ in ()).throw(
                RuntimeError("private-channel-sentinel"))
            retained = []
            restart.retain_direct_flow = lambda name, value: retained.append(value)
            with self.assertRaises(AssertionError):
                restart.direct_restart_readiness(None, tools, driver)
            self.assertEqual(retained[0]["category"], "readiness_unknown")
            self.assertIsNone(retained[0]["exitCode"])
            self.assertNotIn("private-channel-sentinel", json.dumps(retained))

    def test_reused_pid_refuses_even_with_original_and_does_not_touch_outputs(self):
        with self.driver() as (driver, process, tools):
            original = self.original(driver)
            stale = dict(driver, startTicks=str(int(driver["startTicks"]) + 1))
            before = original.read_bytes()
            observation = restart.observe_direct_restart_readiness(None, tools, stale)
            self.assertEqual(observation["category"], "driver_reused")
            self.assertFalse(observation["ready"])
            self.assertEqual(observation["outputs"], {})
            self.assertEqual(observation["stderrReadBytes"], 0)
            self.assertEqual(original.read_bytes(), before)
            foreign = dict(driver, ownerUid=os.getuid() + 1)
            observation = restart.observe_direct_restart_readiness(None, tools, foreign)
            self.assertEqual(observation["category"], "driver_owner_changed")
            self.assertEqual(observation["outputs"], {})
            self.assertIsNone(process.poll())

    def test_original_ready_survives_normal_child_completion(self):
        with self.driver() as (driver, process, tools):
            self.original(driver)
            self.assertTrue(restart.direct_restart_readiness(None, tools, driver))
            self.exit_without_reaping(process, 0)
            observed = restart.observe_direct_restart_readiness(None, tools, driver)
            self.assertEqual(observed["category"], "original_ready")
            self.assertTrue(observed["custody"])
            self.assertEqual(observed["exitCode"], 0)
            self.assertTrue(restart.direct_restart_readiness(None, tools, driver))
            self.assertEqual(process.wait(timeout=5), 0)
            observation = restart.observe_direct_restart_readiness(None, tools, driver)
            self.assertEqual(observation["category"], "original_ready")
            self.assertTrue(observation["ready"])
            self.assertFalse(observation["custody"])
            self.assertIsNone(observation["exitCode"])
            self.assertEqual(observation["stderrReadBytes"], 0)

    def test_unowned_and_oversized_outputs_are_not_read_or_overwritten(self):
        with self.driver() as (driver, process, tools):
            original = self.original(driver)
            self.exit_without_reaping(process, 4)
            stderr = Path(driver["root"]) / "stderr.log"
            stderr.chmod(0o644)
            observation = restart.observe_direct_restart_readiness(None, tools, driver)
            self.assertEqual(observation["category"], "output_custody_unknown")
            self.assertEqual(observation["stderrReadBytes"], 0)
            self.assertEqual(stderr.stat().st_mode & 0o777, 0o644)
            stderr.chmod(0o600)

            original.unlink()
            original.symlink_to(stderr)
            observation = restart.observe_direct_restart_readiness(None, tools, driver)
            self.assertFalse(observation["ready"])
            self.assertEqual(observation["category"], "output_custody_unknown")
            self.assertTrue(original.is_symlink())
            original.unlink()
            os.link(stderr, original)
            observation = restart.observe_direct_restart_readiness(None, tools, driver)
            self.assertEqual(observation["category"], "output_custody_unknown")
            self.assertEqual(stderr.stat().st_nlink, 2)
            original.unlink()

            descriptor = os.open(original, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.truncate(524289)
            observation = restart.observe_direct_restart_readiness(None, tools, driver)
            self.assertEqual(observation["category"], "output_custody_unknown")
            self.assertFalse(observation["ready"])
            self.assertEqual(original.stat().st_size, 524289)
            self.assertEqual(observation["stderrReadBytes"], 0)
            self.assertEqual(process.wait(timeout=5), 4)


if __name__ == "__main__":
    unittest.main()
