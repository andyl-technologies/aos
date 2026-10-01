"""Check restart ownership fences using disposable source-built processes.

The local Python child is a controlled process fixture, not workerd or a queue
delivery. Authenticated-record inputs below are synthetic refusal cases only.
"""

import copy
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


if __name__ == "__main__":
    unittest.main()
