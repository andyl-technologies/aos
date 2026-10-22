"""Runs each selected libtest case in a fresh process with bounded concurrency.

The runner consumes declared Bazel artifacts, never Cargo. Timeouts kill the
case's process group. Exclusive cases drain other work before starting, and
zero matches fail rather than accidentally passing an omitted test suite.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET


@dataclass(frozen=True)
class Case:
    """Names a libtest case and its declared scheduling policy."""

    name: str
    ignored: bool
    timeout: float
    exclusive: bool
    slow_period: float = 0
    termination_grace: float = 10
    leak_grace: float = 0.1


@dataclass(frozen=True)
class Result:
    """Records one isolated invocation without treating a crash as a pass."""

    case: Case
    status: str
    elapsed: float
    output: str
    returncode: int | None


def list_cases(binary, ignored=False):
    """Lists libtest cases, rejecting unrecognized or duplicate output."""
    command = [str(binary), "--list", "--format=terse"]
    if ignored:
        command.append("--ignored")
    listing = subprocess.run(command, capture_output=True, text=True, check=True, timeout=30)
    names = []
    for line in listing.stdout.splitlines():
        if line.endswith(": test"):
            names.append(line[:-len(": test")])
        elif line.endswith(": benchmark") or not line:
            continue
        else:
            raise ValueError(f"unexpected libtest listing: {line!r}")
    if len(set(names)) != len(names):
        raise ValueError("duplicate names in libtest listing")
    return sorted(names)


def matches(condition, package, name):
    """Matches the explicit package/name conditions emitted by policy updates."""
    if "package" in condition and condition["package"] != package:
        return False
    if "package_substring" in condition and condition["package_substring"] not in package:
        return False
    if "substring" in condition and condition["substring"] not in name:
        return False
    if "regex" in condition and re.search(condition["regex"], name) is None:
        return False
    return True


def select_cases(binary, package, policy, filters=(), exact=False, ignored="skip", shard=(0, 1), allow_empty=False):
    """Applies filtering, ignored-case selection, policy, and stable sharding."""
    if policy["schema_version"] != 1:
        raise ValueError("unsupported test policy schema")
    names = list_cases(binary)
    ignored_names = set(list_cases(binary, ignored=True))
    if not ignored_names <= set(names):
        raise ValueError("ignored listing contains unknown tests")
    selected = []
    for name in names:
        if filters and not any(name == value if exact else value in name for value in filters):
            continue
        is_ignored = name in ignored_names
        if ignored == "skip" and is_ignored or ignored == "only" and not is_ignored:
            continue
        timeout = policy["default_timeout_seconds"]
        slow_period = policy.get("default_slow_period_seconds", 0)
        termination_grace = policy.get("default_termination_grace_seconds", 10)
        leak_grace = policy.get("default_leak_grace_seconds", 0.1)
        exclusive = False
        # Nextest takes the first matching override for each setting. An
        # override which sets only exclusivity does not erase the timeout.
        timeout_selected = False
        exclusive_selected = False
        for override in policy["overrides"]:
            if not all(matches(condition, package, name) for condition in override["conditions"]):
                continue
            if "timeout_seconds" in override and not timeout_selected:
                timeout = override["timeout_seconds"]
                slow_period = override.get("slow_period_seconds", slow_period)
                termination_grace = override.get("termination_grace_seconds", termination_grace)
                timeout_selected = True
            if "exclusive" in override and not exclusive_selected:
                exclusive = override["exclusive"]
                exclusive_selected = True
        if timeout <= 0:
            raise ValueError("test timeout must be positive")
        selected.append(Case(name, is_ignored, timeout, exclusive, slow_period, termination_grace, leak_grace))
    # Only a declared empty artifact may pass without cases. Filters and
    # ignored-only selections must still catch typos or omitted coverage.
    if not selected and not (allow_empty and not names and not filters and ignored == "skip"):
        raise ValueError("test selection matched zero cases")
    index, count = shard
    if count < 1 or not 0 <= index < count:
        raise ValueError("invalid Bazel test shard")
    return [case for position, case in enumerate(selected) if position % count == index]


def terminate(process, grace_period):
    """Stops a timed out or cancelled case's process group."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait()
        return
    try:
        process.wait(timeout=grace_period)
    except subprocess.TimeoutExpired:
        pass
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


class Executor:
    """Coordinates cancellation and cleanup of the case processes."""

    def __init__(self, binary):
        self.binary = binary
        self.cancelled = threading.Event()

    def cancel(self, *_):
        # Signal handlers only set a flag. Workers perform process cleanup;
        # waiting from a handler can deadlock subprocess's internal locks.
        self.cancelled.set()

    def run(self, case):
        if self.cancelled.is_set():
            return Result(case, "cancelled", 0, "test run cancelled", None)
        command = [str(self.binary), case.name, "--exact", "--nocapture", "--test-threads=1"]
        if case.ignored:
            command.append("--ignored")
        started = time.monotonic()
        # Spool noisy test output to disk instead of keeping an unbounded
        # buffer in the controller. Failed cases retain the final 64 KiB.
        with tempfile.TemporaryFile() as output:
            if self.cancelled.is_set():
                return Result(case, "cancelled", 0, "test run cancelled", None)
            try:
                process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            except OSError as error:
                return Result(case, "failed", time.monotonic() - started, str(error), None)
            status = "passed"
            try:
                deadline = started + case.timeout
                next_slow = started + case.slow_period if case.slow_period > 0 else None
                while process.poll() is None:
                    if self.cancelled.is_set():
                        status = "cancelled"
                        terminate(process, case.termination_grace)
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        status = "timed-out"
                        terminate(process, case.termination_grace)
                        break
                    if next_slow is not None and time.monotonic() >= next_slow:
                        print(f"SLOW: {case.name} ({time.monotonic() - started:.1f}s)", flush=True)
                        next_slow += case.slow_period
                    try:
                        process.wait(timeout=min(0.25, remaining))
                    except subprocess.TimeoutExpired:
                        continue
                if status == "passed" and process.returncode:
                    status = "crashed" if process.returncode < 0 else "failed"
            finally:
                # A completed case must not leave background descendants able
                # to affect the next case. Preserve nextest's default brief
                # allowance for their normal shutdown before killing leaks.
                leak_deadline = time.monotonic() + case.leak_grace
                while True:
                    try:
                        os.killpg(process.pid, 0)
                        if time.monotonic() >= leak_deadline:
                            os.killpg(process.pid, signal.SIGKILL)
                            break
                    except ProcessLookupError:
                        break
                    time.sleep(0.01)
            size = output.tell()
            output.seek(max(0, size - 65536))
            text = output.read().decode("utf-8", errors="replace")
            if size > 65536:
                text = "[earlier output truncated]\n" + text
        return Result(case, status, time.monotonic() - started, text, process.returncode)


def execute(binary, cases, jobs, on_result=lambda result: None):
    """Runs parallel batches separated by exclusive cases, preserving failures."""
    if jobs < 1:
        raise ValueError("test concurrency must be positive")
    executor = Executor(binary)
    previous = {}
    if threading.current_thread() is threading.main_thread():
        for signum in [signal.SIGINT, signal.SIGTERM]:
            previous[signum] = signal.signal(signum, executor.cancel)
    results = []
    try:
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            pending = []

            def drain():
                for future in as_completed(pending):
                    result = future.result()
                    results.append(result)
                    on_result(result)
                pending.clear()

            for case in cases:
                if case.exclusive:
                    drain()
                    result = executor.run(case)
                    results.append(result)
                    on_result(result)
                else:
                    pending.append(pool.submit(executor.run, case))
            drain()
    finally:
        executor.cancel()
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return sorted(results, key=lambda result: result.case.name)


def write_junit(path, package, results):
    """Writes one JUnit case for every isolated invocation."""
    failures = sum(result.status != "passed" for result in results)
    suite = ET.Element("testsuite", name=package, tests=str(len(results)), failures=str(failures),
                       time=f"{sum(result.elapsed for result in results):.6f}")
    for result in results:
        case = ET.SubElement(suite, "testcase", name=result.case.name, classname=package, time=f"{result.elapsed:.6f}")
        if result.status != "passed":
            ET.SubElement(case, "failure", type=result.status, message=f"exit status {result.returncode}").text = result.output
    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--package", required=True)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--filter", action="append", default=[])
    parser.add_argument("--exact", action="store_true")
    parser.add_argument("--allow-empty", action="store_true")
    parser.add_argument("--ignored", choices=["skip", "include", "only"], default="skip")
    options = parser.parse_args()
    policy = json.loads(options.policy.read_text())
    filters = options.filter or ([os.environ["TESTBRIDGE_TEST_ONLY"]] if os.environ.get("TESTBRIDGE_TEST_ONLY") else [])
    shard = (int(os.environ.get("TEST_SHARD_INDEX", 0)), int(os.environ.get("TEST_TOTAL_SHARDS", 1)))
    cases = select_cases(options.binary, options.package, policy, filters, options.exact, options.ignored, shard, options.allow_empty)
    if os.environ.get("TEST_SHARD_STATUS_FILE"):
        Path(os.environ["TEST_SHARD_STATUS_FILE"]).touch()

    def report(result):
        if result.status != "passed":
            print(f"{result.status.upper()}: {result.case.name}\n{result.output}", flush=True)

    results = execute(options.binary, cases, options.jobs, report)
    if os.environ.get("XML_OUTPUT_FILE"):
        write_junit(Path(os.environ["XML_OUTPUT_FILE"]), options.package, results)
    failures = [result.case.name for result in results if result.status != "passed"]
    print(f"{len(results)} isolated tests, {len(failures)} failed", flush=True)
    if failures:
        print("Failed cases: " + ", ".join(failures), flush=True)
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
