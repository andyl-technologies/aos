"""Observe one dedicated process window without inventing isolate accounting.

Linux CPU counters cover every thread in the selected workerd process. Resident
high-water memory covers that process's entire lifetime, including startup and
other isolates. These are conservative process envelopes, not platform CPU
charging, heap measurements, or a claim of the Workers isolate memory limit.
The actual queue wrapper and production events must establish invocation and
original identity separately before a window can be attributed.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import time


MAX_SAMPLES = 12001
MAX_FILE_BYTES = 8 * 1024 * 1024
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _read(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        body = os.read(descriptor, maximum + 1)
        if len(body) > maximum:
            raise ValueError("process observation exceeds its bound")
        return body
    finally:
        os.close(descriptor)


def process_identity(pid, executable):
    """Read an owned process's exact lifetime, executable and argument digest."""
    if type(pid) is not int or pid <= 0:
        raise ValueError("process PID differs")
    directory = Path("/proc") / str(pid)
    fields = _read(directory / "stat", 8192).decode().rpartition(") ")[2].split()
    if len(fields) < 22 or fields[0] == "Z":
        raise ValueError("process is not live")
    target = Path(executable).resolve(strict=True)
    if directory.stat().st_uid != os.getuid() or (directory / "exe").resolve(strict=True) != target:
        raise ValueError("process owner or executable differs")
    arguments = _read(directory / "cmdline", 65536)
    with target.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    return {"pid": pid, "ownerUid": os.getuid(), "startTicks": int(fields[19]),
            "executable": str(target), "executableSha256": digest,
            "argumentsSha256": hashlib.sha256(arguments).hexdigest()}


def process_sample(identity):
    """Read actual CPU and resident-memory counters and reject lifetime drift."""
    directory = Path("/proc") / str(identity["pid"])
    started = time.monotonic_ns()
    started_unix = time.time_ns() // 1000000
    fields = _read(directory / "stat", 8192).decode().rpartition(") ")[2].split()
    arguments = _read(directory / "cmdline", 65536)
    if (len(fields) < 22 or fields[0] == "Z" or int(fields[19]) != identity["startTicks"]
            or directory.stat().st_uid != identity["ownerUid"]
            or str((directory / "exe").resolve(strict=True)) != identity["executable"]
            or hashlib.sha256(arguments).hexdigest() != identity["argumentsSha256"]):
        raise ValueError("sampled process lifetime or arguments changed")
    status = _read(directory / "status", 16384).decode()
    memory = {}
    for field in ("VmRSS", "VmHWM", "VmSize"):
        match = re.search(r"^" + field + r":\s+([0-9]+) kB$", status, re.MULTILINE)
        memory[field] = int(match[1]) * 1024 if match else None
    return {"atUnixStartedMillis": started_unix, "atUnixMillis": time.time_ns() // 1000000,
            "monotonicStartedNs": started, "monotonicFinishedNs": time.monotonic_ns(),
            "userTicks": int(fields[11]), "systemTicks": int(fields[12]),
            "residentBytes": memory["VmRSS"], "lifetimeResidentHighWaterBytes": memory["VmHWM"],
            "virtualBytes": memory["VmSize"]}


def collect_process_window(identity, duration_seconds, interval_millis):
    """Collect a bounded dedicated-process window, preserving partial failure."""
    if (not 0 < duration_seconds <= 600 or not 50 <= interval_millis <= 1000
            or duration_seconds * 1000 / interval_millis + 2 > MAX_SAMPLES):
        raise ValueError("process observation duration or sample bound differs")
    report = {"version": 1, "process": identity, "ticksPerSecond": os.sysconf("SC_CLK_TCK"),
              "samples": [], "terminal": "collecting", "isolateMemoryBytes": None,
              "platformCpuMillis": None,
              "scope": "owned process counters; invocation attribution is a separate validated join"}
    deadline = time.monotonic() + duration_seconds
    try:
        while True:
            report["samples"].append(process_sample(identity))
            if time.monotonic() >= deadline:
                report["terminal"] = "completed"
                break
            time.sleep(min(interval_millis / 1000, max(0, deadline - time.monotonic())))
    except (OSError, ValueError, IndexError):
        # The caller retains this incomplete prefix; disappearance is not zero.
        report["terminal"] = "process_observation_failed"
    return report


def invocation_process_envelope(observation, started_millis, finished_millis):
    """Bound process CPU around an independently joined whole invocation.

    Sampling may contain work before/after the invocation. CPU is an upper
    envelope with two ticks of quantization reserve. Memory is the process's
    lifetime resident high-water, not an invocation heap or per-isolate limit.
    Missing boundary samples or process failure leave every derived metric null.
    """
    result = {"wholeInvocationWallMillis": None, "processCpuUpperMillis": None,
              "processLifetimeResidentHighWaterBytes": None,
              "isolateMemoryBytes": None, "platformCpuMillis": None,
              "unresolvedPlatformFacts": ["per_isolate_memory", "charged_invocation_cpu"],
              "unresolved": True,
              "scope": "whole wrapper invocation wall; enclosing process CPU and lifetime RSS envelopes"}
    if (type(started_millis) is not int or type(finished_millis) is not int
            or not 0 <= started_millis <= finished_millis
            or observation.get("terminal") != "completed"):
        return result
    samples = observation.get("samples", [])
    rate = observation.get("ticksPerSecond")
    if (not 2 <= len(samples) <= MAX_SAMPLES or type(rate) is not int or rate <= 0):
        return result
    try:
        previous = None
        for sample in samples:
            for field in ("atUnixStartedMillis", "atUnixMillis", "monotonicStartedNs",
                          "monotonicFinishedNs", "userTicks", "systemTicks"):
                if type(sample[field]) is not int or sample[field] < 0:
                    return result
            if (sample["monotonicStartedNs"] > sample["monotonicFinishedNs"]
                    or sample["atUnixStartedMillis"] > sample["atUnixMillis"]):
                return result
            if previous and (sample["atUnixStartedMillis"] < previous["atUnixMillis"]
                    or sample["monotonicStartedNs"] <= previous["monotonicFinishedNs"]
                    or any(sample[field] < previous[field] for field in ("userTicks", "systemTicks"))):
                return result
            if previous:
                utc_delta = sample["atUnixStartedMillis"] - previous["atUnixStartedMillis"]
                monotonic_delta = (sample["monotonicStartedNs"] - previous["monotonicStartedNs"]) / 1000000
                if abs(utc_delta - monotonic_delta) > 5:
                    return result
            previous = sample
        before = [sample for sample in samples if sample["atUnixMillis"] <= started_millis]
        # CPU reads happen inside each bracket. Select the last bracket wholly
        # before entry and the first wholly after exit, never a crossing read.
        after = [sample for sample in samples if sample["atUnixStartedMillis"] >= finished_millis]
        if not before or not after:
            return result
        first, last = before[-1], after[0]
        # UTC cannot silently stand in for monotonic duration after a clock step.
        elapsed_utc = last["atUnixStartedMillis"] - first["atUnixStartedMillis"]
        elapsed_mono = (last["monotonicStartedNs"] - first["monotonicStartedNs"]) / 1000000
        if abs(elapsed_utc - elapsed_mono) > 5:
            return result
        ticks = sum(last[field] - first[field] for field in ("userTicks", "systemTicks"))
        memory = [sample["lifetimeResidentHighWaterBytes"] for sample in samples]
        if any(value is not None and (type(value) is not int or value < 0) for value in memory):
            return result
        high_water = max(memory) if all(value is not None for value in memory) else None
        result.update(wholeInvocationWallMillis=finished_millis-started_millis,
                      processCpuUpperMillis=((ticks+2)*1000 + rate-1)//rate,
                      processLifetimeResidentHighWaterBytes=high_water, unresolved=False)
    except (KeyError, TypeError, ValueError):
        pass
    return result


def foreground_comparison(foreground, latest_at_dispatch, settlement_seconds,
                          measured_verification_millis):
    """Compare actual verification wall time with the retained original budget.

    ``latest_at_dispatch`` must be the actual qualified conservative clock value,
    already including uncertainty; it is not an arbitrary configured timeout.
    This comparison proves no foreground execution or CPU/memory admissibility.
    """
    if (set(foreground) != {"invocationId", "issuedAt", "expiresAt"}
            or not isinstance(foreground["invocationId"], str)
            or not DIGEST.fullmatch(foreground["invocationId"])):
        raise ValueError("foreground original differs")
    def wire(value):
        if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,19}", value):
            raise ValueError("foreground wire time differs")
        return int(value)
    issued, expiry = wire(foreground["issuedAt"]), wire(foreground["expiresAt"])
    if (not 0 < expiry-issued <= 30 or type(latest_at_dispatch) is not int
            or not issued <= latest_at_dispatch < expiry
            or type(settlement_seconds) is not int or settlement_seconds <= 0
            or type(measured_verification_millis) is not int or measured_verification_millis < 0):
        raise ValueError("foreground observed time or reserve differs")
    remaining = max(0, expiry-latest_at_dispatch-settlement_seconds)*1000
    return {"invocationDigest": foreground["invocationId"],
            "remainingVerificationBudgetMillis": remaining,
            "measuredVerificationMillis": measured_verification_millis,
            "aboveObservedForegroundBudget": measured_verification_millis > remaining,
            "scope": "actual conservative original wall budget comparison; no foreground execution claim"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--start-ticks", type=int, required=True)
    parser.add_argument("--duration-seconds", type=float, required=True)
    parser.add_argument("--interval-millis", type=int, default=100)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    identity = process_identity(args.pid, args.executable)
    if identity["startTicks"] != args.start_ticks:
        raise ValueError("selected process lifetime changed before collection")
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        observation = collect_process_window(identity, args.duration_seconds, args.interval_millis)
        body = (json.dumps(observation, separators=(",", ":")) + "\n").encode()
        if len(body) > MAX_FILE_BYTES:
            raise ValueError("process observation exceeds its output bound")
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(body)
            output.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if observation["terminal"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
