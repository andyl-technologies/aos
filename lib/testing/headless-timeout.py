"""Runs the actual evaluated headless phase with one source-built child."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


def process_exists(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def run_control(root, phases, bash, mode, phase, expected_status, sentinel):
    directory = root / f"{phase}-{mode}"
    directory.mkdir()
    scratch = directory / "scratch"
    scratch.mkdir()
    kernel = directory / "kernel" / "boot"
    kernel.mkdir(parents=True)
    (kernel / "vmlinux-control").write_bytes(b"not a kernel\n")
    disk = directory / "input.img"
    disk.write_bytes(b"not a rootfs\n")
    child_pid_file = directory / "child.pid"
    output = directory / "output"
    environment = os.environ | {
        "TMPDIR": str(scratch),
        "KERNEL": str(kernel.parent),
        "ROOTFS": str(disk),
        "out": str(output),
        "HEADLESS_CONTROL_MODE": mode,
        "HEADLESS_CONTROL_PID": str(child_pid_file),
    }

    started = time.monotonic()
    with (directory / "stdout.log").open("wb") as stdout, (
        directory / "stderr.log"
    ).open("wb") as stderr:
        completed = subprocess.run(
            [bash, "-x", phases[phase]],
            cwd=directory,
            env=environment,
            stdout=stdout,
            stderr=stderr,
            timeout=45,
            check=False,
        )
    elapsed = time.monotonic() - started

    assert completed.returncode == expected_status, (phase, mode, completed.returncode)
    assert sentinel.poll() is None, "unrelated sentinel was terminated"
    child_pid = int(child_pid_file.read_text())
    assert not process_exists(child_pid), f"owned child remains: {child_pid}"
    trace = (directory / "stderr.log").read_text()
    reader_ids = re.findall(r"^\+ SERIAL_MIRROR_PID=([0-9]+)$", trace, re.MULTILINE)
    assert len(reader_ids) == 1, "actual serial reader identity absent"
    reader_pid = int(reader_ids[0])
    assert not process_exists(reader_pid), f"owned serial reader remains: {reader_pid}"
    # The original reader is gone; omit its test-owned FIFO from store output.
    (scratch / "serial.pipe").unlink()
    stdout = (directory / "stdout.log").read_text()
    firecracker_status = 0 if mode in ("no-marker", "contradictory") else expected_status
    assert f"Firecracker exited with code: {firecracker_status}" in stdout

    if expected_status == 0:
        assert (output / "result").read_text() == "PASS\n"
        assert (output / "serial.log").is_file()
        assert (output / "fc.log").is_file()
    else:
        assert not output.exists(), "failed exit published a success output"
        assert (scratch / "serial.log").is_file()
        assert (scratch / "fc.log").is_file()
    if expected_status in (124, 137):
        assert "TEST_RESULT:PASS" in (scratch / "serial.log").read_text()
        assert elapsed >= (16 if mode == "ignore-term" else 1)
    if mode == "slow-pass":
        assert elapsed >= 3, "unset deadline unexpectedly shortened the child"
    if mode == "contradictory":
        serial = (scratch / "serial.log").read_text()
        assert "TEST_RESULT:PASS\nTEST_RESULT:FAIL\n" in serial

    return {
        "phase": phase,
        "mode": mode,
        "status": completed.returncode,
        "elapsed_seconds": elapsed,
        "owned_child_pid": child_pid,
        "owned_reader_pid": reader_pid,
        "owned_child_and_reader_gone": True,
        "unrelated_sentinel_alive": True,
    }


def main():
    configuration = json.loads(Path(sys.argv[1]).read_text())
    root = Path.cwd() / "controls"
    root.mkdir()
    sentinel_environment = os.environ | {
        "HEADLESS_CONTROL_MODE": "sentinel",
        "HEADLESS_CONTROL_PID": str(root / "sentinel.pid"),
    }
    sentinel = subprocess.Popen(
        [configuration["child"]], env=sentinel_environment,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    cases = [
        ("pass", "default", 0),
        ("slow-pass", "null", 0),
        ("pass", "bounded", 0),
        ("pass", "pinned", 0),
        ("hang", "bounded", 124),
        ("hang", "pinned", 124),
        ("ignore-term", "bounded", 137),
        ("nonzero", "bounded", 7),
        ("nonzero", "default", 7),
        ("no-marker", "bounded", 1),
        ("contradictory", "bounded", 1),
    ]
    try:
        results = [run_control(
            root, configuration["phases"], configuration["bash"],
            mode, phase, status, sentinel,
        ) for mode, phase, status in cases]
    finally:
        sentinel.terminate()
        sentinel.wait(timeout=5)
    assert not process_exists(sentinel.pid), "owned sentinel was not reaped"

    numeric_results = []
    for phase in ("fractional", "tiny"):
        script = Path(configuration["phases"][phase]).read_text()
        commands = re.findall(
            r"(/nix/store/[^\s]+/bin/timeout) --foreground -k 15 ([^\s]+) ",
            script,
        )
        assert len(commands) == 1, "actual numeric timeout command absent"
        timeout, duration = commands[0]
        pid_file = root / f"{phase}.pid"
        environment = os.environ | {
            "HEADLESS_CONTROL_MODE": "hang",
            "HEADLESS_CONTROL_PID": str(pid_file),
        }
        completed = subprocess.run(
            [timeout, "--foreground", "-k", "15", duration, configuration["child"]],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
        assert completed.returncode == 124, (phase, duration, completed.returncode)
        # A tiny deadline can expire before the child publishes its identity.
        if pid_file.exists():
            assert not process_exists(int(pid_file.read_text())), "numeric child remains"
        numeric_results.append({"phase": phase, "duration": duration, "status": 124})

    report = {
        "scope": "source-built single-process controls; no VM or KVM execution",
        "controls": results,
        "pass_then_fail_exit_zero_refused": True,
        "sentinel_reaped_after_controls": True,
        "numeric_timeout_controls": numeric_results,
    }
    Path("controls.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"{len(results)} evaluated headless controls passed")
    print("PASS-then-FAIL/exit0 is refused")
    print(f"{len(numeric_results)} evaluated numeric timeout controls passed")


if __name__ == "__main__":
    main()
