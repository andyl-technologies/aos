"""Retain bounded evidence for the configured io-qcow2-108 VM invocation."""

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import threading
import time


TRACE_LIMIT = 256 * 1024
STDOUT_LIMIT = 2 * 1024 * 1024
REPORT_LIMIT = 8 * 1024 * 1024


class Tail:
    """Keep the newest bytes without allowing an active loop to fill the disk."""

    def __init__(self, limit):
        self.limit = limit
        self.data = bytearray()
        self.total = 0
        self.lock = threading.Lock()

    def append(self, data):
        with self.lock:
            self.total += len(data)
            self.data.extend(data)
            if len(self.data) > self.limit:
                del self.data[:-self.limit]

    def save(self, path):
        with self.lock:
            path.write_bytes(self.data)
            return {"observed_bytes": self.total, "retained_bytes": len(self.data)}


def drain(fd, tail, stop):
    while not stop.is_set():
        ready, _, _ = select.select([fd], [], [], 0.2)
        if ready:
            data = os.read(fd, 65536)
            if data:
                tail.append(data)
            else:
                return


def read_text(path, limit=4096):
    try:
        with path.open("rb") as stream:
            return stream.read(limit).replace(b"\0", b" ").decode(errors="replace")
    except OSError:
        return None


def processes(source, meson_pid):
    """Observe the runner and QEMU children, including a daemonized QSD."""
    rows = {}
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        status = read_text(path / "status")
        if status is None:
            continue
        fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        command = read_text(path / "cmdline") or ""
        rows[int(path.name)] = (path, fields, command)

    selected = {meson_pid}
    while True:
        children = {
            pid for pid, (_, fields, _) in rows.items()
            if int(fields.get("PPid", "0")) in selected
        }
        if children <= selected:
            break
        selected |= children
    selected |= {
        pid for pid, (_, fields, cmd) in rows.items()
        if str(source / "build/qemu-") in cmd
        or fields.get("Name", "").strip().startswith("qemu-storage-d")
    }

    observed = []
    for pid in sorted(selected)[:64]:
        if pid not in rows:
            continue
        path, fields, command = rows[pid]
        descriptors = []
        try:
            for fd in sorted((path / "fd").iterdir(), key=lambda p: int(p.name))[:16]:
                try:
                    descriptors.append({"fd": int(fd.name), "target": os.readlink(fd),
                                        "position": read_text(path / "fdinfo" / fd.name, 512)})
                except OSError:
                    continue
        except OSError:
            pass
        observed.append({"pid": pid, "parent": int(fields.get("PPid", "0")),
                         "state": fields.get("State", "").strip(), "command": command,
                         "wait_channel": read_text(path / "wchan"),
                         "syscall": read_text(path / "syscall"),
                         "kernel_stack": read_text(path / "stack"), "descriptors": descriptors})
    return observed


def retain_report(path, output):
    if not path.is_file():
        return {"present": False}
    size = path.stat().st_size
    if size > REPORT_LIMIT:
        return {"present": True, "bytes": size, "omitted": "report exceeds diagnostic bound"}
    data = path.read_bytes()
    (output / path.name).write_bytes(data)
    return {"present": True, "bytes": size, "sha256": hashlib.sha256(data).hexdigest()}


def retain_iotest_output(source, output):
    """Keep bounded raw output even when Meson terminates a stuck script."""
    reports = {}
    scratch = source / "build/scratch/qcow2-file-108"
    for name in ["108.out.bad", "108.full"]:
        path = scratch / name
        if not path.is_file():
            reports[name] = {"present": False}
            continue
        size = path.stat().st_size
        with path.open("rb") as stream:
            stream.seek(max(0, size - STDOUT_LIMIT))
            data = stream.read(STDOUT_LIMIT)
        (output / (name + ".tail")).write_bytes(data)
        reports[name] = {"present": True, "observed_bytes": size,
                         "retained_bytes": len(data)}
    return reports


def run(source, output):
    output.mkdir(parents=True, exist_ok=True)
    trace_fifo = output / "commands.fifo"
    os.mkfifo(trace_fifo, 0o600)
    trace_fd = os.open(trace_fifo, os.O_RDWR | os.O_NONBLOCK)
    trace = Tail(TRACE_LIMIT)
    stdout = Tail(STDOUT_LIMIT)
    stop = threading.Event()
    trace_reader = threading.Thread(target=drain, args=(trace_fd, trace, stop), daemon=True)
    trace_reader.start()

    script = source / "tests/qemu-iotests/108"
    original = script.read_bytes()
    first_line, body = original.split(b"\n", 1)
    # Only this guest-local diagnostic copy is instrumented. Separate tracing
    # preserves the original TAP stream and command results.
    instrumentation = (
        f'exec 9>"{trace_fifo}"\n'
        "export BASH_XTRACEFD=9\n"
        "export PS4='+${EPOCHREALTIME} ${BASH_SOURCE}:${LINENO}: '\n"
        "set -x\n"
    ).encode()
    modified = first_line + b"\n" + instrumentation + body
    script.write_bytes(modified)

    command = ["./pyvenv/bin/meson", "test", "--no-rebuild", "-t", "2",
               "--setup", "thorough", "--num-processes", "8", "--verbose",
               "--logbase", "io108-diagnostic", "io-qcow2-108"]
    started = time.monotonic()
    snapshots = collections.deque(maxlen=32)
    child = subprocess.Popen(command, cwd=source / "build", stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
    stdout_reader = threading.Thread(target=drain, args=(child.stdout.fileno(), stdout, stop),
                                     daemon=True)
    stdout_reader.start()
    try:
        while child.poll() is None:
            snapshots.append({"elapsed_seconds": time.monotonic() - started,
                              "processes": processes(source, child.pid)})
            trace.save(output / "commands.tail")
            stdout.save(output / "stdout.tail")
            (output / "processes.json").write_text(json.dumps(list(snapshots), indent=2) + "\n")
            time.sleep(2)
        stdout_reader.join(timeout=2)
    finally:
        # Meson owns the existing timeout and child cleanup. This observer
        # never signals the test or adds a second per-test deadline.
        stop.set()
        trace_reader.join(timeout=1)
        os.close(trace_fd)
        trace_fifo.unlink()
        script.write_bytes(original)

    reports = {}
    for suffix in ["txt", "json", "junit.xml"]:
        path = source / "build/meson-logs" / ("io108-diagnostic-thorough." + suffix)
        reports[path.name] = retain_report(path, output)
    results = source / "build/meson-logs/io108-diagnostic-thorough.json"
    rows = [json.loads(line) for line in results.read_text().splitlines()] if results.is_file() else []
    selected = [row for row in rows if row.get("name") == "block - qemu:io-qcow2-108"]
    exact_selection = len(rows) == len(selected) == 1
    report = {
        "selection": "qemu:io-qcow2-108", "qualification": False,
        "meson_command": command, "meson_status": child.returncode,
        "exact_selection": exact_selection,
        "test_result": selected[0].get("result") if exact_selection else "INVALID_SELECTION",
        "elapsed_seconds": time.monotonic() - started,
        "trace": trace.save(output / "commands.tail"),
        "stdout": stdout.save(output / "stdout.tail"), "reports": reports,
        "iotest_output": retain_iotest_output(source, output),
        "instrumentation": {"path": str(script),
                            "before_sha256": hashlib.sha256(original).hexdigest(),
                            "after_sha256": hashlib.sha256(modified).hexdigest(),
                            "change": "separate bounded Bash command trace; original restored"},
    }
    (output / "diagnostic.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "result").write_text(
        "DIAGNOSTIC\nselection=qemu:io-qcow2-108\nqualification=false\n"
        f"meson_status={child.returncode}\ntest_result={report['test_result']}\n"
        "filesystem=ext4\nexecution_environment=qemu-kvm-vm\n"
    )
    print(json.dumps(report, indent=2), flush=True)
    print((output / "commands.tail").read_text(errors="replace")[-8192:], flush=True)
    if not exact_selection:
        raise SystemExit("Focused diagnostic did not execute exactly io-qcow2-108")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    run(arguments.source.resolve(), arguments.output.resolve())
