"""Compare exact TCG boundaries and measured cold/restored continuation costs.

The JSON evidence includes each sample, package identities, CPU affinity, exact
retired count, registers, and RAM SHA-256. Timings are evidence rather than a
portable pass/fail threshold; all semantic witnesses must match across repeats,
QEMU variants, and VMState restore. Run with AOS-built Python and fixture tools.
"""

import argparse
import functools
import hashlib
import json
import os
import re
import socket
import subprocess
import tempfile
import time
from pathlib import Path


class Qmp:
    """Own the request/response stream for a local QEMU process."""

    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(30)
        try:
            self.socket.connect(str(path))
        except OSError:
            self.socket.close()
            raise
        self.stream = self.socket.makefile("rwb", buffering=0)
        self.read()
        self.command("qmp_capabilities")

    def read(self):
        while True:
            line = self.stream.readline()
            if not line:
                raise RuntimeError("QMP stream closed")
            response = json.loads(line)
            if "event" not in response:
                return response

    def command(self, name, arguments=None):
        request = {"execute": name}
        if arguments is not None:
            request["arguments"] = arguments
        self.stream.write((json.dumps(request) + "\r\n").encode())
        response = self.read()
        if "error" in response:
            raise RuntimeError(f"QMP {name}: {response['error']}")
        return response["return"]

    def close(self):
        self.stream.close()
        self.socket.close()


def cpu_seconds(pid):
    """Read process user/system CPU accounting without including other VMs."""
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    ticks = os.sysconf("SC_CLK_TCK")
    return int(fields[11]) / ticks, int(fields[12]) / ticks


def wait_for(process, predicate, description, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        if process.poll() is not None:
            raise RuntimeError(f"QEMU exited while waiting for {description}")
        time.sleep(0.002)
    raise TimeoutError(f"timed out waiting for {description}")


def connect_qmp(process, socket_path, timeout):
    """Wait for the listener, which can become ready after its path exists."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return Qmp(socket_path)
        except (FileNotFoundError, ConnectionRefusedError):
            if process.poll() is not None:
                raise RuntimeError("QEMU exited before its QMP listener was ready")
            time.sleep(0.002)
    raise TimeoutError("timed out waiting for QMP listener readiness")


def command(binary, fixtures, socket_path, stop, incoming, bios):
    result = [
        str(binary), "-nodefaults", "-no-user-config", "-display", "none",
        "-monitor", "none", "-serial", "none", "-no-reboot", "-S",
        "-machine", "pc", "-m", "64M", "-smp", "1",
        "-accel", "sim,thread=single", "-icount",
        "shift=0,align=off,sleep=off,rr_switch_quantum=4096",
        "-cpu", "qemu64,-rdrand,-rdseed",
        "-rtc", "base=2026-01-01T00:00:00,clock=vm", "-seed", "0x0010c004",
        "-bios", str(bios),
        "-plugin", f"{fixtures / 'plugin.so'},stop={stop}",
        "-qmp", f"unix:{socket_path},server=on,wait=off",
    ]
    if incoming:
        result.extend(["-incoming", "defer"])
    return result


def run_boundary(binary, fixtures, stop, directory, label, timeout,
                 restore=None, save=None, bios=None):
    socket_path = directory / f"{label}.sock"
    log_path = directory / f"{label}.log"
    log = log_path.open("w")
    process = subprocess.Popen(
        command(binary, fixtures, socket_path, stop, restore is not None, bios),
        stdout=log, stderr=subprocess.STDOUT,
    )
    qmp = None
    try:
        qmp = connect_qmp(process, socket_path, timeout)
        if restore is not None:
            qmp.command("migrate-incoming", {"uri": f"file:{restore}"})
            wait_for(
                process,
                lambda: qmp.command("query-migrate")["status"] == "completed",
                "incoming VMState", timeout,
            )
        user_before, system_before = cpu_seconds(process.pid)
        started = time.perf_counter()
        qmp.command("cont")

        wait_for(
            process, lambda: qmp.command("query-status")["status"] == "paused",
            "exact stop boundary", timeout,
        )
        seconds = time.perf_counter() - started
        user_after, system_after = cpu_seconds(process.pid)
        registers = qmp.command(
            "human-monitor-command", {"command-line": "info registers"},
        ).strip()
        memory_path = directory / f"{label}.ram"
        qmp.command("pmemsave", {
            "val": 0x7000, "size": 256, "filename": str(memory_path),
        })
        memory = memory_path.read_bytes()
        log.flush()
        stop_pattern = rf"TCG_STOP vcpu=0 raw={stop} tick=([0-9]+) status=0"
        markers = re.findall(stop_pattern, log_path.read_text())
        if len(markers) != 1:
            raise AssertionError(f"missing unique exact stop: {log_path.read_text()}")
        witness = {
            "raw_icount": stop,
            "logical_tick": int(markers[0]),
            "registers": registers,
            "ram_sha256": hashlib.sha256(memory).hexdigest(),
            "ram_prefix_hex": memory[:8].hex(),
        }

        if save is not None:
            qmp.command("migrate", {"uri": f"file:{save}"})
            wait_for(
                process,
                lambda: qmp.command("query-migrate")["status"] == "completed",
                "outgoing VMState", timeout,
            )
        qmp.command("quit")
        process.wait(timeout=10)
        if process.returncode != 0:
            raise RuntimeError(f"QEMU exited {process.returncode}: {log_path.read_text()}")
        return {
            "seconds": seconds,
            "user_seconds": user_after - user_before,
            "system_seconds": system_after - system_before,
            "witness": witness,
        }
    finally:
        if qmp is not None:
            qmp.close()
        if process.poll() is None:
            process.kill()
            process.wait()
        log.close()


@functools.cache
def reference_state(stop, loop_instructions):
    """Evaluate the ROM arithmetic independently of QEMU and its plugin."""
    complete, partial = divmod(stop - 6, loop_instructions)
    accumulator = 0x51F15EED
    for _ in range(complete):
        accumulator = ((accumulator << 13) | (accumulator >> 19)) & 0xFFFFFFFF
        accumulator = ((accumulator ^ 0x9E3779B9) + 0x6D2B79F5) & 0xFFFFFFFF

    memory_accumulator = accumulator if complete else 0
    counter = complete & 0xFFFFFFFF
    memory_counter = counter
    if partial >= 1:
        accumulator = ((accumulator << 13) | (accumulator >> 19)) & 0xFFFFFFFF
    if partial >= 2:
        accumulator ^= 0x9E3779B9
    if partial >= 3:
        accumulator = (accumulator + 0x6D2B79F5) & 0xFFFFFFFF
    if partial >= 4:
        memory_accumulator = accumulator
    if partial >= 5:
        counter = (counter + 1) & 0xFFFFFFFF
    if partial >= 6:
        memory_counter = counter

    memory = memory_accumulator.to_bytes(4, "little") + memory_counter.to_bytes(4, "little")
    return accumulator, counter, memory.hex()


def require_reference(sample, stop, loop_instructions):
    """Check the frozen tick conversion and guest arithmetic against an oracle."""
    witness = sample["witness"]
    accumulator, counter, memory_prefix = reference_state(stop, loop_instructions)
    expected_registers = {"EAX": accumulator, "ECX": counter}
    for name, expected in expected_registers.items():
        observed = re.search(rf"\b{name}=([0-9a-fA-F]+)", witness["registers"])
        if observed is None or int(observed[1], 16) != expected:
            raise AssertionError(f"independent {name} oracle differs: {witness}")
    if witness["logical_tick"] != stop * 50:
        raise AssertionError(f"independent 50-ps tick oracle differs: {witness}")
    if witness["ram_prefix_hex"] != memory_prefix:
        raise AssertionError(f"independent RAM arithmetic oracle differs: {witness}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", action="append", required=True,
                        help="LABEL=/absolute/path/to/qemu-system-x86_64")
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bios", type=Path, help="Optional alternate workload ROM")
    parser.add_argument("--loop-instructions", type=int, choices=(7, 8), default=7,
                        help="Use eight for the optional POST-I/O workload")
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--stop", type=int, default=24_000_000)
    parser.add_argument("--checkpoint", type=int, default=12_000_000)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--cpu", type=int)
    args = parser.parse_args()
    if not 6 < args.checkpoint < args.stop or args.repetitions < 2:
        parser.error("require 6 < checkpoint < stop and at least two repetitions")
    if args.cpu is not None:
        os.sched_setaffinity(0, {args.cpu})

    bios = args.bios or args.fixtures / "bios.bin"
    args.output.mkdir(parents=True, exist_ok=True)
    variants = [entry.split("=", 1) for entry in args.qemu]
    expected = None
    records = []
    metadata = {
        "schema": "crucible.tcg-performance.v1",
        "bios": str(bios),
        "bios_sha256": hashlib.sha256(bios.read_bytes()).hexdigest(),
        "cpu_affinity": sorted(os.sched_getaffinity(0)),
        "stop": args.stop, "checkpoint": args.checkpoint,
        "loop_instructions": args.loop_instructions,
        "ticks_per_instruction": 50,
        "binary_sha256": {
            label: hashlib.sha256(Path(binary).read_bytes()).hexdigest()
            for label, binary in variants
        },
        "fixture_sha256": {
            name: hashlib.sha256((args.fixtures / name).read_bytes()).hexdigest()
            for name in ("bios.bin", "plugin.so")
        },
    }
    # Compute the oracle before timed execution so it cannot perturb VM samples.
    reference_state(args.stop, args.loop_instructions)
    for trial in range(args.repetitions):
        # Interleave variants so machine load drifts do not favor one build.
        trial_variants = variants if trial % 2 == 0 else list(reversed(variants))
        for label, binary in trial_variants:
            with tempfile.TemporaryDirectory(prefix="crucible-tcg-") as temporary:
                directory = Path(temporary)
                cold = run_boundary(
                    Path(binary), args.fixtures, args.stop, directory,
                    "cold", args.timeout, bios=bios,
                )
                vmstate = directory / "checkpoint.vmstate"
                run_boundary(
                    Path(binary), args.fixtures, args.checkpoint, directory,
                    "source", args.timeout, save=vmstate, bios=bios,
                )
                restored = run_boundary(
                    Path(binary), args.fixtures, args.stop, directory,
                    "restored", args.timeout, restore=vmstate, bios=bios,
                )
                for mode, sample in (("cold", cold), ("restored", restored)):
                    require_reference(sample, args.stop, args.loop_instructions)
                    if expected is None:
                        expected = sample["witness"]
                    if sample["witness"] != expected:
                        raise AssertionError(
                            f"deterministic witness differs: {label}, {mode}, {trial}\n"
                            f"expected={expected}\nobserved={sample['witness']}"
                        )
                    record = {"label": label, "binary": binary,
                              "trial": trial, "mode": mode, **sample}
                    records.append(record)
                    print(json.dumps(record), flush=True)
                evidence = {**metadata, "samples": records, "deterministic": True}
                (args.output / "evidence.json").write_text(
                    json.dumps(evidence, indent=2) + "\n",
                )
    print("PASS exact icount, logical tick, register state, and RAM digest match")


if __name__ == "__main__":
    main()
