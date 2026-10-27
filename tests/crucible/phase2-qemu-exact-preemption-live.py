"""Exercise exact QEMU preemption before retirement and across VMState restore."""

import argparse
import json
import re
import socket
import subprocess
import tempfile
import time
from pathlib import Path


class Qmp:
    def __init__(self, path):
        connection = socket.socket(socket.AF_UNIX)
        connection.connect(path)
        self.connection = connection
        self.stream = connection.makefile("rwb", buffering=0)
        self._read()
        self.command("qmp_capabilities")

    def _read(self):
        while True:
            line = self.stream.readline()
            if not line:
                raise RuntimeError("QMP connection closed")
            message = json.loads(line)
            if "event" not in message:
                return message

    def command(self, name, arguments=None):
        request = {"execute": name}
        if arguments is not None:
            request["arguments"] = arguments
        self.stream.write((json.dumps(request) + "\r\n").encode())
        response = self._read()
        if "error" in response:
            raise RuntimeError(f"QMP {name} failed: {response['error']}")
        return response["return"]

    def close(self):
        self.stream.close()
        self.connection.close()


def common_command(binary, plugin, architecture, firmware=None):
    machine = "pc" if architecture == "x86" else "virt"
    command = [
        str(binary), "-machine", machine, "-m", "64M", "-smp", "2",
        "-accel", "sim", "-icount",
        "shift=0,align=off,sleep=off,rr_switch_quantum=256",
        "-nographic", "-no-reboot", "-serial", "none", "-monitor", "none",
    ]
    if architecture == "arm":
        command.extend(["-cpu", "max,pmu=off"])
    if firmware is not None:
        command.extend(["-bios", str(firmware)])
    command.extend(["-plugin", str(plugin)])
    return command


def require_handoff(output):
    expected = "PREEMPTION_HANDOFF from=0 to=1 raw=0 tick=10 retired=0"
    if expected not in output or output.count("PREEMPTION_HANDOFF") != 1:
        raise AssertionError(f"missing unique exact handoff:\n{output}")


def require_rejections(output, tick):
    names = (
        ("before-deadline", -2),
        ("beyond-ceiling", -2),
        ("invalid-window", -2),
        ("unpublished-ceiling", -2),
        ("invalid-kind", -6),
        ("invalid-switch", -4),
        ("invalid-interrupt", -5),
        ("duplicate-pending", -3),
    )
    for name, status in names:
        marker = f"PREEMPTION_REJECT name={name} rc={status} raw=0 tick={tick}"
        if output.count(marker) != 1:
            raise AssertionError(f"missing unique rejection {marker}:\n{output}")


def wait_for_socket(path, process):
    for _ in range(200):
        if path.exists():
            return
        if process.poll() is not None:
            raise RuntimeError("QEMU exited before QMP socket was ready")
        time.sleep(0.025)
    raise TimeoutError("QMP socket was not ready")


def wait_for_migration(qmp, label):
    for _ in range(200):
        status = qmp.command("query-migrate")["status"]
        if status == "completed":
            return
        if status in {"failed", "cancelled"}:
            raise RuntimeError(f"{label} migration ended with {status}")
        time.sleep(0.025)
    raise TimeoutError(f"{label} migration did not complete")


def snapshot_and_restore(arm_binary, plugin, directory, continuation=False):
    socket_path = directory / "source.sock"
    vmstate_path = directory / "pending.vmstate"
    firmware = instruction_firmware(directory, "arm") if continuation else None
    source_command = common_command(arm_binary, plugin, "arm", firmware)
    source_command[-1] += ",mode=snapshot-source"
    if continuation:
        source_command[-1] += ",continuation=on"
    source_command.extend([
        "-qmp", f"unix:{socket_path},server=on,wait=off",
    ])
    source = subprocess.Popen(
        source_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        wait_for_socket(socket_path, source)
        qmp = Qmp(str(socket_path))
        try:
            for _ in range(200):
                if qmp.command("query-status")["status"] == "paused":
                    break
                time.sleep(0.025)
            else:
                raise TimeoutError("source did not pause at tick 7")
            qmp.command("migrate", {"uri": f"file:{vmstate_path}"})
            wait_for_migration(qmp, "source")
            qmp.command("quit")
        finally:
            qmp.close()
        output, _ = source.communicate(timeout=10)
        if source.returncode != 0:
            raise AssertionError(f"snapshot source exited {source.returncode}:\n{output}")
        for marker in (
            "PREEMPTION_ADVANCE status=0 time=7 raw=0 tick=7",
            "PREEMPTION_SUBMIT rc=0 raw=0 tick=7",
            "PREEMPTION_VMSTOP rc=0 raw=0 tick=7",
            "PREEMPTION_REJECT name=past-current rc=-2 raw=0 tick=7",
        ):
            if marker not in output:
                raise AssertionError(f"missing {marker}:\n{output}")
        require_rejections(output, 7)
    finally:
        if source.poll() is None:
            source.kill()
            source.communicate()

    destination_command = common_command(arm_binary, plugin, "arm", firmware)
    destination_command[-1] += ",mode=snapshot-destination"
    if continuation:
        destination_command[-1] += ",continuation=on"
    destination_socket = directory / "destination.sock"
    destination_command.extend([
        "-incoming", f"file:{vmstate_path}",
        "-qmp", f"unix:{destination_socket},server=on,wait=off",
    ])
    destination = subprocess.Popen(
        destination_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        wait_for_socket(destination_socket, destination)
        qmp = Qmp(str(destination_socket))
        try:
            # The QMP socket can accept commands before incoming VMState loads.
            wait_for_migration(qmp, "destination")
            qmp.command("cont")
        finally:
            qmp.close()
        try:
            destination_output, _ = destination.communicate(timeout=10)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(f"destination timed out; output={error.output!r}") from error
    finally:
        if destination.poll() is None:
            destination.kill()
            destination.communicate()
    if destination.returncode != 0:
        raise AssertionError(
            f"snapshot destination exited {destination.returncode}:\n"
            f"{destination_output}"
        )
    if continuation:
        expected = ["PREEMPTION_HANDOFF from=0 to=1 raw=0 tick=10 retired=0",
                    "PREEMPTION_HANDOFF from=1 to=0 raw=0 tick=10 retired=0"]
        actual = [line for line in destination_output.splitlines()
                  if line.startswith("PREEMPTION_HANDOFF ")]
        if actual != expected:
            raise AssertionError(f"restored RR ownership changed:\n{destination_output}")
        require_continuation(destination_output, 1)
        print("PASS continuation case=arm-restore pending-command=true")
    else:
        require_handoff(destination_output)


def interrupt_at_exact_tick(x86_binary, plugin, directory, continuation=False):
    socket_path = directory / "interrupt.sock"
    firmware = instruction_firmware(directory, "x86") if continuation else None
    command = common_command(x86_binary, plugin, "x86", firmware)
    command[-1] += ",mode=continuation-interrupt" if continuation else ",mode=interrupt"
    command.extend(["-qmp", f"unix:{socket_path},server=on,wait=off"])

    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        wait_for_socket(socket_path, process)
        qmp = Qmp(str(socket_path))
        try:
            for _ in range(200):
                if qmp.command("query-status")["status"] == "paused":
                    break
                time.sleep(0.025)
            else:
                raise TimeoutError("commanded interrupt did not pause at tick 10")

            lapic = qmp.command(
                "human-monitor-command", {"command-line": "info lapic 1"}
            )
            if "IRR\t 32 " not in lapic:
                raise AssertionError(f"vCPU 1 LAPIC did not receive vector 32:\n{lapic}")
            qmp.command("cont" if continuation else "quit")
        finally:
            qmp.close()
        output, _ = process.communicate(timeout=10)
        if process.returncode != 0:
            raise AssertionError(f"interrupt run exited {process.returncode}:\n{output}")
        if continuation:
            require_continuation(output)
            if "CONTINUATION_INPUT rc=0 raw=0 tick=1" not in output:
                raise AssertionError(f"input was not admitted before its tick:\n{output}")
            order = [output.index(marker) for marker in (
                "CONTINUATION_INPUT rc=0 raw=0 tick=1",
                "CONTINUATION_BOUNDARY index=1 raw=0 tick=10",
                "PREEMPTION_INTERRUPT_BOUNDARY vcpu=0 raw=0 tick=10 vmstop=0",
                "CONTINUATION_EXEC vcpu=0 number=1 raw=1 tick=99",
            )]
            if order != sorted(order):
                raise AssertionError(f"due input crossed guest retirement:\n{output}")
            print("PASS continuation case=x86-input vector=32 irr-confirmed=true")
        else:
            require_rejections(output, 0)
            if "PREEMPTION_SUBMIT rc=0 raw=0 tick=0" not in output:
                raise AssertionError(f"interrupt command was not admitted:\n{output}")
        for marker in (
            "PREEMPTION_CONTROL_REQUEST rc=0",
            "PREEMPTION_INTERRUPT_BOUNDARY vcpu=0 raw=0 tick=10 vmstop=0",
        ):
            if marker not in output:
                raise AssertionError(f"missing interrupt marker {marker}:\n{output}")
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()


def instruction_firmware(directory, architecture):
    """Create real reset instructions; guest execution owns retirement."""
    path = directory / f"{architecture}.rom"
    if architecture == "x86":
        rom = bytearray(b"\xf4" * 65536)
        # The reset vector executes NOP then JMP back to that NOP in real mode.
        rom[65520:65523] = b"\x90\xeb\xfd"
    else:
        # AArch64 NOP followed by B to the NOP at the reset vector.
        rom = bytearray(b"\x1f\x20\x03\xd5\xff\xff\xff\x17")
    path.write_bytes(rom)
    return path


def require_continuation(output, first=0):
    expected = [(0, 1), (0, 10), (0, 49), (1, 99), (1, 100),
                (2, 150), (2, 151), (3, 201)]
    records = re.findall(
        r"CONTINUATION_BOUNDARY index=(\d+) raw=(\d+) tick=(\d+) executed=(\d+)",
        output,
    )
    actual = [(int(index), int(raw), int(tick), int(executed))
              for index, raw, tick, executed in records]
    wanted = [(index, raw, tick, raw)
              for index, (raw, tick) in enumerate(expected) if index >= first]
    if actual != wanted:
        raise AssertionError(f"fractional continuation changed:\n{output}")
    if output.count("CONTINUATION_EXEC ") != 3:
        raise AssertionError(f"real guest instructions were not executed:\n{output}")
    if first == 0:
        for name in ("continuation-past", "continuation-unpublished"):
            marker = f"PREEMPTION_REJECT name={name} rc=-2 raw=0 tick=1"
            if output.count(marker) != 1:
                raise AssertionError(f"missing immutable refusal {name}:\n{output}")
    print(output, end="")


def fractional_continuation(binary, plugin, architecture, directory):
    firmware = instruction_firmware(directory, architecture)
    command = common_command(binary, plugin, architecture, firmware)
    command[-1] += ",continuation=on"
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True,
                                timeout=10, check=False)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"{architecture} continuation timed out; "
                           f"output={error.output!r}") from error
    if result.returncode != 0:
        raise AssertionError(f"{architecture} continuation exited {result.returncode}:\n"
                             f"{result.stdout}")
    require_continuation(result.stdout)
    print(f"PASS continuation case={architecture}-direct")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--x86", type=Path, required=True)
    parser.add_argument("--arm", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    args = parser.parse_args()

    direct = subprocess.run(
        common_command(args.x86, args.plugin, "x86"),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=10, check=False,
    )
    if direct.returncode != 0:
        raise AssertionError(f"direct preemption exited {direct.returncode}:\n{direct.stdout}")
    require_handoff(direct.stdout)
    if "PREEMPTION_SUBMIT rc=0 raw=0 tick=0" not in direct.stdout:
        raise AssertionError(f"direct command was not accepted at raw zero:\n{direct.stdout}")
    require_rejections(direct.stdout, 0)

    with tempfile.TemporaryDirectory(prefix="crucible-exact-preemption-") as path:
        snapshot_and_restore(args.arm, args.plugin, Path(path))
        interrupt_at_exact_tick(args.x86, args.plugin, Path(path))
        fractional_continuation(args.x86, args.plugin, "x86", Path(path))
        fractional_continuation(args.arm, args.plugin, "arm", Path(path))
        snapshot_and_restore(args.arm, args.plugin, Path(path), continuation=True)
        interrupt_at_exact_tick(args.x86, args.plugin, Path(path), continuation=True)
    print("PASS exact preemption at 10 ps with raw 0, restored pending command, and LAPIC interrupt")
    print("PASS fractional continuation with real retirement, restored command and due input")


if __name__ == "__main__":
    main()
