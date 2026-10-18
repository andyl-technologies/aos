"""Checks actual Meson/TAP execution and retains the native compile command."""

import argparse
import json
import pathlib

UNIT = "test-crucible-uart-origin-baseline"
CASES = {
    "/uart-origin/serial/register-readiness",
    "/uart-origin/serial/fifo-overrun",
    "/uart-origin/serial/nonfifo-overwrite",
    "/uart-origin/serial/retry-drop",
    "/uart-origin/serial/loopback-dlab-reset",
    "/uart-origin/serial/full-vmstate",
    "/uart-origin/pl011/blocked-write-all",
    "/uart-origin/pl011/full-vmstate-reset",
}


def configured(build):
    rows = json.loads((build / "meson-info/intro-tests.json").read_text())
    matches = [row for row in rows if row["name"] == UNIT]
    if len(matches) != 1:
        raise ValueError("UART baseline has no unique configured unit")
    row = matches[0]
    if row["suite"] != ["qemu:unit"] or row["timeout"] != 30:
        raise ValueError("UART baseline suite or original 30-second budget differs")
    if not row["cmd"] or pathlib.Path(row["cmd"][0]).name != UNIT:
        raise ValueError("UART baseline configured another executable")
    if row["cmd"][1:] != ["--tap", "-k"]:
        raise ValueError("UART baseline TAP invocation differs")
    if not (build / "config-host.h").is_file():
        raise ValueError("UART baseline has no actual configured host header")


def executed(log_path, commands_path):
    rows = [json.loads(line) for line in log_path.read_text().splitlines()]
    if len(rows) != 1 or rows[0]["name"] != f"unit - qemu:{UNIT}" or rows[0]["result"] != "OK":
        raise ValueError("UART baseline did not execute its exact successful unit")

    if rows[0]["is_fail"] is not False or rows[0]["returncode"] != 0:
        raise ValueError("UART baseline returned a failure")

    stdout = rows[0]["stdout"]
    observed = [
        line.split(maxsplit=2)[2]
        for line in stdout.splitlines()
        if line.startswith("ok ") and len(line.split(maxsplit=2)) == 3
    ]
    if len(observed) != len(CASES) or set(observed) != CASES:
        raise ValueError("UART baseline TAP cases are incomplete or duplicated")
    if stdout.splitlines().count("1..8") != 1:
        raise ValueError("UART baseline TAP cases are incomplete or unexpected")
    if any(line.startswith("not ok ") for line in stdout.splitlines()):
        raise ValueError("UART baseline retained a failing TAP case")

    commands = json.loads(commands_path.read_text())
    matches = [
        command
        for command in commands
        if pathlib.Path(command["file"]).name == f"{UNIT}.c"
    ]
    if len(matches) != 1:
        raise ValueError("UART fixture has no unique genuine native compile action")
    pathlib.Path("uart-origin-compile.json").write_text(
        json.dumps(matches[0], indent=2) + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("configured", "executed"))
    parser.add_argument("path", type=pathlib.Path)
    parser.add_argument("commands", type=pathlib.Path, nargs="?")
    arguments = parser.parse_args()
    if arguments.stage == "configured":
        configured(arguments.path)
    else:
        if arguments.commands is None:
            parser.error("executed requires the genuine compile-command file")
        executed(arguments.path, arguments.commands)
