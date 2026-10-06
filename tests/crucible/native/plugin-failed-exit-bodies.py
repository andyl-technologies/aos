# SPDX-License-Identifier: GPL-2.0-only
"""Retain verbatim plugin shutdown and runstate exit bodies for one native unit."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy


FUNCTIONS = {
    "plugins/api-system.c": ("qemu_plugin_request_shutdown",),
    "system/runstate.c": (
        "qemu_system_shutdown_request_with_code",
        "qemu_system_shutdown_request",
        "qemu_shutdown_requested",
        "main_loop_should_exit",
        "qemu_main_loop",
    ),
}
GLOBALS = (
    "shutdown_requested",
    "shutdown_exit_code",
    "force_shutdown",
    "wakeup_reason",
    "wakeup_notifiers",
)
UNIT = "test-crucible-plugin-failed-exit"
CASES = {"/plugin-exit/failure", "/plugin-exit/clean", "/plugin-exit/failure-then-clean"}


def extract(source, output, extractor):
    function = runpy.run_path(str(extractor))["function"]
    definitions = []
    bindings = []
    runstate = (source / "system/runstate.c").read_text()
    for name in GLOBALS:
        declarations = re.findall(
            rf"(?m)^static [^;\n]*\b{re.escape(name)}\b[^;]*;", runstate
        )
        if len(declarations) != 1:
            raise ValueError(f"missing unique original global: {name}")
        definitions.append(declarations[0] + "\n")

    for relative, names in FUNCTIONS.items():
        data = (source / relative).read_bytes()
        for name in names:
            body = function(data.decode(), name)
            definitions.append(body)
            bindings.append({
                "path": relative,
                "source_sha256": hashlib.sha256(data).hexdigest(),
                "function": name,
                "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
            })
    declarations = [
        body[:body.index("{")].rstrip() + ";"
        for body in definitions[len(GLOBALS):]
    ]
    output.write_text("\n".join(declarations + definitions))
    output.with_suffix(".json").write_text(json.dumps(bindings, indent=2) + "\n")


def configured(build):
    rows = json.loads((build / "meson-info/intro-tests.json").read_text())
    selected = [row for row in rows if row["name"] == UNIT]
    if len(selected) != 1:
        raise ValueError("shutdown unit has no unique configured test")
    row = selected[0]
    if row["suite"] != ["qemu:unit"] or row["timeout"] != 30:
        raise ValueError("shutdown unit suite or budget differs")
    if not row["cmd"] or Path(row["cmd"][0]).name != UNIT:
        raise ValueError("shutdown unit configured another executable")
    if row["cmd"][1:] != ["--tap", "-k"]:
        raise ValueError("shutdown unit TAP invocation differs")


def executed(build):
    rows = [json.loads(line) for line in
            (build / "meson-logs/plugin-failed-exit.json").read_text().splitlines()]
    if len(rows) != 1 or rows[0]["name"] != f"unit - qemu:{UNIT}":
        raise ValueError("shutdown unit did not execute its configured test")
    row = rows[0]
    if row["result"] != "OK" or row["is_fail"] or row["returncode"] != 0:
        raise ValueError("shutdown unit failed")
    lines = row["stdout"].splitlines()
    names = [line.split(maxsplit=2)[2] for line in lines if line.startswith("ok ")]
    if len(names) != len(CASES) or set(names) != CASES or lines.count("1..3") != 1:
        raise ValueError("shutdown unit selected incomplete or duplicate cases")
    if any(line.startswith("not ok ") for line in lines):
        raise ValueError("shutdown unit retained a failed case")
    commands = json.loads((build / "compile_commands.json").read_text())
    selected = [row for row in commands if Path(row["file"]).name == f"{UNIT}.c"]
    if len(selected) != 1:
        raise ValueError("shutdown unit has no unique genuine compile action")
    Path("plugin-failed-exit-compile.json").write_text(
        json.dumps(selected[0], indent=2) + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("extract", "configured", "executed"))
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    parser.add_argument("extractor", type=Path, nargs="?")
    args = parser.parse_args()
    if args.stage == "extract":
        if args.output is None or args.extractor is None:
            parser.error("extract requires output and original function extractor")
        extract(args.source, args.output, args.extractor)
    elif args.stage == "configured":
        configured(args.source)
    else:
        executed(args.source)
