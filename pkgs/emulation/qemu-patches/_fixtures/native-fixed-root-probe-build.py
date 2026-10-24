# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the QEMU-only actual-root interposer using its exact configured source.

The resulting shared object belongs to the QEMU process. It must never be
loaded into the Apache host. Building it alone is not a passed native probe.
"""

import argparse
import json
from pathlib import Path
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("compiler", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    source = arguments.source.resolve()
    database = json.loads((source / "build/compile_commands.json").read_text())
    matches = [row for row in database
               if row["file"].endswith("hw/i386/microvm.c")]
    if len(matches) != 1:
        raise SystemExit("expected one actual x86 microvm compile command")
    row = matches[0]
    original = row.get("arguments") or shlex.split(row["command"])
    flags = []
    iterator = iter(original[1:])
    for flag in iterator:
        if flag in ("-MQ", "-MF", "-o"):
            next(iterator)
        elif flag not in ("-c", "-MD", "-MMD", "-MP", row["file"]):
            flags.append(flag)
    output = arguments.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    fixture = Path(__file__).with_name("native-fixed-root-probe.c")
    command = [str(arguments.compiler), *flags, "-shared", "-fPIC",
               "-Wno-unused-parameter", "-Wno-sign-compare", str(fixture),
               "-ldl", "-o", str(output)]
    subprocess.run(command, cwd=row["directory"], check=True, timeout=90)
    if not output.is_file():
        raise SystemExit("native probe shared object is missing")
    print("PASS built QEMU-only native root probe; execution is a separate check")


if __name__ == "__main__":
    main()
