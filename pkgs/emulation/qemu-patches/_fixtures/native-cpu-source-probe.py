# SPDX-License-Identifier: GPL-2.0-or-later
"""Builds a GPL-only fixture and an emulator-only launch wrapper.

The fixture consumes the exact source build's headers and compiler settings.
It observes real initialization roots or injects a negative native source call.
It never qualifies a provider, physical pause, exact capture, or callback scope.
The generated LD_PRELOAD wrapper must be supplied as the emulator executable;
preloading this library into an Apache host or Cargo driver is prohibited.
"""

import argparse
import json
from pathlib import Path
import shlex
import subprocess


def compile_arguments(build_directory, fixture_source, library):
    rows = json.loads((build_directory / "compile_commands.json").read_text())
    row = next(
        item for item in rows
        if item["file"].endswith("/hw/core/cpu-common.c")
    )
    original = shlex.split(row["command"])
    arguments = []
    skip_operand = False

    for argument in original:
        if skip_operand:
            skip_operand = False
            continue
        if argument in ("-o", "-MF", "-MQ"):
            skip_operand = True
            continue
        if argument in ("-c", "-MD", "-fPIE") or argument == row["file"]:
            continue
        arguments.append(argument)

    return arguments + [
        "-fPIC", "-shared", "-Werror",
        str(fixture_source), "-o", str(library), "-ldl",
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-directory", required=True, type=Path)
    parser.add_argument("--qemu", required=True, type=Path)
    parser.add_argument("--bash", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--mode", choices=("names", "irq", "work"), default="names")
    parser.add_argument(
        "--fixture-source", type=Path,
        default=Path(__file__).with_suffix(".c"),
    )
    arguments = parser.parse_args()

    build_directory = arguments.build_directory.resolve(strict=True)
    fixture_source = arguments.fixture_source.resolve(strict=True)
    qemu = arguments.qemu.resolve(strict=True)
    bash = arguments.bash.resolve(strict=True)
    output = arguments.output_directory.resolve()
    output.mkdir(parents=True, exist_ok=False)
    library = output / "native-source-fixture.so"
    log = output / "emulator-stderr.log"
    wrapper = output / "qemu-native-source-fixture"

    subprocess.run(
        compile_arguments(build_directory, fixture_source, library),
        cwd=build_directory, check=True,
    )
    wrapper.write_text(
        f"#!{bash}\nset -eu\n"
        f"export LD_PRELOAD={shlex.quote(str(library))}\n"
        f"export CRUCIBLE_NATIVE_SOURCE_FIXTURE_MODE={arguments.mode}\n"
        f"exec {shlex.quote(str(qemu))} \"$@\" "
        f"2>> {shlex.quote(str(log))}\n"
    )
    wrapper.chmod(0o700)
    print(wrapper)


if __name__ == "__main__":
    main()
