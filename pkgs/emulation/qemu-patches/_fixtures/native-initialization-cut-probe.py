# SPDX-License-Identifier: GPL-2.0-or-later
"""Builds a QEMU-only initialization-cut negative probe launcher with supplied AOS tools.

The launcher substitutes only an unqualified mechanism-test executable path.
Its GPL interposer loads into QEMU after exec, never Cargo or the Apache host.
The real plugin's original V5/V6 scope and native callbacks remain authoritative.
No output establishes a finite phase permit, readiness, or state profile.
"""

import argparse
import os
from pathlib import Path
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--cc", type=Path, required=True)
    parser.add_argument("--shell", type=Path, required=True)
    parser.add_argument("--glib-include", type=Path, required=True)
    parser.add_argument("--glib-config-include", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    for path in [args.qemu, args.cc, args.shell]:
        if not path.is_file() or not os.access(path, os.X_OK):
            raise RuntimeError(f"missing executable AOS tool or emulator: {path}")
    header = args.source / "include/plugins/qemu-plugin.h"
    if not header.is_file():
        raise RuntimeError("missing exact native source header")
    args.output.mkdir(parents=True, exist_ok=False)
    library = args.output / "native-initialization-cut-probe.so"
    source = Path(__file__).with_suffix(".c")
    subprocess.run([
        str(args.cc), "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
        "-I" + str(header.parent), "-I" + str(args.glib_include),
        "-I" + str(args.glib_config_include), str(source), "-ldl",
        "-o", str(library),
    ], check=True)

    launcher = args.output / "qemu-initialization-cut-probe"
    report = args.output / "emulator-stderr.log"
    launcher.write_text(
        "#!" + str(args.shell) + "\n"
        "set -eu\n"
        "export LD_PRELOAD=" + shlex.quote(str(library)) + "\n"
        "exec " + shlex.quote(str(args.qemu)) + ' "$@" 2>>'
        + shlex.quote(str(report)) + "\n"
    )
    launcher.chmod(0o700)
    print(f"CRUCIBLE_NATIVE_PROBE_QEMU={launcher}")
    print(f"Native fixture checks and emulator diagnostics: {report}")


if __name__ == "__main__":
    main()
