# SPDX-License-Identifier: Apache-2.0
"""Retain bounded ELF function symbols before QEMU's executables are stripped."""

import argparse
import hashlib
from pathlib import Path
import subprocess


def write_function_map(nm: str, executable: Path, output: Path) -> None:
    """Write ELF-relative address, size, type, and name without modifying ELF."""
    original_bytes = executable.read_bytes()
    if not original_bytes.startswith(b"\x7fELF"):
        print(f"SKIP non-ELF: {executable.name}")
        return
    original_digest = hashlib.sha256(original_bytes).digest()
    symbols = subprocess.run(
        [
            nm, "--defined-only", "--numeric-sort", "--print-size",
            "--format=posix", str(executable),
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout

    functions = []
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) != 4 or fields[1] not in {"T", "t", "W", "w"}:
            continue

        name, symbol_type, address, size = fields
        address = int(address, 16)
        size = int(size, 16)
        if size == 0:
            continue
        if "/" in name or "\\" in name:
            raise ValueError(f"function symbol contains a path: {name!r}")

        functions.append((address, size, symbol_type, name))

    if not functions:
        raise ValueError(f"no bounded function symbols in {executable.name}")
    if hashlib.sha256(executable.read_bytes()).digest() != original_digest:
        raise ValueError(f"symbol extraction changed {executable.name}")

    # Zero-size labels have no proven range; leave their samples unidentified.
    functions.sort()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("".join(
        f"{address:016x}\t{size:016x}\t{symbol_type}\t{name}\n"
        for address, size, symbol_type, name in functions
    ))
    map_digest = hashlib.sha256(output.read_bytes()).hexdigest()
    print(
        f"ELF function map {executable.name}: functions={len(functions)} "
        f"executable_sha256={original_digest.hex()} map_sha256={map_digest}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nm", required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    write_function_map(arguments.nm, arguments.executable, arguments.output)


if __name__ == "__main__":
    main()
