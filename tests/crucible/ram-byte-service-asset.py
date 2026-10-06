# SPDX-License-Identifier: Apache-2.0
"""Derive byte-guest entry and delay geometry from its assembled ELF evidence.

The unchanged benchmark has one backward pause/loop pair before its byte load.
The test receives physical instruction coordinates, never an assumed BIOS
instruction count or a guessed virtual-time delay.
"""

import pathlib
import re
import sys


def read_symbols(path):
    """Read unique entry and operand symbols from the assembled image."""
    symbols = {}
    for line in pathlib.Path(path).read_text().splitlines():
        fields = line.split()
        if len(fields) != 3 or fields[2] not in ("long_mode", "aligned_target"):
            continue
        name = fields[2]
        if name in symbols:
            raise ValueError(f"duplicate benchmark symbol: {name}")
        symbols[name] = int(fields[0], 16)
    if set(symbols) != {"long_mode", "aligned_target"}:
        raise ValueError("benchmark entry or target symbol is absent")
    return symbols


def read_instructions(path):
    """Read complete instruction encodings from the AOS disassembler."""
    pattern = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(\S+)(.*)$")
    instructions = []
    for line in pathlib.Path(path).read_text().splitlines():
        match = pattern.match(line)
        if match:
            instructions.append(
                (int(match[1], 16), bytes.fromhex(match[2]), match[3], match[4].strip())
            )
    if not instructions:
        raise ValueError("benchmark instruction evidence is absent")
    return instructions


def main():
    """Publish checked instruction geometry as decimal shell environment values."""
    symbols = read_symbols(sys.argv[1])
    instructions = read_instructions(sys.argv[2])
    pairs = []
    for previous, current in zip(instructions, instructions[1:]):
        address, encoded, mnemonic, operand = current
        if previous[2] != "pause" or mnemonic != "loop":
            continue
        target = re.fullmatch(r"([0-9a-f]+)\s+<[^>]+>", operand)
        if target and int(target[1], 16) == previous[0]:
            pairs.append((previous[0], address + len(encoded)))
    if len(pairs) != 1:
        raise ValueError("benchmark must contain exactly one pause/loop delay pair")
    start, end = pairs[0]
    if instructions[0][0] != symbols["long_mode"] or not symbols["long_mode"] < start < end:
        raise ValueError("delay lies outside the decoded long-mode entry")
    following = next((instruction for instruction in instructions if instruction[0] == end), None)
    if following is None or following[2] != "mov":
        raise ValueError("delay is not immediately followed by the benchmark byte load")
    if following[1][:3] != b"\x8a\x04\x25" or len(following[1]) != 7:
        raise ValueError("benchmark operation is not the supported one-byte load")
    if int.from_bytes(following[1][3:], "little") != symbols["aligned_target"]:
        raise ValueError("benchmark byte load does not name the assembled target")

    for name, value in (
        ("CRUCIBLE_BYTE_ENTRY", symbols["long_mode"]),
        ("CRUCIBLE_BYTE_DELAY_START", start),
        ("CRUCIBLE_BYTE_DELAY_END", end),
        ("CRUCIBLE_BYTE_TARGET", symbols["aligned_target"]),
    ):
        print(f"export {name}={value}")


if __name__ == "__main__":
    main()
