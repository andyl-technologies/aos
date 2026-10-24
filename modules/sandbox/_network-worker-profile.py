"""Encodes final selected Network P/O unit DATA without supplying authority.

The record is AOSNWP02: a 16-byte header followed by two 4096-byte rows.
Each row holds purpose, argc, unit/ExecStart lengths, three u64 native limits,
the rendered-unit and literal-ExecStart SHA256 digests, a 128-byte unit name,
and 2048 bytes of literal ExecStart. Remaining bytes are reserved zeroes.
Unsupported systemd syntax or unbounded declarations refuse the producer.
"""

import hashlib
import json
import re
import struct
import sys
from pathlib import Path


def finite_limit(value, memory=False):
    """Accepts explicit finite declarations without synthesizing defaults."""
    if isinstance(value, bool):
        raise ValueError("boolean native limit")
    spelling = str(value)
    match = re.fullmatch(r"([1-9][0-9]*)([KMGTPE]?)", spelling)
    if match is None or (match[2] and not memory):
        raise ValueError("native limit must be an explicit finite quantity")
    multiplier = 1024 ** ("KMGTPE".index(match[2]) + 1) if match[2] else 1
    result = int(match[1]) * multiplier
    if result >= 2**64:
        raise ValueError("native limit exceeds u64")
    return result


def literal_arguments(command):
    """Checks the selected fixed absolute-path subset of ExecStart syntax."""
    if not isinstance(command, str):
        raise ValueError("ExecStart must be one literal command")
    normalized = command.replace("\\\n", " ")
    arguments = normalized.split()
    if not arguments or len(arguments) >= 2**16:
        raise ValueError("ExecStart argument count")
    for argument in arguments:
        if re.fullmatch(r"/[A-Za-z0-9_+.,/@:=~-]+", argument) is None:
            raise ValueError("ExecStart requires fixed unquoted absolute paths")
        if any(part in (".", "..") for part in argument.split("/")):
            raise ValueError("ExecStart path traversal")
    return arguments


def encode(rows):
    """Retains exact selected values, command spelling and unit provenance."""
    expected = (
        "aos-sandbox-network-worker@.service",
        "aos-sandbox-network-observation-worker@.service",
    )
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise ValueError("expected the exact P/O unit pair")
    packet = bytearray(8208)
    struct.pack_into(">8sHHI", packet, 0, b"AOSNWP02", 2, 2, len(packet))
    for index, (selected, unit) in enumerate(zip(rows, expected)):
        if selected["unit"] != unit:
            raise ValueError("selected unit purpose/order")
        service = selected["service"]
        command = service["ExecStart"]
        arguments = literal_arguments(command)
        unit_bytes = unit.encode("ascii")
        command_bytes = command.encode("ascii")
        rendered = selected["rendered"].encode("utf-8")
        if len(unit_bytes) > 128 or not 0 < len(command_bytes) <= 2048:
            raise ValueError("fixed profile text bound")
        if not rendered or b"\x00" in rendered:
            raise ValueError("rendered unit provenance")
        offset = 16 + index * 4096
        struct.pack_into(
            ">BBHHHQQQ", packet, offset,
            index + 1, 0, len(arguments), len(unit_bytes), len(command_bytes),
            finite_limit(service["MemoryMax"], memory=True),
            finite_limit(service["LimitNOFILE"]),
            finite_limit(service["TasksMax"]),
        )
        packet[offset + 32:offset + 64] = hashlib.sha256(rendered).digest()
        packet[offset + 64:offset + 96] = hashlib.sha256(command_bytes).digest()
        packet[offset + 96:offset + 96 + len(unit_bytes)] = unit_bytes
        packet[offset + 224:offset + 224 + len(command_bytes)] = command_bytes
    return packet


def main():
    packet = encode(json.loads(Path(sys.argv[1]).read_text()))
    output = Path(sys.argv[2])
    output.write_bytes(packet)
    output.chmod(0o444)


if __name__ == "__main__":
    main()
