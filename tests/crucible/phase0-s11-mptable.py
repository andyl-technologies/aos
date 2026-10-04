"""Build the minimal Intel MP 1.4 table for the S11 direct-reset guest.

The reset ROM skips SeaBIOS, so QEMU's four virtual CPUs need an explicit
guest-visible topology. Linux scans the last KiB of conventional memory for
the floating pointer. Both structures fit in that reserved region.
"""

import struct
import sys


TABLE_ADDRESS = 0x9FC00
CONFIG_ADDRESS = TABLE_ADDRESS + 16
CPU_COUNT = 4
IO_APIC_ID = CPU_COUNT


def with_checksum(data: bytes, offset: int) -> bytes:
    result = bytearray(data)
    result[offset] = -sum(result) & 0xFF
    assert sum(result) & 0xFF == 0
    return bytes(result)


def configuration_table() -> bytes:
    entries = []
    for apic_id in range(CPU_COUNT):
        cpu_flags = 1 | (2 if apic_id == 0 else 0)
        entries.append(struct.pack("<BBBBIIII", 0, apic_id, 0x14, cpu_flags, 0, 0, 0, 0))

    entries.append(struct.pack("<BB6s", 1, 0, b"ISA   "))
    entries.append(struct.pack("<BBBBI", 2, IO_APIC_ID, 0x11, 1, 0xFEC00000))

    for irq in range(16):
        destination_pin = 2 if irq == 0 else irq
        entries.append(struct.pack("<BBHBBBB", 3, 0, 0, 0, irq, IO_APIC_ID, destination_pin))

    entries.append(struct.pack("<BBHBBBB", 4, 3, 0, 0, 0, 0xFF, 0))
    entries.append(struct.pack("<BBHBBBB", 4, 1, 0, 0, 0, 0xFF, 1))

    header = struct.pack(
        "<4sHBB8s12sIHHII",
        b"PCMP",
        44 + sum(map(len, entries)),
        4,
        0,
        b"ANDYL   ",
        b"CRUCIBLE-S11",
        0,
        0,
        len(entries),
        0xFEE00000,
        0,
    )
    assert len(header) == 44
    return with_checksum(header + b"".join(entries), 7)


def floating_pointer() -> bytes:
    pointer = struct.pack("<4sIBBBBBBBB", b"_MP_", CONFIG_ADDRESS, 1, 4, 0, 0, 0, 0, 0, 0)
    assert len(pointer) == 16
    return with_checksum(pointer, 10)


def main() -> None:
    image = floating_pointer() + configuration_table()
    assert len(image) <= 1024
    with open(sys.argv[1], "wb") as output:
        output.write(image)


if __name__ == "__main__":
    main()
