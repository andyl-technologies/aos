# SPDX-License-Identifier: MIT
"""Checks the existing ARM loader's ELF relocation and reserved RAM regions.

The mapping follows KernelWorkload's zero-mask calculation and the existing
VExpress_GEM5_V2 load offset. This data check neither loads nor executes a guest.
"""

from pathlib import Path
import struct


RAM_START = 0x80000000
RAM_END = 0x90000000
DTB_START = 0x88000000
DTB_BYTES = 0x200000
CPU_RELEASE_START = DTB_START - 8
INITRD_START = 0x88200000
MAX_INITRD = 32 * 1024 * 1024
MAX_SEGMENTS = 128
MAX_FILE = 1024 * 1024 * 1024
U64_END = 1 << 64


def elf_segments(path, allowed_types=(2,)):
    """Reads bounded AArch64 ELF64 load extents without allocating its payload."""
    path = Path(path)
    extent = path.stat().st_size
    if not 0 < extent <= MAX_FILE:
        raise ValueError("ARM ELF exceeds its finite file bound")
    with path.open("rb") as stream:
        header = stream.read(64)
        if (len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01"
                or struct.unpack_from("<H", header, 16)[0] not in allowed_types
                or struct.unpack_from("<HI", header, 18) != (183, 1)):
            raise ValueError("ARM loader requires a little-endian AArch64 executable")
        entry, offset = struct.unpack_from("<QQ", header, 24)
        header_size, size, count = struct.unpack_from("<HHH", header, 52)
        if (header_size != 64 or size != 56 or not 0 < count <= MAX_SEGMENTS
                or offset < 64 or offset + size * count > extent):
            raise ValueError("ARM ELF program-header extent is invalid")
        stream.seek(offset)
        table = stream.read(size * count)
    if len(table) != size * count:
        raise ValueError("ARM ELF program-header table is truncated")

    segments = []
    for index in range(count):
        kind, flags, offset, virtual, physical, filesz, memsz, align = struct.unpack_from(
            "<IIQQQQQQ", table, index * size)
        if kind != 1 or not memsz:
            continue
        if (filesz > memsz or offset + filesz > extent
                or physical + memsz >= U64_END or virtual + memsz >= U64_END):
            raise ValueError("ARM ELF load extent wraps or escapes its source")
        segments.append({"physical": physical, "virtual": virtual, "bytes": memsz,
                         "file_bytes": filesz, "flags": flags})
    if not segments or not any(
            row["flags"] & 1 and row["virtual"] <= entry < row["virtual"] + row["bytes"]
            for row in segments):
        raise ValueError("ARM ELF has no executable entry within a loadable segment")
    return entry, segments


def intersects(start, extent, other_start, other_extent):
    return start < other_start + other_extent and other_start < start + extent


def validate_loader(kernel, initramfs, firmware):
    """Refuses kernel, initramfs and DTB collisions in the fixed ARM memory map."""
    initrd_bytes = Path(initramfs).stat().st_size
    if not 0 < initrd_bytes <= MAX_INITRD:
        raise ValueError("ARM initramfs exceeds its finite reserved region")
    entry, segments = elf_segments(kernel, allowed_types=(2, 3))
    start = min(row["physical"] for row in segments)
    # MemoryImage::maxAddr is exclusive. An exact power-of-two image span
    # therefore needs the next bit in KernelWorkload's findMsbSet mask.
    end = max(row["physical"] + row["bytes"] for row in segments)
    mask = (1 << max(1, (end - start).bit_length())) - 1
    mapped = []
    executable = []
    for row in segments:
        # ElfObject adds file-backed and zero-filled portions separately;
        # MemoryImage::move masks each portion's base independently.
        chunks = ((row["physical"], row["file_bytes"], "file"),
                  (row["physical"] + row["file_bytes"],
                   row["bytes"] - row["file_bytes"], "zero"))
        for address, extent, kind in chunks:
            if not extent:
                continue
            physical = (address & mask) + RAM_START
            if not RAM_START <= physical < physical + extent <= RAM_END:
                raise ValueError("ARM relocated kernel escapes the fixed board RAM")
            if (intersects(physical, extent, CPU_RELEASE_START, 8)
                    or intersects(physical, extent, DTB_START, DTB_BYTES)
                    or intersects(physical, extent, INITRD_START, initrd_bytes)):
                raise ValueError("ARM relocated kernel overlaps CPU release, DTB or initramfs")
            if any(intersects(physical, extent, prior["address"], prior["bytes"])
                   for prior in mapped):
                raise ValueError("ARM relocated kernel load segments overlap")
            mapped.append({"address": physical, "bytes": extent, "kind": kind})
            if kind == "file" and row["flags"] & 1:
                executable.append((physical, extent))

    mapped_entry = (entry & mask) + RAM_START
    if not any(address <= mapped_entry < address + extent for address, extent in executable):
        raise ValueError("ARM relocated entry is outside loaded executable bytes")

    firmware_entry, firmware_segments = elf_segments(firmware)
    # The existing firmware is linked at 0x10 in the board's 64-MiB boot memory.
    # Native FsWorkload writes these physical extents directly, without masking.
    if firmware_entry != 0x10 or any(
            not 0 <= row["physical"] < row["physical"] + row["bytes"] <= 0x04000000
            for row in firmware_segments):
        raise ValueError("ARM firmware escapes its original boot-memory window")
    return {"schema": "crucible.gem5.arm-linux-loader.v1", "kernel_mask": str(mask),
            "kernel_entry": str(mapped_entry), "kernel_segments": mapped,
            "ram": {"address": RAM_START, "bytes": RAM_END - RAM_START},
            "cpu_release": {"address": CPU_RELEASE_START, "bytes": 8},
            "dtb": {"address": DTB_START, "maximum_bytes": DTB_BYTES},
            "initramfs": {"address": INITRD_START, "bytes": initrd_bytes},
            "firmware_entry": str(firmware_entry)}
