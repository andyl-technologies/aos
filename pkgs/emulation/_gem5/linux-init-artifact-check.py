# SPDX-License-Identifier: MIT
"""Checks source-built Linux PID1 ELF and deterministic newc data without running it.

The fixed archive contains dev/console, proc, sys and the exact init ELF. This
validates artifact geometry; it grants no guest readiness or native node rights.
"""

from pathlib import Path
import hashlib
import json
import stat
import struct
import sys


MAXIMUM_INIT_BYTES = 16 * 1024 * 1024
MACHINES = {"aarch64": 183, "x86_64": 62}
ARCHIVE_ENTRIES = [
    ("dev", stat.S_IFDIR | 0o755, 0, 0),
    ("dev/console", stat.S_IFCHR | 0o600, 5, 1),
    ("proc", stat.S_IFDIR | 0o755, 0, 0),
    ("sys", stat.S_IFDIR | 0o755, 0, 0),
    ("init", stat.S_IFREG | 0o755, 0, 0),
    ("TRAILER!!!", 0, 0, 0),
]


def bounded_bytes(path, maximum):
    """Reads at most the admitted artifact extent plus one refusal byte."""
    with Path(path).open("rb") as source:
        data = source.read(maximum + 1)
    if not 0 < len(data) <= maximum:
        raise ValueError("artifact exceeds its bounded file extent")
    return data


def checked_end(start, extent, maximum):
    """Rejects out-of-domain ELF extents before slicing or address addition."""
    if start > maximum or extent > maximum - start:
        raise ValueError("artifact range exceeds its containing extent")
    return start + extent


def elf(architecture, data):
    """Requires a static LP64 ELF with one file-backed executable entry owner."""
    if architecture not in MACHINES:
        raise ValueError("unknown Linux PID1 architecture")
    if not 64 <= len(data) <= MAXIMUM_INIT_BYTES or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("PID1 lacks a bounded ELF64 little-endian header")
    kind, machine, version = struct.unpack_from("<HHI", data, 16)
    entry, table = struct.unpack_from("<QQ", data, 24)
    header_size, record_size, count = struct.unpack_from("<HHH", data, 52)
    if (kind != 2 or machine != MACHINES[architecture] or version != 1
            or header_size != 64 or record_size != 56 or not 0 < count <= 128):
        raise ValueError("PID1 ELF dimensions or architecture differ")
    checked_end(table, count * record_size, len(data))
    ranges = []
    entry_owners = 0
    for index in range(count):
        kind, flags, offset, address, _physical, file_size, memory_size, alignment = struct.unpack_from(
            "<IIQQQQQQ", data, table + index * record_size)
        if kind in (2, 3):
            raise ValueError("PID1 requires a runtime interpreter or dynamic loader")
        if kind != 1:
            continue
        if file_size > memory_size:
            raise ValueError("PID1 load file exceeds its memory extent")
        checked_end(offset, file_size, len(data))
        end = checked_end(address, memory_size, (1 << 64) - 1)
        if alignment not in (0, 1) and (alignment & (alignment - 1) or address % alignment != offset % alignment):
            raise ValueError("PID1 load alignment differs from its file address")
        if any(address < previous_end and previous_start < end for previous_start, previous_end in ranges):
            raise ValueError("PID1 load memory ranges overlap")
        if memory_size:
            ranges.append((address, end))
        if flags & 1 and address <= entry < address + file_size:
            entry_owners += 1
    if entry_owners != 1:
        raise ValueError("PID1 entry lacks one file-backed executable owner")
    return dict(architecture=architecture, entry=entry, loads=len(ranges), bytes=len(data))


def zero_alignment(data, position, alignment):
    """Consumes only canonical zero alignment bytes within the archive."""
    end = checked_end(position, -position % alignment, len(data))
    if any(data[position:end]):
        raise ValueError("initramfs alignment contains nonzero bytes")
    return end


def archive(data, init):
    """Requires the original fixed record order, identities and exact init bytes."""
    if not 0 < len(data) <= MAXIMUM_INIT_BYTES + 4096 or len(data) % 512:
        raise ValueError("initramfs extent or final block alignment differs")
    position = 0
    for name, mode, major, minor in ARCHIVE_ENTRIES:
        end = checked_end(position, 110, len(data))
        header = data[position:end]
        if header[:6] != b"070701" or any(byte not in b"0123456789abcdef" for byte in header[6:]):
            raise ValueError("initramfs lacks a canonical newc header")
        fields = [int(header[6 + index * 8:14 + index * 8], 16) for index in range(13)]
        inode, actual_mode, uid, gid, links, mtime, size, dev_major, dev_minor, rdev_major, rdev_minor, namesize, checksum = fields
        if (inode, actual_mode, uid, gid, links, mtime, dev_major, dev_minor, rdev_major, rdev_minor, checksum) != (1, mode, 0, 0, 1, 0, 0, 0, major, minor, 0):
            raise ValueError("initramfs record identity or mode differs")
        expected_name = name.encode("ascii") + b"\0"
        if namesize != len(expected_name):
            raise ValueError("initramfs record name extent differs")
        name_end = checked_end(end, namesize, len(data))
        if data[end:name_end] != expected_name:
            raise ValueError("initramfs record name or order differs")
        position = zero_alignment(data, name_end, 4)
        expected = init if name == "init" else b""
        if size != len(expected):
            raise ValueError("initramfs payload extent differs")
        payload_end = checked_end(position, size, len(data))
        if data[position:payload_end] != expected:
            raise ValueError("initramfs payload differs from the exact init ELF")
        position = zero_alignment(data, payload_end, 4)
    end = zero_alignment(data, position, 512)
    if end != len(data):
        raise ValueError("initramfs has records or data after its fixed trailer")
    return dict(entries=len(ARCHIVE_ENTRIES), bytes=len(data))


def check(architecture, root):
    """Checks the two installed data artifacts without invoking either ELF."""
    init = bounded_bytes(root / "init", MAXIMUM_INIT_BYTES)
    initrd = bounded_bytes(root / "initrd.img", MAXIMUM_INIT_BYTES + 4096)
    result = dict(schema="crucible.gem5.linux-device-fixture.v1", elf=elf(architecture, init), archive=archive(initrd, init))
    result["sha256"] = dict(init=hashlib.sha256(init).hexdigest(), initramfs=hashlib.sha256(initrd).hexdigest())
    return result


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise ValueError("expected architecture and installed fixture directory")
    print(json.dumps(check(sys.argv[1], Path(sys.argv[2])), sort_keys=True))
