"""Extracts configured installer requests from a final plugin without loading it.

The ELF section contains CRUCCTL1 with big-endian schema, length, actual ELF
machine and count, followed by seven fixed 32-byte numeric requests. The
280-byte identity appends the complete final ELF SHA-256 to that248-byte record.
Requested geometry describes allocations; it never certifies allocator backing
or grants native startup authority.
"""
# SPDX-License-Identifier: Apache-2.0

import hashlib
from pathlib import Path
import struct
import sys


SECTION = b".qemu.crucible.control\0"
RECORD_BYTES = 248
SYMBOL = b"crucible_installer_layout_requests_v1\0"


def validate_requests(record, *, unfinalized=False):
    """Rejects incompatible, reordered or unrepresentable request records."""
    if (len(record) != RECORD_BYTES or record[:8] != b"CRUCCTL1"
            or struct.unpack_from(">IIII", record, 8)[:2] != (1, RECORD_BYTES)
            or struct.unpack_from(">I", record, 16)[0] not in ((0, 62, 183) if unfinalized else (62, 183))
            or struct.unpack_from(">I", record, 20)[0] != 7):
        raise ValueError("installer request header is not canonical")

    total = 0
    for index in range(7):
        kind, reserved, size, alignment, count = struct.unpack_from(
            ">IIQQQ", record, 24 + 32 * index
        )
        if (
            kind != index + 1 or reserved != 0 or count != 1
            or size == 0 or alignment == 0 or alignment & (alignment - 1)
            or size % alignment or size > (1 << 63) - 1
        ):
            raise ValueError("installer request geometry is not canonical")
        total += size * count
        if total > (1 << 64) - 1:
            raise ValueError("installer request total overflowed")
    return total


def extract(plugin, *, stamp=False):
    """Returns the exact final-artifact identity after complete file hashing."""
    with plugin.open("r+b" if stamp else "rb") as source:
        length = source.seek(0, 2)

        def read_at(offset, size):
            if offset < 0 or size < 0 or offset + size > length:
                raise ValueError("ELF extent leaves the installed plugin")
            source.seek(offset)
            value = source.read(size)
            if len(value) != size:
                raise ValueError("installed plugin changed during extraction")
            return value

        header = read_at(0, 64)
        if header[:7] != b"\x7fELF\x02\x01\x01":
            raise ValueError("installer requests require ELF64 little endian")
        kind, machine, version = struct.unpack_from("<HHI", header, 16)
        programs = struct.unpack_from("<Q", header, 32)[0]
        table = struct.unpack_from("<Q", header, 40)[0]
        header_bytes, program_bytes, program_count, section_bytes, count, names_index = struct.unpack_from(
            "<HHHHHH", header, 52
        )
        if (
            kind != 3 or machine not in (62, 183) or version != 1
            or header_bytes != 64 or section_bytes != 64 or count == 0
            or program_bytes != 56 or not 0 < program_count < 65535
            or programs < 64 or programs + program_count * 56 > length
            or names_index == 0 or names_index >= count
            or table < 64 or table + count * 64 > length
        ):
            raise ValueError("unsupported installed plugin ELF geometry")

        def section(index):
            return struct.unpack("<IIQQQQIIQQ", read_at(table + 64 * index, 64))

        names = section(names_index)
        if names[1] != 3 or names[4] + names[5] > length:
            raise ValueError("invalid ELF section-name table")
        record = None
        record_index = None
        record_section = None
        for index in range(count):
            entry = section(index)
            name_offset = entry[0]
            if name_offset >= names[5]:
                raise ValueError("ELF section name leaves its table")
            available = min(len(SECTION), names[5] - name_offset)
            name = read_at(names[4] + name_offset, available)
            if name != SECTION:
                continue
            if record is not None:
                raise ValueError("duplicate installer request section")
            if entry[1] != 1 or entry[2] not in (2, 2 | 0x200000) or entry[5] != RECORD_BYTES:
                raise ValueError("installer requests are not fixed read-only ELF data")
            record = read_at(entry[4], entry[5])
            record_index = index
            record_section = entry
        if record is None:
            raise ValueError("installed plugin has no retained installer request section")
        validate_requests(record, unfinalized=stamp)
        record_machine = struct.unpack_from(">I", record, 16)[0]
        if record_machine not in ((0, machine) if stamp else (machine,)):
            raise ValueError("installer request machine differs from the final ELF")

        file_start, file_bytes = record_section[4:6]
        address = record_section[3]
        address_end = address + RECORD_BYTES
        if address_end > (1 << 64) - 1:
            raise ValueError("installer request address overflowed")
        # Linux x86-64 base pages are 4 KiB; supported AArch64 kernels can use
        # up to 64 KiB. Larger configured granularity must refuse this edition.
        page_bytes = 4096 if machine == 62 else 65536
        record_page_start = address // page_bytes * page_bytes
        record_page_end = (address_end + page_bytes - 1) // page_bytes * page_bytes
        mapped = 0
        record_page_loads = 0
        for index in range(program_count):
            kind, flags, offset, virtual, _, file_size, memory_size, alignment = struct.unpack(
                "<IIQQQQQQ", read_at(programs + index * 56, 56)
            )
            if kind != 1:
                continue
            if (file_size > memory_size or offset + file_size > length
                    or virtual + memory_size > (1 << 64) - 1
                    or alignment not in (0, 1) and (
                        alignment & (alignment - 1) or offset % alignment != virtual % alignment
                    )):
                raise ValueError("invalid ELF load extent")
            load_page_start = virtual // page_bytes * page_bytes
            load_page_end = (virtual + memory_size + page_bytes - 1) // page_bytes * page_bytes
            page_overlap = load_page_start < record_page_end and record_page_start < load_page_end
            if page_overlap:
                record_page_loads += 1
            if page_overlap and flags != 4:
                raise ValueError("installer request page has conflicting load permissions")
            if offset % page_bytes != virtual % page_bytes:
                raise ValueError("ELF load is incompatible with supported page granularity")
            file_overlap = offset < file_start + file_bytes and file_start < offset + file_size
            address_overlap = virtual < address_end and address < virtual + memory_size
            if not file_overlap and not address_overlap:
                continue
            if (flags != 4 or offset > file_start
                    or file_start + file_bytes > offset + file_size
                    or address != virtual + file_start - offset):
                raise ValueError("installer requests lack one read-only file-backed mapping")
            mapped += 1
        if mapped != 1 or record_page_loads != 1:
            raise ValueError("installer request mapping is missing or ambiguous")

        exported = 0
        for index in range(count):
            symbols = section(index)
            if symbols[1] != 11:
                continue
            if (symbols[9] != 24 or symbols[5] % 24
                    or symbols[6] == 0 or symbols[6] >= count):
                raise ValueError("invalid ELF dynamic symbol table")
            strings = section(symbols[6])
            if strings[1] != 3 or strings[4] + strings[5] > length:
                raise ValueError("invalid ELF dynamic symbol names")
            for offset in range(0, symbols[5], 24):
                name, info, other, owner, value, size = struct.unpack(
                    "<IBBHQQ", read_at(symbols[4] + offset, 24)
                )
                if name >= strings[5]:
                    raise ValueError("ELF dynamic symbol name leaves its table")
                available = min(len(SYMBOL), strings[5] - name)
                if read_at(strings[4] + name, available) != SYMBOL:
                    continue
                if (info != 0x11 or other != 0 or owner != record_index
                        or value != record_section[3] or size != RECORD_BYTES):
                    raise ValueError("installer request export is not the immutable record")
                exported += 1
        if exported != 1:
            raise ValueError("installed plugin lacks one retained installer data export")

        # Final-output stamping is the sole package transform for this field.
        # It runs only after complete section/export/mapping validation, cannot
        # repair any nonzero mismatch, and precedes the complete final hash.
        if stamp and record_machine == 0:
            source.seek(file_start + 16)
            if source.write(struct.pack(">I", machine)) != 4:
                raise ValueError("final ELF machine stamp was incomplete")
            source.flush()
            record = read_at(file_start, RECORD_BYTES)
            validate_requests(record)
            if struct.unpack_from(">I", record, 16)[0] != machine:
                raise ValueError("final ELF machine stamp did not persist")
        else:
            validate_requests(record)

        digest = hashlib.sha256()
        source.seek(0)
        hashed = 0
        while block := source.read(1024 * 1024):
            digest.update(block)
            hashed += len(block)
        if hashed != length:
            raise ValueError("installed plugin changed during complete hashing")
        return record + digest.digest()


def main():
    arguments = sys.argv[1:]
    stamp = arguments[:1] == ["--finalize"]
    if stamp:
        arguments = arguments[1:]
    if len(arguments) != 2:
        raise SystemExit("usage: installer-layouts.py [--finalize] PLUGIN OUTPUT")
    identity = extract(Path(arguments[0]), stamp=stamp)
    Path(arguments[1]).write_bytes(identity)


if __name__ == "__main__":
    main()
