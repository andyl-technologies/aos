# SPDX-License-Identifier: MIT
"""Checks two cross-built PID1 artifacts and original ARM code without executing them."""

from pathlib import Path
import importlib.util
import json
import struct
import sys


def allocated_sections(data):
    """Projects actual loaded section bytes, excluding source-file debug names."""
    table = struct.unpack_from("<Q", data, 40)[0]
    record_size, count, names_index = struct.unpack_from("<HHH", data, 58)
    if record_size != 64 or not 0 < names_index < count <= 4096:
        raise ValueError("fixture section table dimensions differ")
    if table > len(data) or count * record_size > len(data) - table:
        raise ValueError("fixture section table exceeds its file")
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, table + index * record_size) for index in range(count)]
    names_header = headers[names_index]
    names = data[names_header[4]:names_header[4] + names_header[5]]
    result = []
    for name_offset, kind, flags, address, offset, size, _link, _info, alignment, _entry_size in headers:
        if not flags & 2:
            continue
        end = names.find(b"\0", name_offset)
        if end < 0 or name_offset >= len(names):
            raise ValueError("fixture section name is not bounded")
        name = names[name_offset:end].decode("ascii")
        payload = None if kind == 8 else data[offset:offset + size]
        if payload is not None and len(payload) != size:
            raise ValueError("fixture allocated section exceeds its file")
        result.append((name, kind, flags, address, size, alignment, payload))
    return struct.unpack_from("<Q", data, 24)[0], result


def main():
    """Requires real compiler outputs and rejects mutations of those exact bytes."""
    if len(sys.argv) != 9:
        raise ValueError("expected checker, original ARM ELF, two new ELFs and four archives")
    checker_path, original_path, arm_path, x86_path, arm_archive, arm_repeat, x86_archive, x86_repeat = map(Path, sys.argv[1:])
    specification = importlib.util.spec_from_file_location("linux_pid1_artifact_checker", checker_path)
    checker = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(checker)
    original = checker.bounded_bytes(original_path, checker.MAXIMUM_INIT_BYTES)
    arm = checker.bounded_bytes(arm_path, checker.MAXIMUM_INIT_BYTES)
    x86 = checker.bounded_bytes(x86_path, checker.MAXIMUM_INIT_BYTES)
    archives = [checker.bounded_bytes(path, checker.MAXIMUM_INIT_BYTES + 4096) for path in (arm_archive, arm_repeat, x86_archive, x86_repeat)]
    controls = []

    def passed(name):
        controls.append(name)

    def refused(name, operation):
        try:
            operation()
        except ValueError:
            passed(name)
        else:
            raise AssertionError("malformed actual artifact was accepted: " + name)

    checker.elf("aarch64", original)
    checker.elf("aarch64", arm)
    passed("new_arm_static_elf")
    checker.elf("x86_64", x86)
    passed("new_x86_static_elf")
    if allocated_sections(original) != allocated_sections(arm):
        raise AssertionError("shared source changed original ARM allocated code/data or entry")
    passed("original_arm_allocated_code_data_and_entry_preserved")
    for name, image, first, second in [("arm", arm, archives[0], archives[1]), ("x86", x86, archives[2], archives[3])]:
        checker.archive(first, image)
        checker.archive(second, image)
        if first != second:
            raise AssertionError("source-built initramfs packer is nondeterministic")
        passed(name + "_exact_archive_and_repeat")
    refused("arm_as_x86", lambda: checker.elf("x86_64", arm))
    refused("x86_as_arm", lambda: checker.elf("aarch64", x86))

    table, = struct.unpack_from("<Q", x86, 32)
    count, = struct.unpack_from("<H", x86, 56)
    loads = [table + index * 56 for index in range(count) if struct.unpack_from("<I", x86, table + index * 56)[0] == 1]
    if not loads:
        raise AssertionError("actual x86 ELF has no load record")
    first = loads[0]
    dynamic = bytearray(x86)
    struct.pack_into("<I", dynamic, first, 3)
    refused("runtime_interpreter", lambda: checker.elf("x86_64", dynamic))
    missing_entry = bytearray(x86)
    struct.pack_into("<Q", missing_entry, 24, (1 << 64) - 1)
    refused("entry_outside_file_backing", lambda: checker.elf("x86_64", missing_entry))
    oversized = bytearray(x86)
    struct.pack_into("<QQ", oversized, first + 32, len(x86) + 1, len(x86) + 1)
    refused("load_file_extent", lambda: checker.elf("x86_64", oversized))
    overflow = bytearray(x86)
    struct.pack_into("<Q", overflow, first + 16, (1 << 64) - 1)
    refused("load_memory_overflow", lambda: checker.elf("x86_64", overflow))

    wrong_owner = bytearray(archives[2])
    wrong_owner[22:30] = b"00000001"
    refused("archive_nonroot_uid", lambda: checker.archive(wrong_owner, x86))
    payload = bytearray(archives[2])
    offset = payload.find(x86)
    if offset < 0:
        raise AssertionError("actual initramfs lacks its exact init ELF")
    payload[offset] ^= 1
    refused("archive_changed_init", lambda: checker.archive(payload, x86))
    refused("archive_extra_block", lambda: checker.archive(archives[2] + bytes(512), x86))
    if len(controls) != len(set(controls)):
        raise AssertionError("artifact controls repeat a name")
    print(json.dumps(dict(schema="crucible.gem5.linux-device-fixture-controls.v1", controls=controls, passed=len(controls), scope="Compiler/artifact data only; no ELF executed, Linux boot, device parity or native rights"), sort_keys=True))


if __name__ == "__main__":
    main()
