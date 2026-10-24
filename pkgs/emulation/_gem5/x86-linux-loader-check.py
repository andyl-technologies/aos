# SPDX-License-Identifier: MIT
"""Checks actual file geometry against a source-built x86_64 ELF fixture.

The supplied ELF is built by the original AOS assembler/linker. Mutated copies
exercise refusal boundaries; they are not Linux workloads or native authority.
The recording writer tests exact boot-protocol data, not a running machine.
"""

import importlib.util
import json
from pathlib import Path
import shutil
import struct
import sys


helper, executable, root_name = sys.argv[1:]
specification = importlib.util.spec_from_file_location("crucible_x86_loader_check", helper)
loader = importlib.util.module_from_spec(specification)
sys.modules[specification.name] = loader
specification.loader.exec_module(loader)
root = Path(root_name)
root.mkdir(mode=0o700)
kernel = root / "kernel.elf"
initramfs = root / "initrd.img"
shutil.copyfile(executable, kernel)
initramfs.write_bytes(b"checked\x00initramfs")
original = kernel.read_bytes()
program_offset = struct.unpack_from("<Q", original, 32)[0]
program_count = struct.unpack_from("<H", original, 56)[0]
load_index = next(index for index in range(program_count)
                  if struct.unpack_from("<I", original, program_offset + index * 56)[0] == 1)
load_header = program_offset + load_index * 56
results = []


def refused(name, changed, expected_message=None):
    target = root / (name + ".elf")
    target.write_bytes(changed)
    try:
        loader.validate_loader(target, initramfs)
    except (ValueError, OSError) as error:
        if expected_message is not None:
            assert expected_message in str(error), (name, str(error))
        results.append(name)
    else:
        raise AssertionError("malformed x86 loader geometry was accepted: " + name)


def mutate(offset, form, value):
    changed = bytearray(original)
    struct.pack_into(form, changed, offset, value)
    return changed


class RecordingWriter:
    """Records data-helper write requests without any simulated hardware."""

    def __init__(self):
        self.writes = []

    def write(self, address, body):
        self.writes.append((address, body))


try:
    plan = loader.validate_loader(kernel, initramfs)
    assert plan.kernel_bytes == len(original) and plan.load_segments
    assert plan.entry_point == struct.unpack_from("<Q", original, 24)[0]
    assert plan.initramfs == b"checked\x00initramfs"
    writer = RecordingWriter()
    loader.install_initramfs(writer, plan)
    assert writer.writes == [
        (loader.INITRD_ADDRESS, plan.initramfs),
        (loader.BOOT_PARAMETERS + 0x210, b"\xff"),
        (loader.BOOT_PARAMETERS + 0x218, struct.pack("<II", loader.INITRD_ADDRESS, len(plan.initramfs))),
    ]
    results.append("real-source-built-elf-and-exact-boot-protocol-bytes")

    refused("foreign-aarch64-isa", mutate(18, "<H", 183))
    refused("overflowing-program-table", mutate(32, "<Q", (1 << 64) - 1))
    refused("excessive-header-count", mutate(56, "<H", 129))
    refused("truncated-header-table", original[:program_offset + program_count * 56 - 1])
    refused("load-file-overrun", mutate(load_header + 8, "<Q", len(original)))
    refused("load-file-memory-inversion", mutate(load_header + 40, "<Q", 0))
    refused("initramfs-overlap", mutate(load_header + 24, "<Q", loader.INITRD_ADDRESS))
    refused("boot-parameter-overlap", mutate(load_header + 24, "<Q", loader.BOOT_REGION_START))
    refused("ram-overrun", mutate(load_header + 24, "<Q", loader.RAM_BYTES))
    refused("physical-address-overflow", mutate(load_header + 24, "<Q", (1 << 64) - 1))
    entry_refusal = "entry is outside file-backed native physical load segments"
    refused("entry-outside-physical-load", mutate(24, "<Q", loader.RAM_BYTES), entry_refusal)
    physical_start = struct.unpack_from("<Q", original, load_header + 24)[0]
    file_bytes = struct.unpack_from("<Q", original, load_header + 32)[0]
    bss_entry = mutate(24, "<Q", physical_start + file_bytes)
    struct.pack_into("<Q", bss_entry, load_header + 40, file_bytes + 1)
    refused("entry-in-unbacked-bss", bss_entry, entry_refusal)
    for name, address in [("native-page-table-overlap", 0x70000), ("native-firmware-overlap", 0xF0000)]:
        changed = mutate(load_header + 24, "<Q", address)
        struct.pack_into("<Q", changed, load_header + 48, 1)
        refused(name, changed, "overlaps selected native startup memory")
    refused("virtual-extent-overflow", mutate(load_header + 16, "<Q", (1 << 64) - 1))
    refused("invalid-segment-alignment", mutate(load_header + 48, "<Q", 3))
    alias = root / "kernel-alias.elf"
    alias.symlink_to(kernel.name)
    try:
        loader.validate_loader(alias, initramfs)
    except OSError:
        results.append("symbolic-kernel-alias-refused")
    else:
        raise AssertionError("symbolic loader input was accepted")

    with initramfs.open("wb") as stream:
        stream.truncate(loader.MAXIMUM_INITRD_BYTES + 1)
    try:
        loader.validate_loader(kernel, initramfs)
    except ValueError:
        results.append("oversized-sparse-initramfs-refused-before-copy")
    else:
        raise AssertionError("oversized initramfs reached a body copy")

    print(json.dumps({
        "schema": "crucible.gem5.x86-linux-loader-check.v1",
        "passed": results,
        "native_execution_or_capture_qualified": False,
        "scope": "Real bounded file parser and recorded boot-protocol data only; no native machine or live source admission",
    }, sort_keys=True), flush=True)
finally:
    shutil.rmtree(root)
