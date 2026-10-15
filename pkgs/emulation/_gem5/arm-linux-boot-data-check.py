# SPDX-License-Identifier: MIT
"""Checks ARM loader and required-kernel predicates using bounded data only."""

import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile


def load(name, source):
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def refused(action, expected=None):
    try:
        action()
    except ValueError as error:
        if expected is not None and expected not in str(error):
            raise ValueError("data mutation refused for an unrelated predicate") from error
        return
    raise ValueError("data mutation was unexpectedly accepted")


def elf(path, physical, virtual, entry, memory=4096, machine=183, elf_type=2):
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", header, 16, elf_type, machine, 1, entry, 64, 0, 0,
                     64, 56, 1, 0, 0, 0)
    segment = struct.pack("<IIQQQQQQ", 1, 5, 0, virtual, physical, 120, memory, 1)
    path.write_bytes(header + segment)


def main():
    if len(sys.argv) != 3:
        raise ValueError("expected complete helper directory and actual specification")
    directory = Path(sys.argv[1])
    bundle = load("arm_data_control_bundle", directory / "arm-linux-bundle.py")
    loader = load("arm_data_control_loader", directory / "arm-linux-loader.py")
    selected = bundle.read_json(sys.argv[2])["artifacts"]
    actual = loader.validate_loader(*(Path(selected[name]) for name in ("kernel", "initramfs", "firmware")))
    bundle.validate_kernel_configuration(selected["kernel_configuration"])
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        kernel, firmware, initrd, config = (root / name for name in ("kernel", "firmware", "initrd", "config"))
        initrd.write_bytes(b"original finite initramfs")
        elf(kernel, 0xFFFF800080000000, 0xFFFF800080000000, 0xFFFF800080000000)
        elf(firmware, 0x10, 0x10, 0x10, memory=120)
        geometry = loader.validate_loader(kernel, initrd, firmware)
        if geometry["kernel_entry"] != str(0x80000000):
            raise ValueError("original ARM mask/offset did not match the data fixture")
        if geometry["kernel_mask"] != "8191":
            raise ValueError("native exclusive maxAddr convention was lost")
        elf(kernel, 0, 0, 0, elf_type=3)
        if loader.validate_loader(kernel, initrd, firmware)["kernel_entry"] != str(0x80000000):
            raise ValueError("ARM position-independent kernel data was not preserved")
        elf(kernel, 0, 0, 0, elf_type=1)
        refused(lambda: loader.validate_loader(kernel, initrd, firmware))
        elf(kernel, 0x1FF0, 0x1FF0, 0x1FF0)
        split = loader.validate_loader(kernel, initrd, firmware)
        if split["kernel_segments"] != [
                {"address": 0x80001FF0, "bytes": 120, "kind": "file"},
                {"address": 0x80000068, "bytes": 3976, "kind": "zero"}]:
            raise ValueError("native file/BSS independent relocation was lost")
        elf(kernel, 0, 0x1000, 0x1000)
        refused(lambda: loader.validate_loader(kernel, initrd, firmware), "outside loaded executable")
        elf(kernel, 0, 0, 0, memory=0x07FFFFF9)
        refused(lambda: loader.validate_loader(kernel, initrd, firmware), "overlaps CPU release")
        elf(kernel, (1 << 64) - 4096, (1 << 64) - 4096, (1 << 64) - 4096)
        refused(lambda: loader.validate_loader(kernel, initrd, firmware), "wraps")
        elf(kernel, 0, 0, 0, machine=62)
        refused(lambda: loader.validate_loader(kernel, initrd, firmware))
        elf(kernel, 0, 0, 0, memory=0x10000001)
        refused(lambda: loader.validate_loader(kernel, initrd, firmware))
        elf(kernel, 0, 0, 0, memory=0x08000001)
        refused(lambda: loader.validate_loader(kernel, initrd, firmware))
        elf(kernel, 0, 0, 0)
        elf(firmware, 0x4000000, 0x4000000, 0x4000000, memory=120)
        refused(lambda: loader.validate_loader(kernel, initrd, firmware))
        elf(firmware, 0x10, 0x10, 0x10, memory=120)
        initrd.write_bytes(b"")
        refused(lambda: loader.validate_loader(kernel, initrd, firmware))
        config.write_text("\n".join("CONFIG_" + name + "=y" for name in bundle.REQUIRED_KERNEL))
        bundle.validate_kernel_configuration(config)
        for missing in bundle.REQUIRED_KERNEL:
            config.write_text("\n".join("CONFIG_" + name + "=y" for name in bundle.REQUIRED_KERNEL if name != missing))
            refused(lambda: bundle.validate_kernel_configuration(config))
    print(json.dumps({"schema": "crucible.gem5.arm-linux-boot-data-controls.v1",
                      "actual_loader_geometry": actual, "synthetic_loader_positive": 3,
                      "synthetic_loader_negatives": 9, "missing_kernel_negatives": len(bundle.REQUIRED_KERNEL),
                      "native_execution": False}, sort_keys=True))


if __name__ == "__main__":
    main()
