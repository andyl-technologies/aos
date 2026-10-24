"""Checks qboot's actual freestanding compiler/link products before installation."""

import hashlib
import json
from pathlib import Path
import struct
import sys


def artifact(path, root):
    body = path.read_bytes()
    if not body:
        raise ValueError(f"Empty compiled product: {path}")
    return {
        "path": str(path.relative_to(root)),
        "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
    }


def main():
    build = Path(sys.argv[1])
    output = Path(sys.argv[2])
    linked = build / "bios.bin.elf"
    image = linked.read_bytes()
    header = image[:52]
    if len(header) != 52 or header[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("The actual linked firmware is not little-endian ELF32")
    elf_type, machine = struct.unpack_from("<HH", header, 16)
    if elf_type != 2 or machine != 3:
        raise ValueError("The actual firmware is not an executable i386 link product")

    program_offset = struct.unpack_from("<I", header, 28)[0]
    program_stride, program_count = struct.unpack_from("<HH", header, 42)
    if program_stride != 32 or not 1 <= program_count <= 32:
        raise ValueError("The firmware program-header geometry is unsupported")
    if program_offset + program_stride * program_count > len(image):
        raise ValueError("The firmware program-header inventory is truncated")
    for index in range(program_count):
        kind = struct.unpack_from("<I", image, program_offset + index * program_stride)[0]
        if kind in (2, 3):
            raise ValueError("Dynamic or interpreted firmware cannot boot as a raw ROM")
    if (build / "bios.bin").stat().st_size != 65_536:
        raise ValueError("The raw firmware must occupy its original complete 64 KiB ROM")

    objects = sorted((build / "bios.bin.elf.p").glob("*.o"))
    if len(objects) != 15:
        raise ValueError("The actual compiler object roster is incomplete")
    commands = build / "compile-commands.txt"
    dependencies = build / "compiler-dependencies.txt"
    if b"-nostdlib" not in commands.read_bytes():
        raise ValueError("The original freestanding linker invocation is absent")
    if not dependencies.read_bytes():
        raise ValueError("The actual compiler dependency journal is absent")

    products = [build / "bios.bin", linked, commands, dependencies, *objects]
    result = {
        "schema": "aos.qemu.firmware.qboot-source-products.v1",
        "scope": "Compiler/link products only; guest boot and device behavior require separate tests",
        "products": [artifact(path, build) for path in products],
    }
    output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
