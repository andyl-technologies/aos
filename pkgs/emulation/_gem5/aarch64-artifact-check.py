# SPDX-License-Identifier: MIT
"""Checks cross-built ARM fixture identity without executing it on the host."""

from pathlib import Path
import hashlib
import json
import struct
import sys


def aarch64_elf(path, relocatable_kernel=False):
    """Requires a static little-endian AArch64 executable with bounded segments."""
    data = path.read_bytes()
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("fixture lacks an ELF64 little-endian header")
    kind, machine, version = struct.unpack_from("<HHI", data, 16)
    entry, offset = struct.unpack_from("<QQ", data, 24)
    header_size, segment_size, segment_count = struct.unpack_from("<HHH", data, 52)
    allowed_kinds = (2, 3) if relocatable_kernel else (2,)
    if (kind not in allowed_kinds or machine != 183 or version != 1 or header_size != 64
            or segment_size != 56 or not 0 < segment_count <= 128
            or offset + segment_size * segment_count > len(data)):
        raise ValueError("fixture ELF dimensions or architecture differ")
    executable_entry = False
    for index in range(segment_count):
        kind, flags, file_offset, address, physical, file_size, memory_size, alignment = struct.unpack_from(
            "<IIQQQQQQ", data, offset + index * segment_size)
        if kind == 3:
            raise ValueError("cross fixture requires a runtime interpreter")
        if kind == 1:
            if file_size > memory_size or file_offset + file_size > len(data):
                raise ValueError("ELF load segment extends beyond its file")
            executable_entry |= bool(flags & 1 and address <= entry < address + memory_size)
    if not executable_entry:
        raise ValueError("fixture entry does not belong to executable storage")


mode, root = sys.argv[1], Path(sys.argv[2])
if mode == "kernel":
    # arm64 defconfig retains relocatable/KASLR kernels; ET_DYN is expected.
    aarch64_elf(root / "boot/vmlinux", relocatable_kernel=True)
    image = (root / "boot/Image").read_bytes()
    if len(image) < 64 or struct.unpack_from("<I", image, 56)[0] != 0x644d5241:
        raise ValueError("kernel Image lacks the arm64 boot header")
    size, = struct.unpack_from("<Q", image, 16)
    # image_size is the required in-memory extent, including zero-filled BSS.
    # The flat Image omits that tail; it must fit inside the declared extent.
    if not len(image) <= size <= 512 * 1024 * 1024:
        raise ValueError("kernel Image exceeds its bounded in-memory extent")
    if not (root / "include/asm/unistd.h").is_file():
        raise ValueError("fixture lacks sanitized AArch64 syscall headers")
elif mode == "init":
    aarch64_elf(root / "init")
elif mode == "executable":
    aarch64_elf(root)
elif mode == "source":
    binary = Path(sys.argv[3])
    if (binary / "share/corresponding-source").resolve() != root.resolve():
        raise ValueError("binary output does not co-retain its corresponding source")
    manifest = json.loads((root / "source-manifest.json").read_bytes())
    if manifest["schema"] != "aos.linux.corresponding-source.v1":
        raise ValueError("kernel corresponding-source identity differs")

    def digest(path):
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()

    if digest(root / "linux-upstream.tar.xz") != digest(Path(manifest["upstreamSource"])):
        raise ValueError("complete source archive differs from the pinned upstream source")
    if digest(root / "build/recipe.nix") != manifest["recipeSha256"]:
        raise ValueError("corresponding build recipe differs")
    for patch in manifest["patches"]:
        if digest(root / "patches" / patch["file"]) != patch["sha256"]:
            raise ValueError("corresponding source patch differs")
    if (root / "build/config").read_bytes() != (binary / "boot/.config").read_bytes():
        raise ValueError("corresponding resolved kernel configuration differs")
    for record in (root / "binary-bindings.sha256").read_text().splitlines():
        expected, name = record.split(None, 1)
        if name not in ("Image", "vmlinux", "System.map", ".config"):
            raise ValueError("unexpected kernel binary commitment")
        if digest(binary / "boot" / name) != expected:
            raise ValueError("kernel binary commitment differs")
else:
    raise ValueError("unknown fixture artifact kind")
print(f"source-built AArch64 {mode} identity passed")
