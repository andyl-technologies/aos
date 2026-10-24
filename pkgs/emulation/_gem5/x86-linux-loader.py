# SPDX-License-Identifier: MIT
"""Checks fixed x86 Linux loader geometry before any native memory writes.

This module owns bounded data validation and the final initramfs bytes. It does
not freeze kernel file contents through later native loading, authenticate a
process owner, qualify a capture, or grant execution authority. The source-owned
model must separately bind private assets and its complete native installation.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import stat
import struct


RAM_BYTES = 256 * 1024 * 1024
INITRD_ADDRESS = 192 * 1024 * 1024
MAXIMUM_INITRD_BYTES = 32 * 1024 * 1024
MAXIMUM_KERNEL_BYTES = 1024 * 1024 * 1024
MAXIMUM_PROGRAM_HEADERS = 128
BOOT_PARAMETERS = 0x90200
BOOT_REGION_START = 0x90000
BOOT_REGION_END = 0xA0000
# The fixed native startup writes paging/GDT, Linux data and firmware tables
# below 1MiB. This selected loader reserves the complete low-memory region.
NATIVE_RESERVED_END = 0x100000


@dataclass(frozen=True)
class X86LinuxLoaderPlan:
    """Retains checked original loader extents and final initramfs bytes."""

    kernel_bytes: int
    entry_point: int
    load_segments: tuple
    initramfs: bytes

    def describe(self):
        """Reports data geometry without a native ownership or closure claim."""
        return {
            "schema": "crucible.gem5.x86-linux-loader.v1",
            "ram_bytes": str(RAM_BYTES),
            "kernel_bytes": str(self.kernel_bytes),
            "entry_point": str(self.entry_point),
            "load_addr_mask": str((1 << 64) - 1),
            "load_addr_offset": "0",
            "native_reserved_range": ["0", str(NATIVE_RESERVED_END)],
            "kernel_load_segments": [[str(start), str(size)] for start, size in self.load_segments],
            "initramfs_address": str(INITRD_ADDRESS),
            "initramfs_bytes": str(len(self.initramfs)),
            "boot_parameters": str(BOOT_PARAMETERS),
            "linux_boot_protocol": "x86-boot-params-initrd-low32-v1",
        }


def _identity(metadata):
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_nlink,
    )


def _extent(start, size, limit):
    if not 0 <= start <= limit or not 0 <= size <= limit - start:
        raise ValueError("x86 loader extent exceeds its original finite region")
    return start + size


def _overlap(start, end, other_start, other_end):
    return start < other_end and other_start < end


def _open_regular(path, maximum):
    descriptor = os.open(Path(path), os.O_RDONLY | os.O_NOFOLLOW)
    stream = os.fdopen(descriptor, "rb")
    try:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= maximum:
            raise ValueError("x86 loader input is not a finite nonempty regular file")
        return stream, metadata
    except BaseException:
        stream.close()
        raise


def validate_loader(kernel_path, initramfs_path):
    """Validates complete ELF header extents and owned initramfs placement.

    The exact selected profile uses a little-endian executable x86_64 ELF,
    256 MiB RAM, at most 128 program headers and at most 32 MiB initramfs at
    192 MiB. All file and physical extents are checked before the initramfs is
    copied. Returned bytes are inert; this function never writes guest memory.
    """
    image, image_before = _open_regular(initramfs_path, MAXIMUM_INITRD_BYTES)
    with image:
        initrd_end = _extent(INITRD_ADDRESS, image_before.st_size, RAM_BYTES)
        kernel, kernel_before = _open_regular(kernel_path, MAXIMUM_KERNEL_BYTES)
        with kernel:
            header = kernel.read(64)
            if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
                raise ValueError("x86 loader requires a complete little-endian ELF64 header")
            kind, machine, version = struct.unpack_from("<HHI", header, 16)
            if kind != 2 or machine != 62 or version != 1:
                raise ValueError("x86 loader requires the selected executable x86_64 ABI")
            header_size, entry_size, count = struct.unpack_from("<HHH", header, 52)
            if header_size != 64 or entry_size != 56 or not 0 < count <= MAXIMUM_PROGRAM_HEADERS:
                raise ValueError("x86 loader program header geometry is unsupported")
            entry_point = struct.unpack_from("<Q", header, 24)[0]
            offset = struct.unpack_from("<Q", header, 32)[0]
            _extent(offset, count * entry_size, kernel_before.st_size)
            kernel.seek(offset)
            headers = kernel.read(count * entry_size)
            if len(headers) != count * entry_size:
                raise ValueError("x86 loader program header table was truncated")

            segments = []
            entry_is_backed = False
            for index in range(count):
                fields = struct.unpack_from("<IIQQQQQQ", headers, index * entry_size)
                kind, _, file_offset, virtual, physical, file_size, memory_size, alignment = fields
                if kind != 1:
                    continue
                if file_size > memory_size:
                    raise ValueError("x86 load segment has more file bytes than memory backing")
                _extent(file_offset, file_size, kernel_before.st_size)
                _extent(virtual, memory_size, 1 << 64)
                end = _extent(physical, memory_size, RAM_BYTES)
                if alignment > 1 and (alignment & (alignment - 1) or file_offset % alignment != physical % alignment or file_offset % alignment != virtual % alignment):
                    raise ValueError("x86 load segment alignment differs from its file offset")
                if not memory_size:
                    continue
                if _overlap(physical, end, INITRD_ADDRESS, initrd_end):
                    raise ValueError("x86 kernel load backing overlaps the retained initramfs")
                if _overlap(physical, end, 0, NATIVE_RESERVED_END):
                    raise ValueError("x86 kernel load backing overlaps selected native startup memory")
                for start, size in segments:
                    if _overlap(physical, end, start, start + size):
                        raise ValueError("x86 kernel physical load backing overlaps another segment")
                # The actual native loader installs p_paddr and the unchanged
                # ELF entry under identity paging. Virtual ELF symbols do not
                # translate this initial PC; a BSS-only entry is unqualified.
                if physical <= entry_point < physical + file_size:
                    entry_is_backed = True
                segments.append((physical, memory_size))
            if not segments:
                raise ValueError("x86 kernel has no nonempty native load segment")
            if not entry_is_backed:
                raise ValueError("x86 entry is outside file-backed native physical load segments")
            if _identity(kernel_before) != _identity(os.fstat(kernel.fileno())):
                raise ValueError("x86 kernel header custody changed during loader validation")

        payload = image.read(image_before.st_size)
        if len(payload) != image_before.st_size or image.read(1):
            raise ValueError("x86 initramfs changed its checked original extent")
        if _identity(image_before) != _identity(os.fstat(image.fileno())):
            raise ValueError("x86 initramfs custody changed during its bounded read")
        return X86LinuxLoaderPlan(kernel_before.st_size, entry_point, tuple(segments), payload)


def install_initramfs(physical_proxy, plan):
    """Writes only the prevalidated bytes and fixed Linux boot-protocol fields.

    The native model invokes this once after its genuine kernel loader and
    before servicing callbacks. This data helper provides no admission or
    rollback guarantee if an actual native write fails after prior effects.
    """
    if type(plan) is not X86LinuxLoaderPlan:
        raise ValueError("x86 native loader lacks its checked source-selected data plan")
    _extent(INITRD_ADDRESS, len(plan.initramfs), RAM_BYTES)
    if not 0 < len(plan.initramfs) <= MAXIMUM_INITRD_BYTES:
        raise ValueError("x86 original initramfs extent differs from its checked plan")
    physical_proxy.write(INITRD_ADDRESS, plan.initramfs)
    physical_proxy.write(BOOT_PARAMETERS + 0x210, b"\xff")
    physical_proxy.write(BOOT_PARAMETERS + 0x218, struct.pack("<II", INITRD_ADDRESS, len(plan.initramfs)))
