# SPDX-License-Identifier: MIT
"""Packs a deterministic newc initramfs without host mounts or device nodes."""
from pathlib import Path
import stat
import sys

if len(sys.argv) != 3:
    raise RuntimeError("expected source-built init ELF and archive destination")

source, destination = map(Path, sys.argv[1:])
payload = source.read_bytes()
if not payload.startswith(b"\x7fELF") or not 0 < len(payload) <= 16 * 1024 * 1024:
    raise RuntimeError("guest init must be a bounded source-built ELF")

archive = bytearray()


def entry(name, mode, data=b"", device_major=0, device_minor=0):
    """Writes one fixed-identity, epoch-timestamp newc record."""
    encoded = name.encode("ascii") + b"\x00"
    fields = [1, mode, 0, 0, 1, 0, len(data), 0, 0,
              device_major, device_minor, len(encoded), 0]
    archive.extend(b"070701" + b"".join(f"{value:08x}".encode("ascii") for value in fields))
    archive.extend(encoded)
    archive.extend(bytes(-len(archive) % 4))
    archive.extend(data)
    archive.extend(bytes(-len(archive) % 4))


entry("dev", stat.S_IFDIR | 0o755)
entry("dev/console", stat.S_IFCHR | 0o600, device_major=5, device_minor=1)
entry("proc", stat.S_IFDIR | 0o755)
entry("sys", stat.S_IFDIR | 0o755)
entry("init", stat.S_IFREG | 0o755, payload)
entry("TRAILER!!!", 0)
archive.extend(bytes(-len(archive) % 512))
destination.write_bytes(archive)
