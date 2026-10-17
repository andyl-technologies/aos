# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise the actual bounded root early-pin grammar on both system binaries.

The fixture commitments are parser inputs, not authenticated preparations.
Successful help parsing does not construct a machine or qualify any profile.
"""

import os
from pathlib import Path
import socket
import struct
import subprocess
import sys


def exercise(binary):
    endpoint, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        identity = os.fstat(endpoint.fileno())
        digest = lambda value: bytes([value]) + bytes(31)
        common = digest(1) + digest(2) + digest(3) + digest(4)
        initial = common + struct.pack("<II", 7, 64)
        phase = common + struct.pack("<IQ", 1, 64)
        administrative = common + struct.pack(
            "<IIiIQQ", 1, 1, endpoint.fileno(), 0,
            identity.st_dev, identity.st_ino)
        body = (digest(1) + digest(5) + digest(3) + digest(6) +
                digest(2) + digest(2) + digest(2) + digest(7) +
                struct.pack("<5Q6I", 65536, 32 * 1024 * 1024, 8254,
                            64, 1000, 2, 7, 1, 1, 64, 0))
        assert len(body) == 320
        companions = [
            "-crucible-node-initialization", "v1:" + initial.hex(),
            "-crucible-node-phase", "v1:" + phase.hex(),
            "-crucible-node-administration", "v1:" + administrative.hex(),
        ]
        count = 0

        def run(label, pin, tail=(), expected="invalid or duplicate original native root policy"):
            nonlocal count
            result = subprocess.run(
                [str(binary), "-crucible-node-root", pin, *tail, "-help"],
                pass_fds=(endpoint.fileno(),), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=5)
            if expected is None:
                assert result.returncode == 0, (label, result.stderr)
            else:
                assert result.returncode != 0 and expected.encode() in result.stderr, (
                    label, result.returncode, result.stderr)
            count += 1

        original = "v1:" + body.hex()
        run("valid grammar only", original, companions, expected=None)
        for label, argument in (
            ("short", original[:-1]), ("long", original + "0"),
            ("version", "v2:" + body.hex()),
            ("nonhex", "v1:g" + body.hex()[1:]),
        ):
            run(label, argument, companions)
        for offset in range(0, 256, 32):
            changed = bytearray(body)
            changed[offset:offset + 32] = bytes(32)
            run("zero original digest", "v1:" + changed.hex(), companions)
        for label, offset, size, value in (
            ("firmware small", 256, 8, 65535),
            ("firmware large", 256, 8, 16 * 1024 * 1024 + 1),
            ("RAM small", 264, 8, 16 * 1024 * 1024 - 1),
            ("RAM large", 264, 8, 3 * 1024 * 1024 * 1024 + 1),
            ("microstep zero", 280, 8, 0),
            ("microstep large", 280, 8, 1000001),
            ("service zero", 288, 8, 0),
            ("service large", 288, 8, 10000001),
            ("mapping", 296, 4, 1), ("controller", 300, 4, 6),
            ("profile", 304, 4, 2), ("digest algorithm", 308, 4, 2),
            ("budget zero", 312, 4, 0), ("budget large", 312, 4, 65),
            ("reserved", 316, 4, 1),
        ):
            changed = bytearray(body)
            changed[offset:offset + size] = value.to_bytes(size, "little")
            run(label, "v1:" + changed.hex(), companions)
        mismatch = "native root policy requires its complete original Realize companions"
        run("missing companions", original, expected=mismatch)
        for offset in (0, 64, 128, 160, 192, 280):
            changed = bytearray(body)
            changed[offset] ^= 0x80
            run("foreign original companion", "v1:" + changed.hex(),
                companions, expected=mismatch)
        run("duplicate", original, [*companions, "-crucible-node-root", original])
        run("restore", original, [*companions, "-incoming", "defer"],
            expected="native initialization requires an original fresh machine")
        run("constructor override", original, [*companions, "-cpu", "max"],
            expected="fixed microvm root policy refuses CPU/global constructor overrides")
        print(f"PASS {binary.name}: actual root early argv {count} cases; grammar only, no machine/Ready")
    finally:
        endpoint.close()
        peer.close()


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: native-root-argv.py QEMU_X86 QEMU_AARCH64")
    for name in sys.argv[1:]:
        exercise(Path(name).resolve())


if __name__ == "__main__":
    main()
