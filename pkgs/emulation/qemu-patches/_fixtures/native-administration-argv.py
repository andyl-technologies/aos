# SPDX-License-Identifier: GPL-2.0-or-later
"""Check actual early-pin parsing and OS descriptors on both system binaries.

Fixture digests exercise grammar and original companion equality. They are not
an authenticated preparation, reader enrollment, or execution qualification.
"""

import os
from pathlib import Path
import socket
import struct
import subprocess
import sys


def check_binary(qemu):
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        identity = os.fstat(left.fileno())
        scope = bytes([1]) + bytes(31)
        commit = bytes([2]) + bytes(31)
        realize = bytes([3]) + bytes(31)
        policy = bytes([4]) + bytes(31)
        prefix = scope + commit + realize + policy
        body = prefix + struct.pack(
            "<IIiIQQ", 1, 1, left.fileno(), 0, identity.st_dev, identity.st_ino)
        phase = prefix + struct.pack("<IQ", 1, 64)
        initial = prefix + struct.pack("<II", 7, 64)
        assert (len(body), len(phase), len(initial)) == (160, 140, 136)
        original = "v1:" + body.hex()
        companions = ["-crucible-node-phase", "v1:" + phase.hex(),
                      "-crucible-node-initialization", "v1:" + initial.hex()]
        count = 0

        def run(label, pin, tail=(), expected="invalid or duplicate original native reader pin", inherited=None):
            nonlocal count
            result = subprocess.run(
                [str(qemu), "-crucible-node-administration", pin, *tail, "-help"],
                pass_fds=tuple(inherited or (left.fileno(),)),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            if expected is None:
                assert result.returncode == 0, (label, result.stderr)
            else:
                assert result.returncode != 0 and expected.encode() in result.stderr, (
                    label, result.returncode, result.stderr)
            count += 1

        run("valid socket/parser only", original, companions, expected=None)
        run("missing companion", original,
            expected="native reader pin requires its original phase Realize")
        for label, value in (
            ("short", original[:-1]), ("long", original + "0"),
            ("version", "v2:" + body.hex()), ("nonhex", "v1:g" + body.hex()[1:]),
        ):
            run(label, value, companions)

        for label, offset, packed in (
            ("kind", 128, struct.pack("<I", 2)),
            ("count", 132, struct.pack("<I", 2)),
            ("negative descriptor", 136, struct.pack("<i", -1)),
            ("reserved", 140, struct.pack("<I", 1)),
            ("wrong device", 144, struct.pack("<Q", identity.st_dev ^ 1)),
            ("wrong inode", 152, struct.pack("<Q", identity.st_ino ^ 1)),
        ):
            changed = bytearray(body)
            changed[offset:offset + len(packed)] = packed
            run(label, "v1:" + changed.hex(), companions)

        for offset in (0, 32, 64, 96):
            changed = bytearray(body)
            changed[offset:offset + 32] = bytes(32)
            run("zero digest", "v1:" + changed.hex(), companions)
        changed = bytearray(body)
        changed[64] ^= 1
        run("foreign Realize", "v1:" + changed.hex(), companions,
            expected="native reader pin requires its original phase Realize")
        run("duplicate", original,
            [*companions, "-crucible-node-administration", original])
        run("captured cut", original, [*companions, "-incoming", "defer"],
            expected="native initialization requires an original fresh machine")

        stream, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            changed = bytearray(body)
            stream_stat = os.fstat(stream.fileno())
            changed[136:140] = struct.pack("<i", stream.fileno())
            changed[144:160] = struct.pack("<QQ", stream_stat.st_dev, stream_stat.st_ino)
            run("wrong stream", "v1:" + changed.hex(), companions,
                inherited=(stream.fileno(),))
        finally:
            stream.close()
            peer.close()

        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as unconnected:
            changed = bytearray(body)
            unconnected_stat = os.fstat(unconnected.fileno())
            changed[136:140] = struct.pack("<i", unconnected.fileno())
            changed[144:160] = struct.pack(
                "<QQ", unconnected_stat.st_dev, unconnected_stat.st_ino)
            run("unconnected", "v1:" + changed.hex(), companions,
                inherited=(unconnected.fileno(),))
        print(f"PASS {qemu.name}: native administrative early argv {count} cases; no qualification")
    finally:
        left.close()
        right.close()


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: native-administration-argv.py QEMU_X86 QEMU_AARCH64")
    for binary in sys.argv[1:]:
        check_binary(Path(binary).resolve())


if __name__ == "__main__":
    main()
