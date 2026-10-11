# SPDX-License-Identifier: GPL-2.0-or-later
"""Checks original native phase-policy pins on a source-built emulator.

Synthetic hashes exercise parser, pairing and fresh-construction mechanics.
They confer no CNP authority, source qualification or execution permission.
Every bounded subprocess owns and reaps its child, including on timeout.
"""

import argparse
import subprocess


def initialization():
    return "v1:" + (bytes([1]) * 128 + (7).to_bytes(4, "little")
                    + (64).to_bytes(4, "little")).hex()


def phase(mapping=1, maximum=1_000_000, digests=None):
    if digests is None:
        digests = bytes([1]) * 128
    return "v1:" + (digests + mapping.to_bytes(4, "little")
                    + maximum.to_bytes(8, "little")).hex()


def refuse(qemu, arguments, expected):
    result = subprocess.run(
        [qemu, *arguments, "-machine", "none", "-display", "none",
         "-nodefaults", "-accel", "sim", "-icount",
         "shift=0,align=off,sleep=off"],
        capture_output=True, timeout=5, check=False,
    )
    if result.returncode != 1 or expected not in result.stderr:
        raise AssertionError(
            f"phase refusal mismatch: exit={result.returncode} "
            f"stderr={result.stderr!r}"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu", help="Matching source-built system emulator")
    args = parser.parse_args()
    valid = phase()
    pinned = ["-crucible-node-initialization", initialization()]
    invalid = [valid.replace("v1:", "v2:", 1), valid[:-1], valid + "0",
               "v1:A" + valid[4:], phase(mapping=0), phase(mapping=2),
               phase(maximum=0), phase(maximum=1_000_001)]
    for offset in range(0, 128, 32):
        hashes = bytearray(bytes([1]) * 128)
        hashes[offset:offset + 32] = bytes(32)
        invalid.append(phase(digests=hashes))

    for value in invalid:
        refuse(args.qemu, [*pinned, "-crucible-node-phase", value],
               b"invalid or duplicate original native phase pin")
    refuse(args.qemu, [*pinned, "-crucible-node-phase", valid,
                      "-crucible-node-phase", valid],
           b"invalid or duplicate original native phase pin")
    refuse(args.qemu, ["-crucible-node-phase", valid],
           b"native phase pin requires its original initialization Realize")
    for offset in (0, 64):
        hashes = bytearray(bytes([1]) * 128)
        hashes[offset:offset + 32] = bytes([2]) * 32
        refuse(args.qemu, [*pinned, "-crucible-node-phase",
                          phase(digests=hashes)],
               b"native phase pin requires its original initialization Realize")

    for option, operand in (("-loadvm", "original"),
                            ("-incoming", "defer"), ("-preconfig", None)):
        extra = [option] + ([operand] if operand is not None else [])
        refuse(args.qemu, [*pinned, "-crucible-node-phase", valid, *extra],
               b"native initialization requires an original fresh machine")
    # Both argument orders pin the same original pair before construction.
    for pair in ([*pinned, "-crucible-node-phase", valid],
                 ["-crucible-node-phase", valid, *pinned]):
        refuse(args.qemu, pair,
               b"native initialization pin lacks matching callbacks")

    result = subprocess.run(
        [args.qemu, "-name", "-crucible-node-phase", "-version"],
        capture_output=True, timeout=5, check=False,
    )
    if result.returncode != 0:
        raise AssertionError("ordinary argv operand acquired native phase pin")
    print("PASS 21 phase-policy refusals; ordinary argv operand preserved")


if __name__ == "__main__":
    main()
