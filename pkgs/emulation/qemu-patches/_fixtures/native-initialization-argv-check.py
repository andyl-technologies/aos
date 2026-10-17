# SPDX-License-Identifier: GPL-2.0-or-later
"""Checks preparation-only native argv refusal on an actual source-built emulator.

These deliberately synthetic authorization bytes test parser and lifecycle
mechanics only. They never qualify a CNP realization, execution or Ready proof.
The timeout owns, kills and reaps every child if a refusal fails to terminate.
"""

import argparse
import subprocess


def authorization(classes=7, maximum=64, digests=None):
    if digests is None:
        digests = bytes([1]) * 128
    return "v1:" + (
        digests + classes.to_bytes(4, "little") + maximum.to_bytes(4, "little")
    ).hex()


def refuse(qemu, arguments, expected):
    result = subprocess.run(
        [qemu, *arguments, "-machine", "none", "-display", "none",
         "-nodefaults", "-accel", "sim", "-icount",
         "shift=0,align=off,sleep=off"],
        capture_output=True, timeout=5, check=False,
    )
    if result.returncode != 1 or expected not in result.stderr:
        raise AssertionError(
            f"native refusal mismatch: exit={result.returncode} "
            f"stderr={result.stderr!r}"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu", help="Matching source-built system emulator")
    args = parser.parse_args()
    valid = authorization()
    invalid = (
        valid.replace("v1:", "v2:", 1), valid[:-1], valid + "0",
        "v1:A" + valid[4:], authorization(classes=0),
        authorization(classes=8), authorization(maximum=0),
        authorization(maximum=65), authorization(digests=bytes(128)),
    )

    for value in invalid:
        refuse(args.qemu, ["-crucible-node-initialization", value],
               b"invalid or duplicate original native initialization pin")
    refuse(args.qemu,
           ["-crucible-node-initialization", valid,
            "-crucible-node-initialization", valid],
           b"invalid or duplicate original native initialization pin")
    for option, operand in (("-loadvm", "original"),
                            ("-incoming", "defer"), ("-preconfig", None)):
        extra = [option] + ([operand] if operand is not None else [])
        refuse(args.qemu, ["-crucible-node-initialization", valid, *extra],
               b"native initialization requires an original fresh machine")
    refuse(args.qemu, ["-crucible-node-initialization", valid],
           b"native initialization pin lacks matching callbacks")

    # An option's operand cannot silently become initialization authority.
    result = subprocess.run(
        [args.qemu, "-name", "-crucible-node-initialization", "-version"],
        capture_output=True, timeout=5, check=False,
    )
    if result.returncode != 0:
        raise AssertionError("ordinary argv operand acquired native pin")
    print("PASS 14 native preparation refusals; ordinary argv operand preserved")


if __name__ == "__main__":
    main()
