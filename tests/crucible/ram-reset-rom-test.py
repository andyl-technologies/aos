# SPDX-License-Identifier: Apache-2.0
"""Reject actual assembled reset-vector, store, and milestone mutations."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def run(command):
    return subprocess.run(command, check=True, capture_output=True, timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--checker", type=Path, required=True)
    parser.add_argument("--objcopy", default="objcopy")
    parser.add_argument("--objdump", default="objdump")
    parser.add_argument("--nm", default="nm")
    parser.add_argument("--ld", default="ld")
    parser.add_argument("--reply-control-object", type=Path, required=True)
    parser.add_argument("--reply-decoder-object", type=Path, required=True)
    parser.add_argument("--wire-reference", type=Path, required=True)
    args = parser.parse_args()
    symbols = {}
    for line in run([args.nm, "-n", str(args.elf)]).stdout.decode().splitlines():
        fields = line.split()
        if len(fields) == 3:
            symbols[fields[2]] = int(fields[0], 16)

    with tempfile.TemporaryDirectory(prefix="reset-rom-controls-") as temporary:
        directory = Path(temporary)
        sections = {}
        for section in (".text", ".reset"):
            path = directory / (section + ".bin")
            run([args.objcopy, "--dump-section", f"{section}={path}",
                 str(args.elf), str(directory / (section + ".elf"))])
            sections[section] = path.read_bytes()

        for name, section, offset, replacement in (
            ("bad-reset-vector", ".reset", 0, 0x90),
            ("missing-writer-store", ".text", symbols["write_payload"], 0x90),
            ("missing-ready-marker", ".text", symbols["ready_marker"] + 1, ord("!")),
            ("missing-baseline-reply-call", ".text", symbols["baseline_reply_call"], 0x90),
        ):
            changed = bytearray(sections[section])
            assert changed[offset] != replacement
            changed[offset] = replacement
            payload = directory / (name + ".section")
            payload.write_bytes(changed)
            elf = directory / (name + ".elf")
            image = directory / (name + ".bin")
            run([args.objcopy, "--update-section", f"{section}={payload}",
                 str(args.elf), str(elf)])
            run([args.objcopy, "-O", "binary", str(elf), str(image)])
            result = subprocess.run(
                [sys.executable, str(args.checker), "--rom", str(image),
                 "--elf", str(elf), "--objcopy", args.objcopy,
                 "--objdump", args.objdump, "--nm", args.nm,
                 "--wire-reference", str(args.wire_reference),
                 "--output", str(directory / name)],
                capture_output=True, timeout=10)
            assert result.returncode != 0 and b"AssertionError" in result.stderr, name
            assert not (directory / name / "asset.json").exists(), name

        object_symbols = {}
        for line in run([args.nm, "-n", str(args.reply_decoder_object)]).stdout.decode().splitlines():
            fields = line.split()
            if len(fields) == 3:
                object_symbols[fields[2]] = int(fields[0], 16)
        body = directory / "rom-object-text.bin"
        run([args.objcopy, "--dump-section", f".text.reply={body}",
             str(args.reply_decoder_object), str(directory / "object-copy.o")])
        changed = bytearray(body.read_bytes())
        offset = object_symbols["reply_first_guard"]
        length = 2 if changed[offset] == 0x75 else 6
        assert changed[offset:offset + 2] == b"\x0f\x85" or length == 2
        changed[offset:offset + length] = b"\x90" * length
        body.write_bytes(changed)
        mutant_object = directory / "omitted-reply-guard.o"
        run([args.objcopy, "--update-section", f".text.reply={body}",
             str(args.reply_decoder_object), str(mutant_object)])
        mutant = directory / "omitted-reply-guard"
        run([args.ld, "-m", "elf_i386", "-e", "_start",
             str(args.reply_control_object), str(mutant_object), "-o", str(mutant)])
        result = subprocess.run([str(mutant)], timeout=5)
        assert result.returncode == 3, result.returncode

    print(json.dumps({"negative_cases": 4, "actual_reply_guard_mutant_refused": True,
                      "scope": "actual ELF/ROM and decoder mutations only; no reset machine execution"}))


if __name__ == "__main__":
    main()
