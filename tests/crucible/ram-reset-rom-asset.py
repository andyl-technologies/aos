# SPDX-License-Identifier: Apache-2.0
"""Generate the exact loader payload and check the assembled reset ROM.

The asset check establishes encodings and seed bytes, not a machine-reset run.
"""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rom", required=True, type=Path)
    parser.add_argument("--elf", required=True, type=Path)
    parser.add_argument("--objdump", default="objdump")
    parser.add_argument("--objcopy", default="objcopy")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    image = args.rom.read_bytes()
    with tempfile.TemporaryDirectory(prefix="reset-rom-image-") as temporary:
        generated = Path(temporary) / "reset.bin"
        subprocess.run([args.objcopy, "-O", "binary", str(args.elf), str(generated)],
                       check=True, timeout=5)
        assert image == generated.read_bytes(), "ROM does not match its decoded ELF"
    assert len(image) == 65536
    assert image[65520:65525] == bytes.fromhex("ea000000f0")
    assert image[65525:] == bytes(11)
    for marker in ("READY", "WRITTEN", "BAD_SEED", "BAD_COMMAND"):
        assert image.count(f"\nRESET_ROM_{marker}_V1\n\0".encode()) == 1

    instructions = subprocess.check_output(
        [args.objdump, "-d", "-m", "i386", "--insn-width=16", str(args.elf)],
        text=True, timeout=5)
    # Exact symbol slices keep a boot decoder's mixed-mode output out of this check.
    write = instructions.split("<write_payload>:\n", 1)[1].split("<payload_written>:", 1)[0]
    assert "mov    %al,(%edi)" in write and "sub    $0x11,%al" in write
    verify = instructions.split("<verify_seed>:\n", 1)[1].split("<seed_checked>:", 1)[0]
    assert "cmp    %al,(%edi)" in verify and "add    $0x11,%al" in verify

    seed = bytes((0x3D + 17 * index) & 255 for index in range(32))
    written = bytes((0xC2 - 17 * index) & 255 for index in range(32))
    assert all(before ^ after == 255 for before, after in zip(seed, written))
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "loader-seed.bin").write_bytes(seed)
    (args.output / "expected-written.bin").write_bytes(written)
    (args.output / "instructions.txt").write_text(instructions)
    (args.output / "asset.json").write_text(json.dumps({
        "payload_gpa": 1048576,
        "payload_bytes": 32,
        "loader_device": "loader,file=loader-seed.bin,addr=0x100000,force-raw=on",
        "scope": "assembled guest asset only; actual ROM reset and RAM root remain unexecuted",
    }, indent=2) + "\n")
    print("PASS: reset vector, four markers, actual writer/seed instructions, independent complemented payload")


if __name__ == "__main__":
    main()
