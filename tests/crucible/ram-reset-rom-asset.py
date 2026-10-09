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
    parser.add_argument("--nm", default="nm")
    parser.add_argument("--wire-reference", type=Path, required=True)
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
    symbols = {}
    for line in subprocess.check_output([args.nm, "-n", str(args.elf)],
                                        text=True, timeout=5).splitlines():
        fields = line.split()
        if len(fields) == 3:
            symbols[fields[2]] = int(fields[0], 16)
    wire = args.wire_reference.read_bytes()
    assert len(wire) == 81 + 3 * 128
    registration = symbols["registration_template"]
    request = symbols["request_template"]
    assert image[registration:registration + 81] == wire[:81]
    assert image[request:request + 128] == wire[81:81 + 128]
    for marker in ("READY", "WRITTEN", "RESEEDED", "BAD_SEED", "BAD_COMMAND"):
        assert image.count(f"\nRESET_ROM_{marker}_V1\n\0".encode()) == 1

    instructions = subprocess.check_output(
        [args.objdump, "-d", "-m", "i386", "--insn-width=16", str(args.elf)],
        text=True, timeout=5)
    # Exact symbol slices keep a boot decoder's mixed-mode output out of this check.
    write = instructions.split("<write_payload>:\n", 1)[1].split("<payload_written>:", 1)[0]
    assert "mov    %al,(%edi)" in write and "sub    $0x11,%al" in write
    verify = instructions.split("<verify_seed>:\n", 1)[1].split("<seed_checked>:", 1)[0]
    assert "cmp    %al,(%edi)" in verify and "add    $0x11,%al" in verify

    baseline = instructions.split("<baseline_boundary>:\n", 1)[1].split("<write_payload>:", 1)[0]
    written_boundary = instructions.split("<written_boundary>:\n", 1)[1].split("<seed_failed>:", 1)[0]
    for boundary in (baseline, written_boundary):
        assert "out    %al,$0xe7" in boundary
        assert "<validate_reply>" in boundary and "<command_failed>" in boundary
        assert "test   %eax,%eax" in boundary

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
        "control": "existing flight.ready v1 Selected Unit, sequence2 before stores and sequence3 after stores",
        "reset_boundary": "host system_reset only after WRITTEN; warm guest latch requires original canonical RAM custody",
        "serial": "output only; no UART command input",
        "scope": "assembled guest asset only; actual ROM reset and RAM root remain unexecuted",
    }, indent=2) + "\n")
    print("PASS: reset vector, five markers, actual encoder bytes/reply gates, writer/seed instructions, independent complemented payload")


if __name__ == "__main__":
    main()
