"""Binds emitted instruction counts/encodings to the closed CPU profiles.

This is a build-time artifact check, never a native dirty-tracking/VM result.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

PROFILES = (
    ("scalar8", 1, "mov"), ("scalar16", 1, "mov"), ("scalar32", 1, "mov"),
    ("unaligned32", 1, "mov"), ("cross-page32", 1, "mov"),
    ("exchange8", 1, "xchg"), ("exchange16", 1, "xchg"), ("exchange32", 1, "xchg"),
    ("unaligned-exchange32", 1, "xchg"), ("cross-page-exchange32", 1, "xchg"),
    ("compare-exchange64", 5, "cmpxchg8b"), ("failed-compare-exchange32", 6, "cmpxchg"),
    ("vector128", 3, "movdqa"), ("unaligned-vector128", 3, "movdqu"),
    ("cross-page-vector128", 3, "movdqu"),
    ("locked-add8", 1, "add"), ("locked-add16", 1, "add"),
    ("locked-add32", 1, "add"), ("unaligned-locked-add32", 1, "add"),
    ("cross-page-locked-add32", 1, "add"), ("locked-xadd32", 1, "xadd"),
    ("unaligned-locked-xadd32", 1, "xadd"), ("cross-page-locked-xadd32", 1, "xadd"),
    ("successful-compare-exchange32", 3, "cmpxchg"),
    ("cross-page-successful-compare-exchange32", 3, "cmpxchg"),
    ("unaligned-compare-exchange64", 5, "cmpxchg8b"),
    ("cross-page-compare-exchange64", 5, "cmpxchg8b"),
    ("compound-two-store32", 3, "mov"),
)


# Successful profiles have no counter/witness memory store in the loop. Their
# target reaches page two, and neither cross-page half is masked. Failed CAS
# keeps its ordinary page-one witness, without a hardware no-write claim.
TARGETS = (
    (0x8040, 1), (0x8040, 2), (0x8040, 4), (0x8043, 4), (0x7ffd, 4),
    (0x8040, 1), (0x8040, 2), (0x8040, 4), (0x8043, 4), (0x7ffd, 4),
    (0x8080, 8), (0x8080, 4), (0x8080, 16), (0x8083, 16), (0x7ff9, 16),
    (0x8040, 1), (0x8040, 2), (0x8040, 4), (0x8043, 4), (0x7ffd, 4),
    (0x8040, 4), (0x8043, 4), (0x7ffd, 4), (0x8080, 4), (0x7ffd, 4),
    (0x8083, 8), (0x7ffd, 8), (0x7ff8, 4),
)


def require_memory_instruction(item, mnemonic, register, prefixes, opcode, target):
    """Checks one closed encoding, including exact prefix count and operand width."""
    words = item["instruction"].split()
    expected_words = (["lock"] if 0xf0 in prefixes else []) + [mnemonic]
    assert words[:len(expected_words)] == expected_words, item
    operands = "".join(words[len(expected_words):])
    assert operands.startswith(register + ","), item

    encoded = list(bytes.fromhex(item["bytes"]))
    actual_prefixes = []
    while encoded and encoded[0] in (0x66, 0xf0):
        actual_prefixes.append(encoded.pop(0))
    assert sorted(actual_prefixes) == sorted(prefixes), item
    assert encoded == [*opcode, *target.to_bytes(2, "little")], item


def require_extended_body(index, body):
    """Binds new cases to exact memory operations, not equivalent final bytes."""
    if 15 <= index <= 19:
        register, size_prefix = ("%al", []) if index == 15 else (
            ("%ax", []) if index == 16 else ("%eax", [0x66]))
        opcode = 0x00 if index == 15 else 0x01
        require_memory_instruction(body[0], "add", register, [0xf0, *size_prefix],
                                   [opcode, 0x06], TARGETS[index][0])
    elif 20 <= index <= 22:
        require_memory_instruction(body[0], "xadd", "%eax", [0xf0, 0x66],
                                   [0x0f, 0xc1, 0x06], TARGETS[index][0])
    elif 23 <= index <= 24:
        require_memory_instruction(body[-1], "cmpxchg", "%ecx", [0xf0, 0x66],
                                   [0x0f, 0xb1, 0x0e], TARGETS[index][0])
    elif 25 <= index <= 26:
        # CMPXCHG8B has no explicit register operand and a fixed 64-bit width.
        item = body[-1]
        assert item["instruction"].split()[:2] == ["lock", "cmpxchg8b"], item
        encoded = bytes.fromhex(item["bytes"])
        assert encoded == bytes([0xf0, 0x0f, 0xc7, 0x0e]) + TARGETS[index][0].to_bytes(2, "little"), item
    elif index == 27:
        require_memory_instruction(body[0], "mov", "%eax", [0x66], [0xa3], 0x7ff8)
        assert body[1]["instruction"].split() == ["not", "%eax"], body[1]
        assert bytes.fromhex(body[1]["bytes"]) == bytes([0x66, 0xf7, 0xd0]), body[1]
        require_memory_instruction(body[2], "mov", "%eax", [0x66], [0xa3], 0x8008)


def inventory(root):
    rows = []
    for index, (name, body_count, opcode) in enumerate(PROFILES):
        rom = (root / f"{name}.bin").read_bytes()
        assert len(rom) == 65536
        assert rom[0xffd0:0xffd8] == b"CRUCWRT1"
        assert int.from_bytes(rom[0xffd8:0xffdc], "little") == index
        text = (root / f"{name}.instructions").read_text()
        section = None
        startup = []
        loop = []
        body = []
        for line in text.splitlines():
            label = re.match(r"^[0-9a-f]+ <([^>]+)>:$", line)
            if label:
                section = label[1]
                continue
            instruction = re.match(r"^\s*[0-9a-f]+:\s+((?:[0-9a-f]{2} )+)\s*(\S.*)$", line)
            if not instruction:
                continue
            encoded, decoded = instruction.groups()
            item = {"bytes": encoded.strip(), "instruction": decoded}
            if section == "_start":
                startup.append(item)
            elif section == "writer_loop":
                loop.append(item)
            elif section == "operation_begin":
                body.append(item)
            elif section == "operation_end":
                loop.append(item)
        # Reset LJMP is separately counted; loop has four prefix + three tail instructions.
        assert len(startup) + 1 == 2062, (name, len(startup))
        assert len(body) == body_count, (name, body)
        assert len(loop) == 7, (name, loop)
        if index == 11:
            assert "0x7010" in loop[-2]["instruction"]
        else:
            assert loop[-2]["instruction"] == "nop", (name, loop[-2])
        target, width = TARGETS[index]
        assert target + width > 0x8000 or index == 27
        # In .code16, these closed memory operations end with the absolute
        # disp16 operand. Binutils renders ModRM displacements above 0x7fff as
        # signed values; compare the actual operand bytes, not its spelling.
        assert any(opcode in item["instruction"]
                   and int.from_bytes(bytes.fromhex(item["bytes"])[-2:], "little") == target
                   for item in body), (name, opcode, hex(target))
        require_extended_body(index, body)
        missing = (root / f"{name}-missing-operation.bin").read_bytes()
        assert missing != rom and len(missing) == len(rom)
        missing_text = (root / f"{name}-missing-operation.instructions").read_text()
        missing_body = missing_text.split("<operation_begin>:\n", 1)[1].split("<operation_end>:", 1)[0]
        missing_instructions = re.findall(r"^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2} )+\s*(\S.*)$", missing_body, re.M)
        assert len(missing_instructions) == body_count and all(item == "nop" for item in missing_instructions), name
        assert missing[0xffd0:0xffdc] == rom[0xffd0:0xffdc]
        mutations = {"missing_operation_sha256": hashlib.sha256(missing).hexdigest()}
        if index == 11:
            forced = (root / f"{name}-forced-success.bin").read_bytes()
            assert forced != rom and len(forced) == len(rom)
            assert forced[0xffd0:0xffdc] == rom[0xffd0:0xffdc]
            mutations["forced_success_sha256"] = hashlib.sha256(forced).hexdigest()
        rows.append({"profile": name, "index": index, "causal_mutants": mutations, "rom_sha256": hashlib.sha256(rom).hexdigest(),
                     "elf_sha256": hashlib.sha256((root / f"{name}.elf").read_bytes()).hexdigest(),
                     "startup_instructions": 2062, "loop_instructions": 7 + body_count,
                     "target_gpa": target, "target_width": width,
                     "counter_gpa": 0x7010 if index == 11 else None,
                     "operation": body})
    (root / "manifest.json").write_text(json.dumps({"schema": 1, "scope": "emitted bytes, not VM proof", "profiles": rows}, indent=2) + "\n")


if __name__ == "__main__":
    inventory(Path(sys.argv[1]))
