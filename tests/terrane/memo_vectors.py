"""Reproduces common Memo witnesses with independent primitive CDDL writers.

The supplied source-built helper supplies raw BLAKE3 only. These format models
carry no recipe replay, trust, publication authority or allocation measurement.
"""

import argparse
from pathlib import Path
import subprocess
import textwrap


HEADING = "## Common immutable memo record witnesses"
INTRODUCTION = (
    "These TEST-1/2 witnesses reproduce the existing CDDL common Memo record, {1: "
    "digest32, 2: digest32}, directly through its owning format decoder. Positive "
    "record identities use the registered OBJ-2 domain. Detached recipe lookup "
    "fields carry no descriptor. These are format witnesses; they establish neither "
    "DRV-22 replay nor trust or publication authority. Reproduce this section with "
    "tests/terrane/memo_vectors.py --emit --blake3-bin <reference_blake3>, using "
    "the source-built raw primitive helper."
)
REFUSAL = (
    "Owning Memo decoder rejects this independent wire input. No immutable identity "
    "is assigned."
)


def head(major, value):
    """Writes a shortest definite CBOR primitive header."""
    prefix = major << 5
    if value < 24:
        return bytes([prefix | value])
    for marker, width in [(24, 1), (25, 2), (26, 4), (27, 8)]:
        if value < 1 << (width * 8):
            return bytes([prefix | marker]) + value.to_bytes(width, "big")
    raise ValueError("CBOR length exceeds u64")


def byte_string(value):
    """Writes a definite primitive byte string."""
    return head(2, len(value)) + value


def pair(key, value):
    """Writes an integer map key and an already encoded field value."""
    return head(0, key) + value


def record(recipe, result):
    """Transcribes the two ordered digest fields without a Terrane codec."""
    return head(5, 2) + pair(1, byte_string(recipe)) + pair(2, byte_string(result))


def models():
    """Constructs fixed positive fields and independent malformed wire models."""
    positives = [
        ("zero", bytes(32), bytes(32)),
        ("ff", bytes([255]) * 32, bytes([255]) * 32),
        ("increasing", bytes(range(32)), bytes(range(32, 64))),
    ]
    recipe, result = bytes(range(32)), bytes(range(32, 64))
    first = pair(1, byte_string(recipe))
    second = pair(2, byte_string(result))
    negatives = [
        ("missing-recipe", b"\xa1" + second),
        ("missing-root", b"\xa1" + first),
        ("empty-map", b"\xa0"),
        ("unknown-field", b"\xa2" + first + pair(3, byte_string(result))),
        ("extra-field", b"\xa3" + first + second + pair(3, b"\x00")),
        ("duplicate-recipe", b"\xa2" + first + first),
        ("duplicate-root", b"\xa2" + second + second),
        ("reordered", b"\xa2" + second + first),
        ("array-container", b"\x82" + first + second),
        ("null-container", b"\xf6"),
        ("text-key", b"\xa2\x61x" + byte_string(recipe) + second),
    ]
    for field in (1, 2):
        for length in (31, 33):
            digest = recipe[:length] if length == 31 else recipe + b"\x00"
            # Field 2 uses its own increasing model, rather than field 1 bytes.
            if field == 2:
                digest = result[:length] if length == 31 else result + b"\x00"
            wire = record(digest, result) if field == 1 else record(recipe, digest)
            negatives.append((f"field-{field}-digest-{length}", wire))
        values = [
            ("wrong-uint", b"\x00"),
            ("wrong-null", b"\xf6"),
            ("wrong-array", b"\x80"),
            ("wrong-text", b"\x78\x20" + recipe),
            ("nonminimal-length", b"\x59\x00\x20" + recipe),
            ("indefinite-bytes", b"\x5f" + byte_string(recipe) + b"\xff"),
            ("hostile-u64", b"\x5b" + bytes([255]) * 8),
        ]
        for label, value in values:
            fields = pair(1, value) + second if field == 1 else first + pair(2, value)
            negatives.append((f"field-{field}-{label}", b"\xa2" + fields))
    negatives += [
        ("nonminimal-map", b"\xb8\x02" + first + second),
        ("nonminimal-key-1", b"\xa2\x18\x01" + byte_string(recipe) + second),
        ("nonminimal-key-2", b"\xa2" + first + b"\x18\x02" + byte_string(result)),
        ("indefinite-map", b"\xbf" + first + second + b"\xff"),
        ("hostile-map", b"\xbb" + bytes([255]) * 8),
        ("trailing-null", record(recipe, result) + b"\xf6"),
        ("oversize", bytes(72)),
    ]
    for label, recipe, result in positives:
        wire = record(recipe, result)
        negatives.extend((f"{label}-truncated-{length}", wire[:length]) for length in range(71))
    return positives, negatives


def raw_digest(binary, data):
    """Obtains only the raw primitive digest of independently assembled bytes."""
    output = subprocess.check_output([str(binary)], input=data).decode().strip()
    if len(output) != 64 or any(character not in "0123456789abcdef" for character in output):
        raise ValueError("raw helper did not return a lowercase 32-byte digest")
    return output


def self_check(binary):
    """Checks the primitive anchor, model counts, labels and exact byte lengths."""
    if raw_digest(binary, b"") != "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262":
        raise ValueError("raw BLAKE3 empty-input anchor differs")
    positives, negatives = models()
    assert len(positives) == 3 and len(negatives) == 249
    assert len({label for label, _ in negatives}) == 249
    assert all(len(record(recipe, result)) == 71 for _, recipe, result in positives)
    assert head(5, 2) == b"\xa2" and byte_string(bytes(32)) == b"\x58\x20" + bytes(32)
    assert sum(not wire for _, wire in negatives) == 3
    print("PASS: independent common Memo primitive and model self-check")


def render(binary):
    """Renders the published section exactly, including empty truncation fences."""
    positives, negatives = models()
    lines = [HEADING, "", *textwrap.wrap(INTRODUCTION, 78), ""]
    for label, recipe, result in positives:
        wire = record(recipe, result)
        identity = raw_digest(binary, b"terrane-memo-v1\x00" + wire)
        lines += [
            f"### common-memo-{label}", "", "```text",
            f"recipe = {recipe.hex()}", f"result = {result.hex()}",
            f"identity = {identity}", "length = 71", "```", "", "```hex",
            *textwrap.wrap(wire.hex(), 72), "```", "",
        ]
    for label, wire in negatives:
        lines += [
            f"### common-memo-reject-{label}", "", *textwrap.wrap(REFUSAL, 78),
            "", "```hex", *(textwrap.wrap(wire.hex(), 72) or [""]), "```", "",
        ]
    return "\n".join(lines)


def main():
    """Emits or compares reference text without modifying its published source."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blake3-bin", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-check", action="store_true")
    mode.add_argument("--emit", action="store_true")
    mode.add_argument("--check", type=Path)
    arguments = parser.parse_args()
    if arguments.self_check:
        self_check(arguments.blake3_bin)
        return
    # Verify the primitive even when the checker is called without self-check.
    if raw_digest(arguments.blake3_bin, b"") != "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262":
        raise SystemExit("raw BLAKE3 empty-input anchor differs")
    rendered = render(arguments.blake3_bin)
    if arguments.emit:
        print(rendered, end="")
        return
    reference = arguments.check.read_text(encoding="utf-8")
    if reference.count(HEADING + "\n") != 1:
        raise SystemExit("expected exactly one common Memo reference section")
    existing = reference.split(HEADING + "\n", 1)[1].split("\n## ", 1)[0]
    if (HEADING + "\n" + existing).rstrip() != rendered.rstrip():
        raise SystemExit("common Memo models, identities or independent wires differ")
    print("PASS: independent common Memo reference matches")


if __name__ == "__main__":
    main()
