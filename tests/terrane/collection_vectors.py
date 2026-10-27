"""Reproduces collection-record wire models with independent CBOR primitives.

The inputs transcribe the registered CDDL and GC-7 membership-hint rule.
Digest fields are ordinary model data. This generator uses no store, clock,
signature verification, ownership construction or collection workflow.
"""

import argparse
from copy import deepcopy
import json
from pathlib import Path
import textwrap


HEADING = "## Collection-record format witnesses"

NEGATIVE_REASONS = {
    "collection-mark-bad-filter": "The membership hint differs from GC-7 reconstruction.",
    "collection-roots-true-cutoff": "A parent cutoff cannot be true.",
    "collection-state-null-context": "A present proof context cannot be null.",
    "collection-state-reversed-contexts": (
        "Proof contexts must use unsigned fieldwise order, not CBOR length order."
    ),
    "collection-generation-repeated-burn": "Permanent burn pack IDs must be unique.",
}


def head(major, value):
    """Encodes the shortest head for one unsigned CBOR argument."""
    if not 0 <= major <= 5 or type(value) is not int or value < 0:
        raise ValueError("expected a supported major type and unsigned argument")
    if value < 24:
        return bytes([(major << 5) | value])
    for width, additional in [(1, 24), (2, 25), (4, 26), (8, 27)]:
        if value < 1 << (8 * width):
            return bytes([(major << 5) | additional]) + value.to_bytes(width, "big")
    raise ValueError("argument exceeds uint64")


def encode(value):
    """Encodes field models independently of Terrane's format codecs."""
    if value is None:
        return b"\xf6"
    if type(value) is bool:
        return b"\xf5" if value else b"\xf4"
    if type(value) is int:
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(encode(item) for item in value)
    if isinstance(value, dict):
        fields = [(encode(key), encode(item)) for key, item in value.items()]
        fields.sort(key=lambda field: (len(field[0]), field[0]))
        return head(5, len(fields)) + b"".join(key + item for key, item in fields)
    raise TypeError(f"unsupported field model: {type(value).__name__}")


def diagnostic(value):
    """Renders all fields, including embedded byte strings, in diagnostic notation."""
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    if isinstance(value, bytes):
        return f"h'{value.hex()}'"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ", ".join(diagnostic(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(
            f"{diagnostic(key)}: {diagnostic(item)}"
            for key, item in sorted(value.items())
        ) + "}"
    raise TypeError(f"unsupported diagnostic model: {type(value).__name__}")


def membership_hint(hashes):
    """Transcribes GC-7's three big-endian positions into a 2,048-byte hint."""
    hint = bytearray(2048)
    for digest in hashes:
        if len(digest) != 32:
            raise ValueError("a mark hash must contain exactly 32 bytes")
        for offset in [1, 11, 21]:
            position = int.from_bytes(digest[offset:offset + 2], "big") % 16384
            hint[position // 8] |= 1 << (position % 8)
    return bytes(hint)


def empty_state(phase):
    """Constructs an ordinary version-one checkpoint field model."""
    return {0: 1, 1: 7, 2: 9, 3: phase, 4: 24, 5: [], 6: [], 7: [], 8: [], 9: []}


def models():
    """Constructs positive and negative wire inputs without parsing fixtures."""
    witnesses = {"collection-lease": {1: "collector", 2: 9, 3: 256}}
    reasons = [
        "current", "reflog-gc", "reflog-count", "reflog-ttl", "lease",
        "forever", "tag", "job", "retention-witness",
    ]
    roots = []
    for index, reason in enumerate(reasons):
        reference = "refs/heads/_/main"
        if reason == "tag":
            reference = "refs/tags/_/release"
        elif reason == "job":
            reference = "refs/jobs/_/classify"
        cutoff = [None, 23, False][index % 3]
        roots.append([reference, bytes([index + 1]) * 32, cutoff, reason])
    witnesses["collection-roots-empty"] = {0: 1, 1: 7, 2: 9, 3: 24, 4: []}
    witnesses["collection-roots-reasons"] = {0: 1, 1: 7, 2: 9, 3: 24, 4: roots}

    hashes = [bytes([1]) * 32, bytes([1]) + bytes([2]) * 31]
    for name, values in [("empty", []), ("two-hashes", hashes)]:
        witnesses[f"collection-mark-{name}"] = {
            0: 1, 1: 7, 2: 9, 3: 1, 4: values, 5: membership_hint(values),
        }
    for phase in ["snapshot", "mark", "sweep", "delete", "done"]:
        witnesses[f"collection-state-{phase}"] = empty_state(phase)

    contexts = [None, [bytes([3]) * 32, bytes([4]) * 32, b"/aa"],
                [bytes([3]) * 32, bytes([4]) * 32, b"/z"]]
    state = empty_state("mark")
    state[5] = [[1, 0, bytes([7]) * 32], [255, 24, bytes([8]) * 32]]
    state[8] = [bytes([1]) * 16, bytes([2]) * 16]
    for context in contexts:
        suffix = [] if context is None else [context]
        state[6].append([2, bytes([5]) * 32, False, 2] + suffix)
        state[7].append([bytes([6]) * 32, None] + suffix)
        state[9].append([2, bytes([5]) * 32, 2] + suffix)
    witnesses["collection-state-proof-contexts"] = state

    witnesses["collection-tombstone"] = {
        1: bytes(range(16)), 2: 7, 3: 24, 4: 2, 5: 9,
    }
    generation = {1: 24, 2: [], 3: 256, 4: 7}
    witnesses["collection-generation-legacy"] = generation
    witnesses["collection-generation-known-empty"] = {
        **generation, 5: [], 6: [], 7: [],
    }
    witnesses["collection-generation-complete-fields"] = {
        1: 24,
        2: [[1, bytes([3]) * 32, 256],
            [255, bytes([4]) * 32, 256, bytes([5]) * 32, 24]],
        3: 256,
        4: 7,
        5: [[bytes(range(16)), bytes([6]) * 32, 262, bytes([7]) * 32, 148]],
        6: [[bytes([9]) * 16, 7, 9]],
        7: [bytes([10]) * 16],
    }

    bad_filter = deepcopy(witnesses["collection-mark-two-hashes"])
    changed = bytearray(bad_filter[5])
    changed[0] ^= 1
    bad_filter[5] = bytes(changed)
    witnesses["collection-mark-bad-filter"] = bad_filter
    true_cutoff = deepcopy(witnesses["collection-roots-reasons"])
    true_cutoff[4][0][2] = True
    witnesses["collection-roots-true-cutoff"] = true_cutoff
    null_context = deepcopy(state)
    null_context[6][1][-1] = None
    witnesses["collection-state-null-context"] = null_context
    reversed_contexts = deepcopy(state)
    reversed_contexts[7][1], reversed_contexts[7][2] = (
        reversed_contexts[7][2], reversed_contexts[7][1]
    )
    witnesses["collection-state-reversed-contexts"] = reversed_contexts
    repeated_burn = deepcopy(witnesses["collection-generation-complete-fields"])
    repeated_burn[7].append(repeated_burn[7][0])
    witnesses["collection-generation-repeated-burn"] = repeated_burn
    return witnesses


def render():
    """Renders each complete model and its independently encoded bytes."""
    parts = [HEADING, "", textwrap.fill(
        "These TEST-1/TEST-2 models transcribe GcLease, GcRoots, GcMark, "
        "GcState, Tombstone and IndexGenerationManifest in terrane-v1.cddl. "
        "GC-7 defines the reconstructed mark hint; GC-30 defines fieldwise "
        "proof-context order. These records have no immutable-content "
        "descriptor. Opaque digest fields do not establish root completeness, "
        "verified history, checkpoint authenticity or effect authority.", 78), ""]
    for name, model in models().items():
        parts += [f"### {name}", ""]
        if name in NEGATIVE_REASONS:
            parts += [textwrap.fill("Negative vector: " + NEGATIVE_REASONS[name], 78), ""]
        else:
            parts += ["Positive format vector.", ""]
        # Diagnostic hex byte strings permit whitespace between their digits.
        fields = textwrap.wrap(diagnostic(model), width=78, break_on_hyphens=False)
        parts += ["```text", *fields, "```", "", "```hex",
                  *textwrap.wrap(encode(model).hex(), 72), "```", ""]
    return "\n".join(parts)


def self_check():
    """Checks primitive boundaries and hint positions against explicit oracles."""
    primitive_cases = [
        (0, "00"), (23, "17"), (24, "1818"), (255, "18ff"),
        (256, "190100"), (65535, "19ffff"), (65536, "1a00010000"),
        (2**32, "1b0000000100000000"), (2**64 - 1, "1bffffffffffffffff"),
        (False, "f4"), (True, "f5"), (None, "f6"),
        (b"", "40"), ("", "60"), ([], "80"), ({}, "a0"),
        ({24: 0, 1: False}, "a201f4181800"),
    ]
    for model, expected in primitive_cases:
        if encode(model).hex() != expected:
            raise ValueError(f"CBOR primitive oracle failed: {model!r}")
    for model in [-1, 2**64]:
        try:
            encode(model)
        except ValueError:
            continue
        raise ValueError("out-of-range unsigned argument was accepted")

    digest = bytearray(32)
    digest[1:3] = b"\x00\x01"
    digest[11:13] = b"\x40\x09"
    digest[21:23] = b"\xff\xff"
    expected = bytearray(2048)
    expected[0] = 2
    expected[1] = 2
    expected[2047] = 128
    if membership_hint([bytes(digest)]) != bytes(expected):
        raise ValueError("GC-7 hint oracle failed")
    if not set(NEGATIVE_REASONS) <= models().keys():
        raise ValueError("a negative witness is missing")


def main():
    """Emits or compares only this generator's bounded reference section."""
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--emit", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--insert", action="store_true")
    mode.add_argument("--self-check", action="store_true")
    parser.add_argument("reference", type=Path, nargs="?")
    arguments = parser.parse_args()
    self_check()
    if arguments.self_check:
        print(f"PASS: primitive and hint oracles; {len(models())} wire models")
        return
    section = render()
    if arguments.emit:
        print(section, end="")
        return
    if arguments.reference is None:
        parser.error("--check and --insert require a reference path")
    original = arguments.reference.read_text(encoding="utf-8")
    if arguments.insert:
        if HEADING in original:
            raise SystemExit("collection section exists; refusing to replace it")
        marker = "## Reproduction\n"
        if original.count(marker) != 1:
            raise SystemExit("expected one reproduction section")
        arguments.reference.write_text(
            original.replace(marker, section + "\n" + marker), encoding="utf-8",
        )
        return
    if original.count(HEADING + "\n") != 1:
        raise SystemExit("expected one collection reference section")
    existing = original.split(HEADING + "\n", 1)[1].split("\n## ", 1)[0]
    if (HEADING + "\n" + existing).rstrip() != section.rstrip():
        raise SystemExit("collection reference bytes or models differ")
    print("PASS: independent collection reference section matches byte-for-byte")


if __name__ == "__main__":
    main()
