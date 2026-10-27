"""Constructs inert attribute field models independently of Terrane codecs.

Only primitive canonical CBOR and the source-built raw digest helper are used.
Digest values, executable metadata and signatures are fixed format data: this
module does not compute plaintext properties or establish producer authority.
"""

import argparse
from copy import deepcopy
from pathlib import Path
import textwrap

from collection_vectors import encode, self_check as check_cbor
from pack_vectors import digest
from retirement_vectors import diagnostic_lines


HEADING = "## Derived-attribute field model witnesses"
OBJECT = bytes([17]) * 32
PRODUCER = bytes([34]) * 32
SIGNATURE = bytes(range(64))
INTERPRETER = "/opt/terrane/interpreter"
PREFIX = b"terrane-attr-signature-v1\0"
MAGIC = ["elf", "shebang", "ar", "zstd", "gzip", "tar", "text", "other"]


def values():
    """Returns complete registered values, without deriving them from programs."""
    models = {}
    for label, attribute, function, width, byte in [
        ("sha256", "hash.sha256", "sha256", 32, 49),
        ("sha512", "hash.sha512", "sha512", 64, 50),
        ("git-blob-sha1", "hash.git-blob-sha1", "git-blob-sha1", 20, 51),
        ("git-blob-sha256", "hash.git-blob-sha256", "git-blob-sha256", 32, 52),
        ("dictionary", "zstd-dictionary", "zstd-dictionary", 32, 53),
    ]:
        models[label] = (attribute, function, bytes([byte]) * width)
    for magic in MAGIC:
        models[f"magic-{magic}"] = ("class.magic", "magic", magic)
    for word_size, machine in [(32, 3), (64, 62)]:
        for linked in [False, True]:
            label = f"elf{word_size}-" + ("linked" if linked else "static")
            models[label] = ("class.elf", "elf", {
                1: word_size, 2: machine, 3: 3 if linked else 2,
                4: INTERPRETER if linked else None,
                5: ["libz.so", "liba.so", "libz.so"] if linked else [],
            })
    for argument, label in [(None, "plain"), ("--mode inert", "argument")]:
        models[f"shebang-{label}"] = (
            "class.shebang", "shebang", {1: INTERPRETER, 2: argument})
    return models


def record(attribute, function, value, signed=False, version="1", producer=PRODUCER):
    """Constructs all record fields; key six contains opaque bytes when present."""
    fields = {1: OBJECT, 2: attribute, 3: value,
              4: f"{function}/{version}", 5: producer}
    if signed:
        fields[6] = SIGNATURE
    return fields


def records():
    """Pairs every value with absent and present signatures and retained metadata."""
    models = {}
    for label, (attribute, function, value) in values().items():
        for signed in [False, True]:
            suffix = "opaque-signature" if signed else "unsigned"
            models[f"{label}-{suffix}"] = record(attribute, function, value, signed)
    for signed in [False, True]:
        suffix = "opaque-signature" if signed else "unsigned"
        models[f"magic-future-{suffix}"] = record(
            "class.magic", "magic", "text", signed, version="2")
        models[f"magic-other-producer-{suffix}"] = record(
            "class.magic", "magic", "text", signed, producer=bytes([35]) * 32)
    return models


def negatives():
    """Reconstructs malformed schema fields using primitive CBOR models only."""
    models = {}

    def add(label, fields, reason, attribute=None):
        models[label] = (fields, reason, attribute)

    for label, (attribute, _, value) in values().items():
        if isinstance(value, bytes):
            for delta, suffix in [(-1, "short"), (1, "long")]:
                add(f"value-{label}-{suffix}", bytes([value[0]]) * (len(value) + delta),
                    "The digest has the wrong registered width.", attribute)
    add("value-magic-unknown", "future-class", "The classification is unregistered.",
        "class.magic")
    elf = {1: 64, 2: 62, 3: 3, 4: INTERPRETER, 5: ["libz.so", "liba.so", "libz.so"]}
    for label, key, value in [
        ("class", 1, 16), ("machine", 2, 65536), ("type", 3, 65536),
        ("interpreter-type", 4, True), ("interpreter-empty", 4, ""),
        ("interpreter-nul", 4, "a\0b"), ("needed-type", 5, "liba.so"),
        ("needed-member-type", 5, [b"liba.so"]),
        ("needed-empty", 5, [""]), ("needed-nul", 5, ["a\0b"]),
    ]:
        fields = deepcopy(elf)
        fields[key] = value
        add(f"value-elf-{label}", fields, "The ELF field violates its value schema.",
            "class.elf")
    shebang = {1: INTERPRETER, 2: None}
    for label, key, value in [
        ("relative", 1, "relative/interpreter"), ("empty", 1, ""),
        ("nul", 1, "/a\0b"), ("argument-type", 2, True),
        ("argument-empty", 2, ""), ("argument-nul", 2, "a\0b"),
    ]:
        fields = deepcopy(shebang)
        fields[key] = value
        add(f"value-shebang-{label}", fields,
            "The shebang field violates its value schema.", "class.shebang")
    for label, attribute, original, key in [
        ("elf", "class.elf", elf, 4),
        ("shebang", "class.shebang", shebang, 2),
    ]:
        fields = deepcopy(original)
        del fields[key]
        add(f"value-{label}-missing-optional-key", fields,
            "The nullable field's schema key is required.", attribute)
        fields = deepcopy(original)
        fields[9] = fields.pop(key)
        add(f"value-{label}-unknown-key", fields,
            "The map contains a key outside its schema.", attribute)

    base = record("hash.sha256", "sha256", bytes([49]) * 32)
    mutations = [
        ("object-short", 1, bytes(31)), ("object-long", 1, bytes(33)),
        ("producer-short", 5, bytes(31)), ("producer-long", 5, bytes(33)),
        ("signature-short", 6, bytes(63)), ("signature-long", 6, bytes(65)),
        ("unknown-name", 2, "hash.future"), ("name-type", 2, b"hash.sha256"),
        ("value-type", 3, "digest"), ("function-type", 4, b"sha256/1"),
        ("function-no-version", 4, "sha256"), ("function-empty-name", 4, "/1"),
        ("function-empty-version", 4, "sha256/"),
        ("function-extra-slash", 4, "sha256/1/2"),
        ("function-invalid-character", 4, "sha256/1!"),
    ]
    for label, key, value in mutations:
        fields = deepcopy(base)
        fields[key] = value
        add(f"record-{label}", fields, "The record field violates its structural schema.")
    fields = deepcopy(base)
    del fields[5]
    add("record-missing-producer", fields, "The producer reference key is required.")
    fields = deepcopy(base)
    fields[7] = None
    add("record-extra-key", fields, "The record has an unregistered key.")
    fields = deepcopy(base)
    fields[7] = fields.pop(5)
    add("record-wrong-key", fields, "Key seven cannot replace the producer key.")
    return models


def self_check():
    """Checks primitive byte anchors and positive model field invariants."""
    check_cbor()
    assert len(values()) == 19 and len(records()) == 42 and len(negatives()) == 49
    assert encode(values()["sha256"][2]).hex() == "5820" + "31" * 32
    assert encode(values()["magic-elf"][2]).hex() == "63656c66"
    assert encode({1: 32, 2: 3, 3: 2, 4: None, 5: []}).hex() == "a50118200203030204f60580"
    assert PREFIX.hex() == "74657272616e652d617474722d7369676e61747572652d763100"
    for fields in records().values():
        unsigned = {key: value for key, value in fields.items() if key != 6}
        assert set(unsigned) == {1, 2, 3, 4, 5}
        assert len(fields[1]) == len(fields[5]) == 32
        assert encode(unsigned)[0] == 0xa5
        if 6 in fields:
            assert fields[6] == SIGNATURE and encode(fields)[0] == 0xa6


def render(binary):
    """Renders separate values, records, preimages and explicit negative inputs."""
    parts = [HEADING, "", textwrap.fill(
        "These TEST-1/TEST-2 field models cover all eight registered value kinds. "
        "Fixed digest bytes and represented ELF/shebang fields assert no external "
        "plaintext properties. Value fragments have no immutable-content identity. "
        "Full records carry terrane-attr-v1 identities and exact unsigned "
        "signature preimages; optional signatures are fixed opaque bytes, without "
        "signing, verification or authority. Future function version 2 remains "
        "format data. Structural negatives acquire no content identity. These "
        "codec comparisons cover DRV-1/2/6/8 format data only.", 78), ""]

    def append(name, fields, description):
        parts.extend([f"### attribute-{name}", "", textwrap.fill(description, 78),
                      "", "```text", *diagnostic_lines(fields), "```", "", "```hex",
                      *textwrap.wrap(encode(fields).hex(), 72), "```", ""])

    for label, (attribute, function, value) in values().items():
        append(f"value-{label}", value,
               f"Positive {attribute} value fragment; producing function {function}/1.")
    for label, fields in records().items():
        append(f"record-{label}", fields, "Positive complete inert AttrRecord.")
        unsigned = {key: value for key, value in fields.items() if key != 6}
        parts.extend(["Unsigned signature preimage:", "", "```hex",
                      *textwrap.wrap((PREFIX + encode(unsigned)).hex(), 72), "```", "",
                      "Attribute-domain identity digest:", "", "```hex",
                      digest(binary, "terrane-attr-v1", encode(fields)).hex(), "```", ""])
    for label, (fields, reason, attribute) in negatives().items():
        context = f" Decode as {attribute}." if attribute else " Decode as AttrRecord."
        append(f"negative-{label}", fields, "Negative vector: " + reason + context)
    return "\n".join(parts)


def main():
    """Emits or checks a separate reference section without changing goldens."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blake3-bin", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-check", action="store_true")
    mode.add_argument("--emit", action="store_true")
    mode.add_argument("--check", type=Path)
    arguments = parser.parse_args()
    self_check()
    if arguments.self_check:
        print("PASS: 19 attribute values, 42 complete records and 49 negative models")
        return
    section = render(arguments.blake3_bin)
    if arguments.emit:
        print(section, end="")
        return
    reference = arguments.check.read_text(encoding="utf-8")
    if reference.count(HEADING + "\n") != 1:
        raise SystemExit("expected one derived-attribute reference section")
    existing = reference.split(HEADING + "\n", 1)[1].split("\n## ", 1)[0]
    if (HEADING + "\n" + existing).rstrip() != section.rstrip():
        raise SystemExit("attribute models, bytes, preimages or identities differ")
    print("PASS: independent attribute reference section matches")


if __name__ == "__main__":
    main()
