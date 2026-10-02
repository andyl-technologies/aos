"""Reconstructs inert chunk envelopes and merged shards from binary field tables.

Primitive bytes and little-endian integers reproduce complete wire models.
The source-built raw BLAKE3 helper supplies registered-domain digests only.
No codec, decompressor, store, publication, or authority is used as an oracle.
"""

import argparse
from copy import deepcopy
from pathlib import Path
import textwrap

from pack_vectors import digest
from retirement_vectors import diagnostic_lines


HEADING = "## Chunk-envelope and merged-shard field witnesses"
PLAINTEXT = b"inert\n"
DICTIONARY = b"terrane inert dictionary\n"
PREFIX = 0xAB
PROFILE_MAXIMUM = 4_194_304


def frame(plaintext, empty_blocks=0):
    """Builds an RFC 8878 single-segment frame with sized raw blocks only."""
    assert len(plaintext) < 256
    # Descriptor 0x20: single segment, one-byte content size, no checksum or
    # dictionary-ID field. Raw blocks carry no dictionary references.
    header = bytes.fromhex("28b52ffd") + bytes([0x20, len(plaintext)])
    empty = bytes(3) * empty_blocks
    last_raw = ((len(plaintext) << 3) | 1).to_bytes(3, "little")
    return header + empty + last_raw + plaintext


def envelope(codec, body, dictionary=None):
    """Writes only the tag, optional dictionary digest and represented body."""
    return bytes([codec]) + (dictionary if codec == 2 else b"") + body


def check_raw_frame(encoded, plaintext):
    """Checks the fixture's sized raw-block construction without a decompressor."""
    assert encoded[:5] == bytes.fromhex("28b52ffd20")
    assert encoded[5] == len(plaintext)
    position = 6
    reconstructed = b""
    while True:
        assert position + 3 <= len(encoded)
        block = int.from_bytes(encoded[position:position + 3], "little")
        assert (block >> 1) & 3 == 0
        length = block >> 3
        position += 3
        assert position + length <= len(encoded)
        reconstructed += encoded[position:position + length]
        position += length
        if block & 1:
            break
    assert position == len(encoded) and reconstructed == plaintext


def envelopes(binary):
    """Constructs valid sized frames and their distinct plaintext identities."""
    dictionary_id = digest(binary, "terrane-chunk-v1", DICTIONARY)
    models = {}
    for codec, label in [(0, "raw"), (1, "zstd"), (2, "dictionary")]:
        for plaintext, suffix in [(b"", "empty"), (PLAINTEXT, "plain")]:
            models[f"envelope-{label}-{suffix}"] = {
                "codec": codec, "plaintext": plaintext,
                "dictionary_plaintext": DICTIONARY if codec == 2 else None,
                "dictionary": dictionary_id if codec == 2 else None,
                "body": plaintext if codec == 0 else frame(plaintext),
                "declared": len(plaintext), "maximum": PROFILE_MAXIMUM,
            }
    for codec, label, empty_blocks in [(1, "zstd", 40), (2, "dictionary", 29)]:
        plaintext = b"q" * 100
        models[f"envelope-{label}-overhead-control"] = {
            "codec": codec, "plaintext": plaintext,
            "dictionary_plaintext": DICTIONARY if codec == 2 else None,
            "dictionary": dictionary_id if codec == 2 else None,
            "body": frame(plaintext, empty_blocks), "declared": 100, "maximum": 100,
        }
    return models


def row(ordinal, kind, codec, state):
    """Constructs opaque content locations with all public wire fields present."""
    plaintext_len = 10 + kind
    body_len = plaintext_len if kind else [11, 20, 52][codec]
    return {
        "hash": bytes([PREFIX]) + bytes([ordinal]) * 31,
        "pack": bytes([0x40 + ordinal]) * 16,
        "offset": 0x0102030405060708 + ordinal,
        "body_len": body_len, "plaintext_len": plaintext_len,
        "codec": codec, "kind": kind, "state": state, "reserved": bytes(5),
    }


def shards():
    """Covers every state, kind and permitted codec, plus complete ordered rows."""
    models = {"shard-empty": []}
    rows = []
    for kind in range(10):
        for codec in (range(3) if kind == 0 else [0]):
            for state in range(3):
                entry = row(len(rows) + 1, kind, codec, state)
                if kind == 0 and codec == 2:
                    entry["body_len"] = 0x01020304
                    entry["plaintext_len"] = 0x05060708
                rows.append(entry)
                models[f"shard-kind-{kind}-codec-{codec}-state-{state}"] = [entry]
    models["shard-all-ordered"] = rows
    return models


def shard_wire(rows, count=None, magic=b"TRIX"):
    """Writes the 12-byte preamble and complete 72-byte record fields."""
    wire = magic + (len(rows) if count is None else count).to_bytes(8, "little")
    for entry in rows:
        wire += entry["hash"] + entry["pack"]
        wire += entry["offset"].to_bytes(8, "little")
        wire += entry["body_len"].to_bytes(4, "little")
        wire += entry["plaintext_len"].to_bytes(4, "little")
        wire += bytes([entry["codec"], entry["kind"], entry["state"]])
        wire += entry["reserved"]
    return wire


def negative_envelopes():
    """Builds parse failures and size failures without a rejecting encoder."""
    models = {
        "envelope-missing-tag": (b"", None, None, "The codec tag is absent."),
        "envelope-tag-three": (b"\x03", None, None, "Codec three is unregistered."),
        "envelope-tag-255": (b"\xff", None, None, "Codec 255 is unregistered."),
        "envelope-dictionary-absent": (b"\x02", None, None, "The dictionary digest is absent."),
        "envelope-dictionary-short": (b"\x02" + bytes(31), None, None,
                                      "The dictionary digest is truncated."),
    }
    for declared, label in [(5, "short"), (7, "long")]:
        models[f"envelope-raw-declaration-{label}"] = (
            b"\x00" + PLAINTEXT, declared, 7, "The raw body differs from its declaration.")
    for codec, label in [(0, "raw"), (1, "zstd"), (2, "dictionary")]:
        body = PLAINTEXT if codec == 0 else frame(PLAINTEXT)
        wire = bytes([codec]) + (bytes(range(32)) if codec == 2 else b"") + body
        models[f"envelope-{label}-profile-maximum"] = (
            wire, 6, 5, "The declared length exceeds the profile maximum.")
    for codec, label, empty_blocks in [(1, "zstd", 41), (2, "dictionary", 30)]:
        wire = bytes([codec]) + (bytes(range(32)) if codec == 2 else b"")
        wire += frame(b"q" * 100, empty_blocks)
        models[f"envelope-{label}-overhead-excess"] = (
            wire, 100, 100, "The encoded body exceeds the exact overhead bound.")
    return models


def negative_shards():
    """Assembles malformed rows and framing independently of shard codecs."""
    models = {}
    base = row(1, 0, 0, 0)
    for label, field, value in [
        ("state-three", "state", 3), ("state-255", "state", 255),
        ("kind-ten", "kind", 10), ("kind-255", "kind", 255),
        ("codec-three", "codec", 3), ("codec-255", "codec", 255),
        ("offset-before-header", "offset", 23), ("zero-body", "body_len", 0),
        ("raw-length", "plaintext_len", 9),
    ]:
        entry = deepcopy(base)
        entry[field] = value
        models[f"shard-{label}"] = (shard_wire([entry]), PREFIX,
                                    "The represented row violates its field schema.")
    for codec in [1, 2]:
        entry = row(1, 1, codec, 0)
        models[f"shard-meta-codec-{codec}"] = (
            shard_wire([entry]), PREFIX, "Metadata requires the raw codec.")
    entry = row(1, 1, 0, 0)
    entry["body_len"] += 1
    models["shard-meta-raw-length"] = (
        shard_wire([entry]), PREFIX, "Raw metadata body and plaintext lengths differ.")
    for offset in range(5):
        entry = deepcopy(base)
        entry["reserved"] = bytes(offset) + b"\x01" + bytes(4 - offset)
        models[f"shard-reserved-{offset}"] = (
            shard_wire([entry]), PREFIX, "Every reserved byte must be zero.")
    models["shard-wrong-prefix"] = (
        shard_wire([base]), PREFIX + 1, "The row hash belongs to another shard.")
    other = row(2, 1, 0, 1)
    duplicate = deepcopy(other)
    duplicate["hash"] = base["hash"]
    models["shard-duplicate"] = (
        shard_wire([base, duplicate]), PREFIX, "Two rows carry the same identity.")
    models["shard-descending"] = (
        shard_wire([other, base]), PREFIX, "Hashes are not in ascending order.")
    for count in [0, 2, (1 << 64) - 1]:
        models[f"shard-count-{count}"] = (
            shard_wire([base], count=count), PREFIX, "Count disagrees with record bytes.")
    models["shard-bad-magic"] = (
        shard_wire([base], magic=b"BAD!"), PREFIX, "The preamble magic is unknown.")
    models["shard-short-preamble"] = (
        b"TRIX" + bytes(7), PREFIX, "The preamble count is truncated.")
    models["shard-short-record"] = (
        shard_wire([base])[:-1], PREFIX, "The fixed-width record is truncated.")
    models["shard-trailing-byte"] = (
        shard_wire([base]) + b"\x00", PREFIX, "An extra byte follows the complete shard.")
    return models


def self_check(binary):
    """Checks independent byte anchors, widths, state coverage and frame sizes."""
    assert frame(PLAINTEXT).hex() == "28b52ffd2006310000696e6572740a"
    assert frame(b"").hex() == "28b52ffd2000010000"
    assert shard_wire([]).hex() == "545249580000000000000000"
    assert len(shards()) == 38 and len(envelopes(binary)) == 8
    assert len(negative_envelopes()) == 12 and len(negative_shards()) == 27
    ordered = shards()["shard-all-ordered"]
    assert len(ordered) == 36 and len(shard_wire(ordered)) == 12 + 36 * 72
    assert [entry["hash"] for entry in ordered] == sorted(entry["hash"] for entry in ordered)
    assert {entry["state"] for entry in ordered} == {0, 1, 2}
    assert {entry["kind"] for entry in ordered} == set(range(10))
    assert {entry["codec"] for entry in ordered} == {0, 1, 2}
    first = shard_wire([ordered[0]])
    assert first[60:68].hex() == "0907060504030201"
    assert first[68:84].hex() == "0b0000000a0000000000000000000000"
    assert len(frame(b"q" * 100, 40)) == 229
    assert 32 + len(frame(b"q" * 100, 29)) == 228
    for fields in envelopes(binary).values():
        assert len(fields["plaintext"]) <= fields["maximum"]
        if fields["dictionary_plaintext"] is not None:
            assert len(fields["dictionary_plaintext"]) <= fields["maximum"]
        if fields["codec"] != 0:
            check_raw_frame(fields["body"], fields["plaintext"])


def render(binary):
    """Renders one bounded section with complete fields and registered digests."""
    parts = [HEADING, "", textwrap.fill(
        "These TEST-1/2/3 witnesses cover CDC-7/9 envelope fields and PACK-17/18/19/20 "
        "shard format only. Plaintext and dictionary identities hash their full "
        "bytes in terrane-chunk-v1, independently of stored envelopes. Primitive "
        "RFC 8878 single-segment frames include their content size and only raw "
        "blocks; they use no dictionary references. Core envelope parsing and "
        "size checks do not establish native decompression, dictionary provenance "
        "or admission. Ordinary positive envelopes use cdc-1m's registered "
        "4,194,304-byte maximum, which also accommodates the dictionary plaintext. "
        "Overhead controls instead use a local structural size oracle with a "
        "100-byte maximum; that context is not a registered profile. Complete "
        "merged shards have terrane-index-v1 identities. "
        "Their embedded content hashes and pack IDs are opaque fixture fields, "
        "without corresponding bodies, entropy, placements, generations or "
        "authority. State bytes represent live, tombstone and quarantine fields "
        "without performing those operations. Negative wires have no identity.", 78), ""]

    def append(name, fields, wire, description):
        parts.extend([f"### container-{name}", "", textwrap.fill(description, 78),
                      "", "```text", *diagnostic_lines(fields), "```", "", "```hex",
                      *textwrap.wrap(wire.hex(), 72), "```", ""])

    for label, fields in envelopes(binary).items():
        wire = envelope(fields["codec"], fields["body"], fields["dictionary"])
        description = (
            "Positive complete chunk envelope with a local structural size oracle."
            if label.endswith("overhead-control") else
            "Positive complete chunk envelope under the registered cdc-1m size maximum.")
        append(label, fields, wire, description)
        parts.extend(["Plaintext chunk identity digest:", "", "```hex",
                      digest(binary, "terrane-chunk-v1", fields["plaintext"]).hex(), "```", ""])
    for label, rows in shards().items():
        wire = shard_wire(rows)
        append(label, {"magic": "TRIX", "count": len(rows), "prefix": PREFIX,
                       "records": rows}, wire, "Positive complete merged index shard.")
        parts.extend(["Index-domain shard identity digest:", "", "```hex",
                      digest(binary, "terrane-index-v1", wire).hex(), "```", ""])
    for label, (wire, declared, maximum, reason) in negative_envelopes().items():
        append("negative-" + label, {"declared": declared, "maximum": maximum,
                                   "encoded": wire}, wire, "Negative vector: " + reason)
    for label, (wire, prefix, reason) in negative_shards().items():
        append("negative-" + label, {"prefix": prefix, "encoded": wire}, wire,
               "Negative vector: " + reason)
    return "\n".join(parts)


def main():
    """Emits or checks one separate reference section without changing goldens."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blake3-bin", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-check", action="store_true")
    mode.add_argument("--emit", action="store_true")
    mode.add_argument("--check", type=Path)
    arguments = parser.parse_args()
    self_check(arguments.blake3_bin)
    if arguments.self_check:
        print("PASS: eight envelopes, 38 shards and 39 independent negative wires")
        return
    section = render(arguments.blake3_bin)
    if arguments.emit:
        print(section, end="")
        return
    reference = arguments.check.read_text(encoding="utf-8")
    if reference.count(HEADING + "\n") != 1:
        raise SystemExit("expected one chunk-envelope and merged-shard reference section")
    existing = reference.split(HEADING + "\n", 1)[1].split("\n## ", 1)[0]
    if (HEADING + "\n" + existing).rstrip() != section.rstrip():
        raise SystemExit("container fields, bytes or identities differ")
    print("PASS: independent container reference section matches")


if __name__ == "__main__":
    main()
