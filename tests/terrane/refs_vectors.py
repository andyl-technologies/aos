"""Reproduces inert modern commit and mutable ref field witnesses.

Canonical CBOR is assembled from field tables, without a Terrane codec.
Signatures, token claims, candidate selectors and embedded digests are opaque
format data. No fixture authenticates a principal or establishes backend state.
"""

import argparse
from copy import deepcopy
from pathlib import Path
import re
import textwrap

from collection_vectors import diagnostic, encode, head
from pack_vectors import digest


HEADING = "## Modern commit and ref record field witnesses"
REASONS = ["commit", "merge", "fold", "rollback", "job-checkpoint", "migrate"]
POLICIES = ["prefer-ours", "prefer-theirs", "prefer-trusted", "prefer-newer",
            "keep-conflict", "error"]
OPERATIONS = ["graft", "split", "flatten", "overlay", "merge", "filter", "map",
              "union", "difference", "intersection", "index", "realize"]


def repeated(byte, width=32):
    """Constructs opaque embedded digest and fixed-width field bytes."""
    return bytes([byte]) * width


def locality():
    """Constructs all three optional locality labels."""
    return {1: "region", 2: "zone", 3: "host"}


def source():
    """Constructs an unverified source entry reference."""
    return [repeated(3), repeated(4), b"source\xff"]


def receipts():
    """Constructs every receipt shape, with distinct absent/empty attributes."""
    proof = {1: "ab" * 32, 2: "private:source", 3: 42, 4: repeated(7, 64)}
    return [
        [repeated(1), b"a", 0],
        [repeated(1), b"b", source()],
        [repeated(1), b"c", 0, {}],
        [repeated(1), b"d", source(), {"z": 0, "aa": source()}],
        [repeated(1), b"e", 0, None, source()],
        [repeated(1), b"f", 0, {}, source()],
        [repeated(1), b"g", 0, None, source(), proof],
        [repeated(1), b"h", 0, {"z": source()}, source(), proof],
    ]


def context():
    """Constructs sorted ordinary scope assertions without trusting them."""
    return {1: "refs/heads/_/main", 2: "sdk", 3: locality(),
            4: [[b"/", "public"], [b"/aa", "private:fixture"],
                [b"/z", "public"]]}


def token(full=False):
    """Constructs opaque authority/attenuation blocks, including closed caveats."""
    authority = {1: "issuer", 2: "key", 3: "subject", 4: 2, 5: [], 6: 99,
                 8: repeated(2, 16), 9: [["refs/heads/_/main", 5]],
                 11: repeated(8), 12: repeated(9, 64)}
    if not full:
        return [authority]
    authority.update({5: ["builders", "readers"], 7: 1, 10: "workload"})
    caveats = [["before", 90], ["after", 2], ["ref", "refs/heads/_/main"],
               ["root", "/aa"], ["verb", 1], ["domain", "public"],
               ["surface", "sdk"], ["locality", locality()],
               ["epoch", "refs/heads/_/main", 7]]
    return [authority, {1: 90, 2: 2, 3: [["refs/heads/_/main", 1]],
                        4: caveats, 5: repeated(10), 6: repeated(11, 64)}]


def recipe(operation):
    """Constructs schema-complete registered recipe alternatives."""
    if operation == "graft":
        entry = {1: 4, 6: repeated(2)}
        return {1: operation, 2: [repeated(1), repeated(2)],
                3: {"at": b"target", "entry": encode(entry), "replace": False}}
    if operation == "merge":
        return {1: operation, 2: [repeated(1), repeated(2), repeated(3)],
                3: {"policy": ["prefer-ours", "error"]}}
    return {1: operation, 2: [repeated(1), repeated(2)]}


def commit(kind=2, production=1):
    """Constructs complete required commit fields with absent optional keys."""
    return {1: repeated(1), 2: [],
            3: {1: "issuer", 2: repeated(2, 16), 3: "subject", 4: kind,
                6: "fixture process", 7: 24, 8: 7, 9: production},
            4: 24, 5: "", 6: {1: 1, 2: "cdc-1m"}}


def envelope():
    """Constructs a tag annotation with inert signature and arbitrary values."""
    return {1: "refs/tags/_/snapshot", 2: repeated(1),
            3: {"a": [0, True, None, repeated(13, 3)],
                "zz": {"x": "value"}}, 4: "cd" * 32, 5: repeated(14, 64)}


def record(seq=1, selected=False):
    """Constructs a ref value, independently of any transition operation."""
    fields = {1: repeated(seq), 2: seq, 3: 7, 4: locality()}
    if selected:
        fields[6] = repeated(15)
    return fields


def log(reason="commit", mode="legacy"):
    """Constructs legacy, selected and retained-predecessor log representations."""
    previous = record(1, True)
    fields = {1: record(2, mode != "legacy"), 2: repeated(1),
              3: "subject", 4: reason, 5: 24}
    if mode == "fresh":
        fields.update({1: record(1, True), 2: None, 6: None})
    elif mode == "expected":
        fields[6] = previous
    elif mode == "retained":
        fields.update({6: None, 7: previous})
    return fields


def positives():
    """Builds named independent models for every nested optional field family."""
    values = {}
    for kind in range(1, 4):
        for production in range(1, 7):
            values[f"commit-kind-{kind}-source-{production}"] = commit(kind, production)
    for operation in OPERATIONS:
        fields = commit()
        fields[6][3] = recipe(operation)
        values[f"commit-recipe-{operation}"] = fields
    full = commit()
    full[2] = [repeated(2), repeated(3)]
    full[3].update({5: "workload", 10: token(True)})
    full[5] = "complete fixture \u03bb"
    full[6].update({3: recipe("merge"), 4: True,
                    5: {1: "job", 2: 99},
                    6: {"hashes": ["sha256", "sha512"],
                        "classify": ["elf", "shebang"],
                        "index": ["class.magic"], "strict-attrs": True},
                    7: receipts(), 8: context()})
    full[7] = [[repeated(16, 16), locality()], [repeated(17, 16), {}]]
    full[8] = repeated(18, 64)
    values["commit-complete-signed"] = full
    empty = commit()
    empty[3][10] = token()
    empty[6].update({4: False, 6: {}, 7: []})
    values["commit-explicit-empty-optionals"] = empty
    maximum = commit()
    maximum[2] = [repeated(19)] * 256
    maximum[3][10] = token() + [{5: repeated(10), 6: repeated(11, 64)}] * 15
    values["commit-count-boundaries"] = maximum
    values["ref-legacy"] = record()
    values["ref-selected"] = record(selected=True)
    fields = record(selected=True)
    fields[5] = {}
    values["ref-empty-policy"] = fields
    for index, retention in enumerate(["gc", "lease", "forever", ["ttl", 99]]):
        fields = record(selected=index % 2 == 1)
        fields[5] = {1: index % 2 == 1, 2: POLICIES, 3: retention,
                     4: index % 2 == 0, 5: envelope()}
        values[f"ref-policy-{index}"] = fields
    fields = record()
    fields[4] = {}
    values["ref-empty-locality"] = fields
    for reason in REASONS:
        values[f"log-legacy-{reason}"] = log(reason)
    for mode in ["fresh", "expected", "retained"]:
        values[f"log-selected-{mode}"] = log(mode=mode)
    fields = log("migrate", "expected")
    fields[1][4] = {1: "destination"}
    fields[1][5] = {3: "forever"}
    fields[6][5] = {3: "gc"}
    values["log-migrate-locality-policy"] = fields
    return values


def negatives():
    """Builds structural failures through primitive field maps and raw heads."""
    values = {}

    def add(name, family, fields):
        values[name] = (family, encode(fields))

    def changed(name, family, base, path, replacement):
        fields = deepcopy(base)
        target = fields
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = replacement
        add(name, family, fields)

    for key in range(1, 7):
        fields = commit()
        del fields[key]
        add(f"bad-commit-missing-{key}", "commit", fields)
    for name, path, value in [
        ("tree-width", [1], repeated(1, 31)),
        ("parent-width", [2], [repeated(1, 33)]),
        ("parents-limit", [2], [repeated(1)] * 257),
        ("principal", [3, 4], 0), ("source", [3, 9], 7),
        ("token-id-width", [3, 2], repeated(2, 15)),
        ("workload-type", [3, 5], None), ("tree-format", [6, 1], 2),
        ("profile-empty", [6, 2], ""), ("recipe-operation", [6, 3], {1: "unknown", 2: []}),
        ("conflicted-type", [6, 4], 0), ("lease-missing", [6, 5], {1: "job"}),
        ("property-null", [6, 6], {"retain": None}),
        ("property-key", [6, 6], {"": True}),
        ("packs-empty", [7], []), ("pack-width", [7], [[repeated(1, 15), {}]]),
        ("signature-width", [8], repeated(1, 63)), ("unknown", [9], 0),
    ]:
        changed("bad-commit-" + name, "commit", commit(), path, value)
    for name, scope in [
        ("ref", {**context(), 1: "refs/unknown/_/main"}),
        ("surface", {**context(), 2: "unknown"}),
        ("empty", {**context(), 4: []}),
        ("relative", {**context(), 4: [[b"relative", "public"]]}),
        ("duplicate", {**context(), 4: [[b"/", "public"]] * 2}),
        ("order", {**context(), 4: list(reversed(context()[4]))}),
    ]:
        changed("bad-context-" + name, "commit", commit(), [6, 8], scope)
    for name, rows in [
        ("empty-path", [[repeated(1), b"", 0]]),
        ("origin", [[repeated(1), b"a", 1]]),
        ("four-null", [[repeated(1), b"a", 0, None]]),
        ("source-reintro", [[repeated(1), b"a", source(), None, source()]]),
        ("duplicate", [receipts()[0]] * 2),
        ("order", list(reversed(receipts()))),
        ("attribute-empty", [[repeated(1), b"a", 0, {"": 0}]]),
    ]:
        changed("bad-receipt-" + name, "commit", commit(), [6, 7], rows)
    bad_proof = deepcopy(receipts()[-1])
    bad_proof[5][1] = "AB" * 32
    changed("bad-proof-key", "commit", commit(), [6, 7], [bad_proof])
    for name, blocks in [("empty", []), ("missing", [{}]),
                         ("limit", token() + [{5: repeated(10), 6: repeated(11, 64)}] * 16)]:
        changed("bad-token-" + name, "commit", commit(), [3, 10], blocks)
    for key, value in [(4, 4), (8, repeated(2, 17)), (9, []),
                       (11, repeated(8, 31)), (12, repeated(9, 65)), (13, 0)]:
        blocks = token()
        blocks[0][key] = value
        changed(f"bad-token-authority-{key}", "commit", commit(), [3, 10], blocks)
    for key, value in [(4, [["unknown", 0]]), (3, []), (5, repeated(10, 31)), (7, 0)]:
        blocks = token(True)
        blocks[1][key] = value
        changed(f"bad-token-attenuation-{key}", "commit", commit(), [3, 10], blocks)
    for name, path, value in [
        ("seq-zero", [2], 0), ("commit-width", [1], repeated(1, 31)),
        ("candidate-width", [6], repeated(15, 31)), ("unknown", [7], 0),
        ("locality-key", [4], {4: "host"}),
        ("policy-bool", [5], {1: None}), ("policy-empty-merges", [5], {2: []}),
        ("policy-merge", [5], {2: ["unknown"]}),
        ("policy-retain", [5], {3: "unknown"}),
        ("policy-ttl", [5], {3: ["ttl"]}),
        ("policy-unknown", [5], {6: 0}),
    ]:
        changed("bad-ref-" + name, "ref", record(), path, value)
    for name, key, value in [("tag", 1, "refs/heads/_/main"),
                             ("commit", 2, repeated(1, 31)),
                             ("attestation", 3, {1: True}),
                             ("signature", 5, repeated(14, 63))]:
        annotation = envelope()
        annotation[key] = value
        changed("bad-envelope-" + name, "ref", record(), [5], {5: annotation})
    for name, fields in [
        ("reason", {**log(), 4: "unknown"}),
        ("selected-no-expectation", {**log(), 1: record(2, True)}),
        ("previous-mismatch", {**log(mode="expected"), 2: repeated(99)}),
        ("fresh-sequence", {**log(mode="fresh"), 1: record(2, True)}),
        ("retained-with-expectation", {**log(mode="expected"), 7: record(1, True)}),
        ("retained-legacy", {**log(), 7: record(1)}),
        ("epoch-regression", {**log(mode="expected"), 1: {**record(2, True), 3: 6}}),
        ("home-changed", {**log(mode="expected"), 1: {**record(2, True), 4: {}}}),
        ("unknown", {**log(), 8: 0}),
    ]:
        add("bad-log-" + name, "log", fields)
    for family, fields in [("commit", commit()), ("ref", record()), ("log", log())]:
        wire = encode(fields)
        values[f"bad-{family}-truncated"] = (family, wire[:-1])
        values[f"bad-{family}-trailing"] = (family, wire + b"\0")
        values[f"bad-{family}-indefinite"] = (family, b"\xbf" + wire[1:] + b"\xff")
        values[f"bad-{family}-nonminimal"] = (family, wire[:1] + b"\x18\x01" + wire[2:])
        values[f"bad-{family}-claimed-count"] = (family, b"\xbb" + b"\xff" * 8)
        pairs = [(encode(key), encode(value)) for key, value in fields.items()]
        reversed_wire = head(5, len(pairs)) + b"".join(key + value for key, value in reversed(pairs))
        duplicate_pairs = deepcopy(pairs)
        duplicate_pairs[1] = (pairs[0][0], pairs[1][1])
        duplicate_wire = head(5, len(pairs)) + b"".join(key + value for key, value in duplicate_pairs)
        values[f"bad-{family}-key-order"] = (family, reversed_wire)
        values[f"bad-{family}-duplicate-key"] = (family, duplicate_wire)
    return values


def render(binary):
    """Renders full field tables, exact wires, preimages and commit identities."""
    parts = [HEADING, "", textwrap.fill(
        "These TEST-1/TEST-2 field witnesses cover REF-9/REF-20 and PROV-1/PROV-3. "
        "Fixed signatures, public token chains, context roots, disclosure proofs "
        "and selectors are unverified inert data. Only complete positive Commit "
        "records have immutable identities. Ref records, logs, annotations and "
        "signature preimages have no content descriptor. Preimages omit the "
        "signature key and have no domain prefix. Structural rejection does not "
        "claim signature, policy, tree witness or backend verification.", 78), ""]
    for name, fields in positives().items():
        family = name.split("-", 1)[0]
        wire = encode(fields)
        parts += [f"### {name}", "", "```text", f"family = {family}",
                  "fields = " + diagnostic(fields), "wire = " + wire.hex()]
        if family == "commit":
            unsigned = {key: value for key, value in fields.items() if key != 8}
            parts += ["preimage = " + encode(unsigned).hex(),
                      "identity = " + digest(binary, "terrane-commit-v1", wire).hex()]
        elif family == "ref" and 5 in fields and 5 in fields[5]:
            annotation = fields[5][5]
            parts += ["preimage = " + encode({key: value for key, value in annotation.items()
                                             if key != 5}).hex()]
        parts += ["```", ""]
    for name, (family, wire) in negatives().items():
        parts += [f"### {name}", "", "```text", f"family = {family}",
                  "wire = " + wire.hex(), "result = structural rejection", "```", ""]
    return "\n".join(parts)


def check_section(original, expected):
    """Requires one exact bounded section, allowing unrelated adjacent sections."""
    headings = list(re.finditer(r"^## .*?$", original, re.MULTILINE))
    matches = [index for index, match in enumerate(headings) if match[0] == HEADING]
    if len(matches) != 1:
        raise ValueError("expected exactly one modern commit/ref witness section")
    index = matches[0]
    start = headings[index].start()
    end = headings[index + 1].start() if index + 1 < len(headings) else len(original)
    if original[start:end].rstrip("\n") != expected.rstrip("\n"):
        raise ValueError("modern commit/ref witness fields or bytes differ")


def self_check(binary):
    """Checks primitives, distinct option representations and bounded comparison."""
    if encode({2: True, 1: None}).hex() != "a201f602f5":
        raise ValueError("primitive canonical CBOR oracle failed")
    if head(4, 256).hex() != "990100":
        raise ValueError("primitive count boundary oracle failed")
    positive, negative = positives(), negatives()
    if len(positive) != len(set(positive)) or positive.keys() & negative.keys():
        raise ValueError("witness names must be disjoint")
    section = render(binary)
    check_section("## Earlier\ntext\n" + section + "\n## Later\ntext\n", section)
    for invalid in ["", section + section, section.replace("wire = ", "wire = 00", 1),
                    section.replace("### commit-kind-1-source-1", "## Interrupted", 1),
                    section[:-1] + " \n", section.replace("\n", "\r\n")]:
        try:
            check_section(invalid, section)
        except ValueError:
            continue
        raise ValueError("missing, duplicate, tampered or split section was accepted")
    if encode(log(mode="fresh")) == encode(log()) or encode(record()) == encode(record(selected=True)):
        raise ValueError("explicit absence and selector alternatives collapsed")


def main():
    """Emits or checks the independently generated bounded reference section."""
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    for name in ["self-check", "emit", "check"]:
        modes.add_argument("--" + name, action="store_true")
    parser.add_argument("reference", type=Path, nargs="?")
    parser.add_argument("--blake3-bin", type=Path, required=True)
    arguments = parser.parse_args()
    self_check(arguments.blake3_bin)
    if arguments.self_check:
        print(f"PASS: {len(positives())} complete positive models; "
              f"{len(negatives())} independent structural negative wires")
    elif arguments.emit:
        print(render(arguments.blake3_bin), end="")
    else:
        if arguments.reference is None:
            parser.error("--check requires a reference path")
        check_section(arguments.reference.read_bytes().decode("utf-8"),
                      render(arguments.blake3_bin))
        print("PASS: independent modern commit/ref witness section matches")


if __name__ == "__main__":
    main()
