"""Constructs inert publication/control alternatives from complete CDDL fields.

Primitive CBOR and the source-built raw BLAKE3 helper are the only wire oracles.
Bindings, roots, lease times, keys and identities are unauthenticated data.
No mutable/control record receives an immutable identity or descriptor.
"""

import argparse
from copy import deepcopy
import json
from pathlib import Path
import re
import textwrap

from collection_vectors import encode, self_check as check_cbor
from foundation_vectors import raw_digest


HEADING = "## Publication and original-control alternative witnesses"
BEHAVIOR = """acl baseline chunk classify compaction_threshold compression dedup
degraded domain durability encryption gap_merge_bytes hashes home index merge
on-release passthrough prefetch quota reassembly redundancy reflog_retain replicate
retain span_max_bytes store strict-attrs trust warm whole_pack_threshold wipe writers""".split()
NAME = "refs/heads/_/main"
NONCE = bytes([0x34]) * 32


def repeated(byte, size=32):
    """Constructs opaque fixed-length fixture bytes."""
    return bytes([byte]) * size


def binding(kind):
    """Constructs each physical binding without locating a backend."""
    if kind == "local":
        return [0, b"/a", 1, 2, 3, 4]
    return [1, kind, ["https://endpoint/É", "bucket", b"" if kind == "s3" else b"p/\xff",
                      repeated(3)], [b"coord/\x00", repeated(4)]]


def physical(kind):
    """Preserves the v1 local and case-two remote registration shapes."""
    if kind == "local":
        return [1, repeated(1), b"/r", "public", 1, 2, 3, 4, b"/c"]
    return [2, repeated(1), "public", binding(kind), b"original/\x00"]


def acl():
    """Preserves ordering, repeated principals and the zero/all verb masks."""
    return [["principal", 0], ["principal", 31], ["group", 2]]


def bootstrap(empty=False):
    """Constructs all bootstrap fields with an explicitly empty/full ACL."""
    return [1, repeated(1), NAME, 3, [] if empty else acl()]


def association():
    """Constructs the opaque claimed commit association."""
    return [1, repeated(2), repeated(1), NAME, 3]


def imported(kind, version):
    """Constructs each registered import version independently."""
    return [version, physical(kind), bootstrap(), association()]


def issuers():
    """Constructs sorted keys with absent and present retirement fields."""
    return [["issuer", "a", repeated(5), None], ["issuer", "b", repeated(6), 0]]


def disclosures():
    """Constructs sorted opaque roles with bounded and open intervals."""
    return [["01" * 32, "public", repeated(7), 0, None],
            ["01" * 32, "public", repeated(8), 1, 2]]


def config(mode):
    """Constructs every configuration field and all optional-text states."""
    return {0: 1, 1: "store", 2: "" if mode == 1 else "hint",
            3: {} if mode == 0 else ({1: "", 3: ""} if mode == 1 else
                                     {1: "region", 2: "zone", 3: "host"}),
            4: acl(), 5: 262144, 6: "public", 7: "cdc-1m",
            8: [262144, 1048576, 4194304, 48, 2, repeated(9)],
            9: [None, "", "policy"][mode]}


def registry():
    """Lists complete registered behaviors and disjoint inert later names."""
    return {0: 1, 1: 1, 2: BEHAVIOR, 3: 1, 4: 1, 5: 1, 6: 1,
            7: "terrane-v1", 8: ["future-a", "future-z"]}


def head():
    """Constructs a whole retained head including its candidate selector."""
    return {1: repeated(2), 2: 1, 3: 3, 4: {1: "region", 2: "", 3: "host"},
            6: repeated(10)}


def branches():
    """Constructs all selection alternatives in unique unsigned-name order."""
    return [["refs/conflicts/_/old/00000000000000000001", [2]], [NAME, [1, head()]],
            ["refs/jobs/_/never", [0]]]


def history(kind):
    """Constructs complete retained history with a claimed origin stamp."""
    return {0: 1, 1: branches(), 2: binding(kind)}


def inventory(kind):
    """Constructs full inventory, including absence versus present-empty bytes."""
    return [["CAPABILITIES", b""], ["gc/lease", None],
            ["publication/SELECTED-HISTORY", encode(history(kind))],
            ["refs/conflicts/_/old/00000000000000000001:record", None], [NAME + ":record", encode(head())],
            ["refs/jobs/_/never:record", None]]


def snapshot(kind, delta=0):
    """Constructs full checkpoints and empty/populated exact predecessor deltas."""
    if delta:
        rows = [] if delta == 1 else [["CAPABILITIES", b""], ["gc/lease", None]]
        return {0: 1, 1: 1, 2: binding(kind), 3: rows,
                4: ["publication/snapshots/0:" + NONCE.hex(), repeated(11)]}
    return {0: 1, 1: 0, 2: binding(kind), 3: inventory(kind), 4: None}


def state(kind, owners=0):
    """Constructs populated state while preserving omitted versus empty owners."""
    value = {0: 1, 1: 0, 2: 0, 3: [[NAME, repeated(12)]], 4: binding(kind),
             5: branches(), 6: repeated(13)}
    if owners:
        value[7] = [] if owners == 1 else [[repeated(0x12, 16), [0]]]
    return value


def genesis(binary, kind):
    """Constructs valid genesis mandatory changes and raw snapshot relationship."""
    return {0: 1, 1: NONCE, 2: None, 3: encode(state(kind)),
            4: [[key, None, value] for key, value in inventory(kind)],
            5: [0], 6: None,
            7: ["publication/snapshots/0:" + NONCE.hex(),
                raw_digest(binary, encode(snapshot(kind)))]}


def authorization(binary, kind, lineage=False):
    """Constructs complete embedded sweep/copied data, without retirement effects."""
    pack = repeated(0x12, 16)
    tombstone = encode({1: pack, 2: 3, 3: 4, 4: 0, 5: 2})
    trash = ["trash/3/" + pack.hex(), raw_digest(binary, tombstone), len(tombstone)]
    backend = [0, b"/a", 1, 2, 3, 4] if kind == "local" else [
        1, "s3", ["e", "b", b"", repeated(1)], [b"c", repeated(2)]]
    value = {0: 2, 1: NONCE, 2: backend, 3: [pack, 3, 2],
             4: {1: "A", 2: 2, 3: 100}, 5: 2, 8: tombstone, 9: 2000000000,
             10: ["gc/3/fence/2", repeated(8)], 11: 1, 12: 1000000000, 13: 1}
    if kind == "sweep":
        witness = b"TRPK\x01\x00\x00\x00" + pack + b"TRIX" + bytes(8)
        base = "objects/pack/12/" + pack.hex()
        value[6] = [[base + ".pack", repeated(7), 52],
                    [base + ".idx", raw_digest(binary, b"terrane-index-v1\x00" + witness), 36], trash]
        value[7] = witness
    else:
        barrier = [trash[0], repeated(5), [2, tombstone], b"\x06"] if kind == "local" else trash
        value.update({6: [None, None, barrier], 14: 1,
                      15: [0, repeated(9)], 16: [1, repeated(10)]})
        if lineage:
            value[17] = ["gc/3/fence/2", repeated(21)]
    return value


def corpus(binary):
    """Constructs positive and malformed wire inputs without owning encoders."""
    values = {}
    negative = {}
    inputs = {}

    def add(name, value):
        if name in values:
            raise ValueError("duplicate witness name")
        values[name] = encode(value)
        inputs[name] = deepcopy(value)
        return value

    def reject(name, value, reason):
        add("control-negative-" + name, value)
        negative["control-negative-" + name] = reason

    for kind in ["local", "s3", "gcs"]:
        add("control-binding-" + kind, binding(kind))
        for phase, digest in [(0, None), (0, repeated(14)), (1, repeated(14))]:
            label = "pending-null" if digest is None else ("pending-digest" if phase == 0 else "active")
            add(f"control-registration-{kind}-{label}", {0: 1, 1: binding(kind), 2: phase, 3: digest})
        add("control-physical-" + kind, physical(kind))
        add("control-history-" + kind, history(kind))
        add("control-snapshot-" + kind + "-full", snapshot(kind))
        add("control-snapshot-" + kind + "-delta-empty", snapshot(kind, 1))
        add("control-snapshot-" + kind + "-delta-rows", snapshot(kind, 2))
        transaction = add("control-genesis-" + kind, genesis(binary, kind))
        add("control-commit-" + kind, {0: 1, 1: 0, 2: None,
                                      3: "publication/transactions/" + NONCE.hex(),
                                      4: raw_digest(binary, encode(transaction))})
        add("control-portable-current-" + kind, {0: 1, 1: transaction[7][0], 2: transaction[7][1]})
    add("control-binding-local-bounds", [0, b"/", 0, 23, 24, (1 << 64) - 1])
    add("control-binding-remote-bounds", [1, "gcs", ["é" * 2048, "b" * 4096,
                                                   bytes(4096), repeated(3)],
                                         [bytes(4096), repeated(4)]])
    add("control-local-registration", physical("local"))
    add("control-bootstrap-empty", bootstrap(True))
    add("control-bootstrap-full", bootstrap())
    add("control-association", association())
    for kind, version in [("local", 1), ("local", 2), ("s3", 2), ("gcs", 2)]:
        label = f"{kind}-v{version}"
        value = add("control-import-" + label, imported(kind, version))
        digest = raw_digest(binary, encode(value))
        add("control-import-binding-" + label, [1, repeated(2), repeated(1), repeated(15), digest])
        add("control-import-trust-" + label,
            [1, digest, repeated(1), repeated(15), issuers(), disclosures()])
    for index, row in enumerate(issuers()):
        add(f"control-issuer-{index}", row)
    for index, row in enumerate(disclosures()):
        add(f"control-disclosure-{index}", row)
    for mode, kind in enumerate(["local", "s3", "gcs"]):
        add(f"control-config-{mode}", config(mode))
        add(f"control-guard-{kind}", {0: 1, 1: physical(kind), 2: issuers(),
                                     3: disclosures(), 4: config(mode), 5: registry()})
    add("control-registry", registry())
    attribute_two = registry()
    attribute_two[3] = 2
    add("control-registry-attribute-two", attribute_two)
    add("control-profile", config(0)[8])
    for index in range(3):
        add(f"control-selection-{index}", branches()[index][1])
        add(f"control-state-owners-{index}", state("local", index))
    add("control-publication-current", {0: 1, 1: 0, 2: repeated(16)})
    add("control-commit-next", {0: 1, 1: 1, 2: repeated(16),
                                 3: "publication/transactions/" + NONCE.hex(), 4: repeated(17)})
    add("control-proof-raw", [0])
    add("control-proof-candidate", [1, repeated(18)])
    add("control-proof-guard", [4, repeated(19)])
    add("control-proof-collection-empty", [2, "gc/3/fence/2", repeated(20), [], []])
    collection = [2, "gc/3/fence/2", repeated(20),
                  [[repeated(0x12, 16), repeated(21)], [repeated(0x13, 16), repeated(22)]],
                  [[NAME, repeated(23)], ["refs/tags/_/alias", repeated(24)]]]
    add("control-proof-collection-full", collection)
    repeated_pack = deepcopy(collection)
    repeated_pack[3].append(deepcopy(repeated_pack[3][0]))
    add("control-proof-collection-repeated", repeated_pack)
    for kind, lineage in [("sweep", False), ("remote", False), ("remote", True), ("local", True)]:
        label = kind + ("-lineage" if lineage else "")
        auth = authorization(binary, kind, lineage)
        add("control-authorization-" + label, auth)
        add("control-proof-retirement-" + label,
            [3, encode(auth), [[NAME, repeated(23)]] if lineage or kind == "sweep" else []])

    malformed = binding("local")
    malformed[1] = b"/a/../b"
    reject("local-path", malformed, "The local root is not normalized.")

    malformed = binding("s3")
    malformed[1] = "azure"
    reject("provider", malformed, "Only the registered S3/GCS tags exist.")

    malformed = binding("s3")
    malformed[2][0] = ""
    reject("endpoint-empty", malformed, "The endpoint is nonempty text.")

    malformed = binding("s3")
    malformed[2][2] = bytes(4097)
    reject("prefix-bound", malformed, "Prefix bytes exceed 4096.")

    malformed = binding("s3")
    malformed[2][3] = repeated(3, 31)
    reject("nonce-short", malformed, "The registration nonce is exactly 32 bytes.")
    reject("active-null", {0: 1, 1: binding("local"), 2: 1, 3: None}, "Active requires a genesis digest.")
    reject("activation", {0: 1, 1: binding("local"), 2: 2, 3: None}, "There is no activation case two.")
    malformed = physical("local")
    malformed[0] = 2
    reject("local-version", malformed, "There is no local nine-field version-two record.")

    malformed = physical("s3")
    malformed[3] = binding("local")
    reject("remote-local", malformed, "Remote registration requires the remote binding case.")

    malformed = bootstrap()
    malformed[4][0][1] = 32
    reject("acl-mask", malformed, "ACL masks cannot exceed 31.")
    malformed = imported("s3", 1)
    reject("import-v1-remote", malformed, "Import v1 admits local registration only.")
    malformed = imported("local", 2)
    malformed[3][2] = repeated(99)
    reject("import-id", malformed, "Repeated original IDs disagree.")
    reject("trust-version", [2, repeated(1), repeated(1), repeated(15), [], []], "Trust retains version one.")
    reject("issuers-order", [1, repeated(1), repeated(1), repeated(15), list(reversed(issuers())), disclosures()], "Issuer rows must be sorted uniquely.")
    reject("disclosure-interval", ["01" * 32, "public", repeated(7), 2, 2], "The exclusive end must exceed the start.")
    malformed = config(2)
    malformed[5] = 1
    reject("config-minimum", malformed, "The minimum contradicts the profile.")

    malformed = registry()
    malformed[3] = 3
    reject("registry-revision", malformed, "Attribute revision three is unregistered.")

    malformed = registry()
    malformed[8] = ["acl"]
    reject("registry-overlap", malformed, "Later names cannot duplicate behavioral names.")
    malformed = {0: 1, 1: physical("local"), 2: issuers(), 3: disclosures(), 4: config(0), 5: registry()}
    malformed[4][6] = "private:elsewhere"
    reject("guard-domain", malformed, "The claimed physical domains disagree.")
    malformed = snapshot("local")
    malformed[3].pop(0)
    reject("snapshot-inventory", malformed, "A full checkpoint requires CAPABILITIES.")

    malformed = snapshot("local")
    malformed[3][1][1] = b""
    reject("snapshot-lease", malformed, "Portable projection clears the lease, even for empty bytes.")

    malformed = snapshot("local")
    malformed[3][-1][1] = encode(head())
    reject("snapshot-selection", malformed, "A projected head contradicts retained Never history.")

    malformed = snapshot("local", 1)
    malformed[1] = 2
    reject("delta-revision", malformed, "A delta must immediately follow its predecessor.")

    malformed = genesis(binary, "local")
    malformed[4].pop(0)
    reject("genesis-inventory", malformed, "Genesis requires a present CAPABILITIES change.")

    malformed = genesis(binary, "local")
    malformed[4][0][1] = b""
    reject("genesis-expected", malformed, "Genesis expectations must be absent, not empty bytes.")

    malformed = genesis(binary, "local")
    malformed[7][0] = "publication/snapshots/0:" + "00" * 32
    reject("genesis-nonce", malformed, "The snapshot operation nonce disagrees.")
    reject("commit-predecessor", {0: 1, 1: 1, 2: None, 3: "publication/transactions/" + NONCE.hex(), 4: repeated(17)}, "Nongenesis requires a predecessor digest.")
    malformed = state("local")
    malformed[6] = None
    reject("state-guard", malformed, "Sources require a represented Guard digest.")

    malformed = deepcopy(collection)
    malformed[3].append([repeated(0x12, 16), repeated(99)])
    reject("proof-index", malformed, "Repeated pack witnesses contradict one another.")
    reject("proof-carried-order", [2, "gc/3/fence/2", repeated(20), [], list(reversed(collection[4]))], "Carried sources must be sorted uniquely.")
    reject("proof-copy-lineage", [3, encode(authorization(binary, "remote")), [[NAME, repeated(23)]]], "Carrying copied lineage requires its lineage fence field.")
    reject("proof-tag", [5], "No proof case five exists.")

    base = encode(binding("local"))
    for name, wire, reason in [
        ("truncated", base[:-1], "A field is truncated."),
        ("trailing", base + b"\x00", "Trailing data is forbidden."),
        ("nonminimal", b"\x98\x06" + base[1:], "An array length uses a nonminimal head."),
        ("huge-array", b"\x9b" + b"\xff" * 8, "The declared count exceeds the schema bound."),
        ("huge-bytes", b"\x86\x00\x5b" + b"\xff" * 8, "The declared byte count exceeds the bound."),
    ]:
        key = "control-negative-" + name
        values[key] = wire
        negative[key] = reason
    return values, negative, inputs


def diagnostic(value):
    """Renders complete CBOR fields with exact UTF-8 and byte strings."""
    if value is None:
        return "null"
    if isinstance(value, bytes):
        return "h'" + value.hex() + "'"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ", ".join(map(diagnostic, value)) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{key}: {diagnostic(item)}" for key, item in sorted(value.items())) + "}"
    return str(value)


def diagnostic_tokens(value):
    """Splits long literals only with registered EDN same-kind concatenation."""
    if isinstance(value, str):
        return [diagnostic(value[offset:offset + 48])
                for offset in range(0, len(value), 48)] or ['""']
    if isinstance(value, bytes):
        hexadecimal = value.hex()
        return ["h'" + hexadecimal[offset:offset + 64] + "'"
                for offset in range(0, len(hexadecimal), 64)] or ["h''"]
    if isinstance(value, list):
        tokens = ["["]
        for index, item in enumerate(value):
            tokens.extend([","] if index else [])
            tokens.extend(diagnostic_tokens(item))
        return tokens + ["]"]
    if isinstance(value, dict):
        tokens = ["{"]
        for index, (key, item) in enumerate(sorted(value.items())):
            tokens.extend([","] if index else [])
            tokens.extend([str(key), ":"])
            tokens.extend(diagnostic_tokens(item))
        return tokens + ["}"]
    return [diagnostic(value)]


def diagnostic_lines(value):
    """Keeps exact diagnostic literals intact while wrapping semantic tokens."""
    lines = []
    line = ""
    for token in diagnostic_tokens(value):
        if line and len(line) + len(token) + 1 > 78:
            lines.append(line)
            line = token
        else:
            line += (" " if line else "") + token
    return lines + ([line] if line else [])


def render(binary):
    """Publishes complete diagnostic input models and independently encoded wires."""
    values, negative, inputs = corpus(binary)
    lines = [HEADING, "", "These are unauthenticated format inputs only. Raw BLAKE3 fields relate",
             "embedded bytes; they do not grant authority or identify mutable control records.",
             "Opaque CAPABILITIES bytes illustrate presence only, without payload validation.", ""]
    for name, wire in values.items():
        lines.extend([f"### {name}", "", negative.get(name, "Positive complete field model; owning decoding establishes format consistency only."),
                      ""])
        if name in inputs:
            lines.extend(["```text", *diagnostic_lines(inputs[name]), "```", ""])
        else:
            lines.extend(["The complete malformed primitive wire is the input below.", ""])
        lines.extend(["```hex",
                      *textwrap.wrap(wire.hex(), 64), "```", ""])
    return "\n".join(lines)


def check_section(original, expected):
    """Checks a unique contiguous top-level section with only LF boundary tolerance."""
    headings = list(re.finditer(r"^## .*?$", original, re.MULTILINE))
    matches = [index for index, match in enumerate(headings) if match[0] == HEADING]
    if len(matches) != 1:
        raise ValueError("missing or duplicate control witness section")
    index = matches[0]
    end = headings[index + 1].start() if index + 1 < len(headings) else len(original)
    if original[headings[index].start():end].rstrip("\n") != expected.rstrip("\n"):
        raise ValueError("control witness section differs from its exact wire input")


def self_check(binary):
    """Checks primitive controls and refuses exact-section boundary/content corruption."""
    check_cbor()
    values, negative, inputs = corpus(binary)
    assert len(values) == len(set(values)) and set(negative) <= set(values)
    assert len(values) == 126 and len(negative) == 37
    assert len(values) - len(negative) == 89
    assert all(values[name] == encode(value) for name, value in inputs.items())
    attribute_two = deepcopy(inputs["control-registry"])
    attribute_two[3] = 2
    assert inputs["control-registry-attribute-two"] == attribute_two
    assert inputs["control-negative-registry-revision"][1] == 1
    assert inputs["control-negative-registry-revision"][3] == 3
    assert negative["control-negative-registry-revision"] == "Attribute revision three is unregistered."
    assert raw_digest(binary, b"").hex() == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    expected = render(binary)
    check_section(expected, expected)
    check_section("## Earlier\n\nUnrelated.\n\n" + expected + "\n## Later\n\nUnrelated.\n", expected)
    check_section(expected.rstrip("\n"), expected)
    wire = next(iter(values.values())).hex()[:16]
    malformed = ["", expected + "\n" + expected,
                 expected.replace(wire, "00" + wire[2:], 1),
                 expected.replace("### control-binding-local", "## Interrupted", 1),
                 expected.replace("\n", "\r\n"), expected.replace("```hex\n", "```hex \n", 1),
                 "prefix " + expected]
    for item in malformed:
        try:
            check_section(item, expected)
        except ValueError:
            continue
        raise AssertionError("exact section corruption was accepted")
    print(f"PASS: {len(values)} complete primitive wires; {len(values) - len(negative)} positive and {len(negative)} structural negative inputs")


def main():
    """Runs one read-only corpus operation with an explicitly supplied hash helper."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blake3-bin", required=True, type=Path)
    operations = parser.add_mutually_exclusive_group(required=True)
    operations.add_argument("--self-check", action="store_true")
    operations.add_argument("--emit", action="store_true")
    operations.add_argument("--check", type=Path)
    args = parser.parse_args()
    if args.self_check:
        self_check(args.blake3_bin)
    elif args.emit:
        print(render(args.blake3_bin), end="")
    else:
        check_section(args.check.read_bytes().decode("utf-8"), render(args.blake3_bin))
        print("PASS: exact contiguous publication/control witness section")


if __name__ == "__main__":
    main()
