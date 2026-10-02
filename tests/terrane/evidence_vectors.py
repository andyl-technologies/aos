"""Reproduces selector and private evidence fields with primitive CBOR only.

Ordinary ASTs, context syntax and encoder-only preimages are untrusted data.
Opaque signatures, token bytes and identity-shaped fields are never verified.
The raw BLAKE3 helper supplies only registered target-binding relationships.
"""

import argparse
from copy import deepcopy
from pathlib import Path
import re
import textwrap

from collection_vectors import encode, self_check as check_cbor
from foundation_vectors import raw_digest
from retirement_vectors import diagnostic_lines


HEADING = "## Selector and private evidence field witnesses"
PROOF_PREFIX = b"terrane-disclosure-proof-v1\0"
TARGET_PREFIX = b"terrane-disclosure-target-v1\0"
VIEW = bytes([1]) * 32
DOMAIN = "private:target"
PRESETS = ["any", "signed-baseline", "strict", "attested"]


def location(commit, root, path):
    """Constructs all three ordinary location fields."""
    return [bytes([commit]) * 32, bytes([root]) * 32, path]


def selector_models():
    """Constructs each registered executable atom and complete nesting topology."""
    models = {
        "selector-issuer": ["issuer", "issuer-a"],
        "selector-subject": ["subject", "user:*"],
        "selector-group": ["group", "baseline"],
        "selector-signed-by-key": ["signed-by-key", "12" * 32],
    }
    for kind in ["human", "workload", "service"]:
        models[f"selector-kind-{kind}"] = ["kind", kind]
    for source in ["built", "uploaded", "imported", "merged", "derived", "migrated"]:
        models[f"selector-source-{source}"] = ["source", source]
    for preset in PRESETS:
        models[f"selector-preset-{preset}"] = ["preset", preset]
        models[f"selector-property-{preset}"] = preset
    models.update({
        "selector-accepted-by": ["accepted-by", ["group", "baseline"]],
        "selector-attr-by": ["attr-by", "hash.sha256", ["kind", "workload"]],
        "selector-not": ["not", ["source", "imported"]],
        "selector-all-nested": ["all", [
            ["issuer", "issuer-a"],
            ["any", [["kind", "human"], ["subject", "user:*"]]],
            ["not", ["group", "blocked"]],
        ]],
        "selector-any-nested": ["any", [
            ["preset", "any"], ["accepted-by", ["group", "baseline"]],
        ]],
    })
    return models


def evidence(carrying):
    """Constructs all nine tuple elements; carrying and producer paths differ."""
    return [
        bytes([5]) * 32, bytes([6]) * 32, "hash.sha256", "sha256", "v1",
        encode(bytes([7]) * 32), bytes([8]) * 32,
        location(9 if carrying else 8, 10, b"carrying/item"),
        ["public", b"producer/full/item"],
    ]


def row(index, carrying):
    """Constructs complete view location and independent full view path."""
    return [location(1, 2 + index, b"relative/item"), "hash.sha256", DOMAIN,
            b"view/full/item", evidence(carrying)]


def context(version, baseline, rows=None):
    """Constructs exact v1/v2 presence fields without a trust evaluator."""
    fields = [version, VIEW, DOMAIN,
              encode(["attr-by", "hash.sha256", ["kind", "workload"]]),
              baseline, 262144]
    if version == 2:
        fields.append(encode([row(0, False), row(1, True)] if rows is None else rows))
    return fields


def statement(layout):
    """Constructs every registered statement slot and supported content case."""
    content = {
        "inline": [1, 24, [0, bytes([21]) * 32]],
        "manifest": [1, 65536, [1, bytes([21]) * 32]],
        "directory": [2],
        "symlink": [3, b"raw/\xfftarget"],
    }[layout]
    return [
        "12" * 32, "private:source", 256,
        location(11, 12, b"source/full/item"), bytes([13]) * 32,
        ["refs/heads/_/target", bytes([14]) * 32, b"target/full/item", DOMAIN],
        content, bytes([15]) * 32,
    ]


def opaque_recipe():
    """Constructs canonical recipe metadata with signature-shaped opaque values."""
    return {1: "map", 2: [bytes([7]) * 32],
            3: {"opaque": [bytes([0x8A]) * 64, {"signature": bytes([0x8B]) * 64}],
                "note": "kept"}}


def token():
    """Constructs syntax-only public token fields with fixed opaque signatures."""
    return [{
        1: "issuer-a", 2: "key-a", 3: "subject-a", 4: 2, 5: ["baseline"],
        6: 999, 7: 1, 8: bytes([8]) * 16,
        9: [["refs/heads/_/*", 4]], 10: "workload-a",
        11: bytes([0x8D]) * 32, 12: bytes([0x8C]) * 64,
    }]


def target_commit(variant="original", normalized=False):
    """Constructs all commit metadata while changing only requested signature slots."""
    changed = variant == "signatures"
    outer = bytes([0x91 if changed else 0x90]) * 64
    certificate = bytes([0x81 if changed else 0x80]) * 64
    second_certificate = bytes([0x83 if changed else 0x82]) * 64
    if normalized:
        certificate = second_certificate = bytes(64)
    source = location(31, 32, b"origin/item")
    proof = {1: "12" * 32, 2: "private:source", 3: 256, 4: certificate}
    other_proof = {1: "34" * 32, 2: "group:source", 3: 65536, 4: second_certificate}
    provenance = {
        1: "issuer-a", 2: bytes([8]) * 16, 3: "subject-a", 4: 2,
        5: "workload-a", 6: "process-a", 7: 24, 8: 2, 9: 4, 10: token(),
    }
    profile = {
        1: 1, 2: "cdc-1m", 3: opaque_recipe(), 4: False,
        5: {1: "owner-a", 2: 999},
        6: {"baseline": "baseline", "trust": ["preset", "strict"]},
        7: [
            [bytes([2]) * 32, b"a", 0,
             {"magic": 0, "hash.sha256": source}, source, proof],
            [bytes([2]) * 32, b"b", source],
            [bytes([3]) * 32, b"c", 0, None, source, other_proof],
        ],
        8: {1: "refs/heads/_/target", 2: "api", 3: {1: "r", 2: "z", 3: "h"},
            4: [[b"/", DOMAIN], [b"/nested", "group:target"]]},
    }
    result = {
        1: bytes([1]) * 32, 2: [bytes([4]) * 32, bytes([5]) * 32],
        3: provenance, 4: 256, 5: "retained metadata", 6: profile,
        7: [[bytes([6]) * 16, {1: "r", 2: "z", 3: "h"}]],
    }
    if variant == "opaque":
        result[6][3][3]["opaque"][0] = bytes([0x8E]) * 64
    if not normalized:
        result[8] = outer
    return result


def models(binary):
    """Builds the complete corpus as (field-model, wire, role) entries."""
    result = {}

    def add(name, model, role="Positive syntax/field vector.", wire=None):
        if name in result:
            raise ValueError(f"duplicate witness name: {name}")
        result[name] = (model, encode(model) if wire is None else wire, role)

    for name, model in selector_models().items():
        add(name, model)
    selector_negative = {
        "unknown-atom": ["other", "value"],
        "unregistered-attestation": ["attested", "claim"],
        "unknown-kind": ["kind", "other"],
        "unknown-source": ["source", "other"],
        "uppercase-key": ["signed-by-key", "AB" * 32],
        "short-key": ["signed-by-key", "12"],
        "unknown-preset": ["preset", "other"],
        "empty-all": ["all", []],
        "empty-any": ["any", []],
        "unknown-attribute": ["attr-by", "other", ["preset", "any"]],
        "wrong-arity": ["issuer", "a", "b"],
        "wrong-argument": ["issuer", 1],
    }
    for suffix, model in selector_negative.items():
        add(f"selector-negative-{suffix}", model, "Negative selector decoder input.")
    canonical = encode(["preset", "any"])
    for suffix, wire in [
        ("nonminimal", bytes([0x98, 2]) + canonical[1:]),
        ("trailing", canonical + b"\x00"),
        ("truncated", canonical[:-1]),
        ("huge-count", b"\x9b" + bytes([0xFF]) * 8),
    ]:
        add(f"selector-negative-{suffix}", wire, "Negative primitive decoder wire.", wire)

    for version in [1, 2]:
        for baseline, label in [(None, "absent"), ("", "empty"), ("baseline", "present")]:
            add(f"context-v{version}-{label}", context(version, baseline))
    bad_contexts = {}
    for suffix, index, value in [
        ("version", 0, 3), ("short-view", 1, b"x"),
        ("selector", 3, encode(["unknown", "x"])), ("baseline", 4, False),
    ]:
        model = context(1, None)
        model[index] = value
        bad_contexts[suffix] = model
    bad_contexts["empty-selected"] = context(2, None, [])
    for suffix, mutate in [
        ("wrong-view", lambda rows: rows[0][0].__setitem__(0, bytes([99]) * 32)),
        ("wrong-domain", lambda rows: rows[0].__setitem__(2, "public")),
        ("empty-full-path", lambda rows: rows[0].__setitem__(3, b"")),
        ("empty-carrying-path", lambda rows: rows[0][4][7].__setitem__(2, b"")),
        ("empty-producer-path", lambda rows: rows[0][4][8].__setitem__(1, b"")),
        ("short-record", lambda rows: rows[0][4].__setitem__(0, b"x")),
        ("wrong-name", lambda rows: rows[0][4].__setitem__(2, "magic")),
        ("noncanonical-value", lambda rows: rows[0][4].__setitem__(5, b"\x18\x01")),
        ("reversed-rows", lambda rows: rows.reverse()),
        ("duplicate-rows", lambda rows: rows.__setitem__(1, deepcopy(rows[0]))),
        ("short-tuple", lambda rows: rows[0][4].pop()),
    ]:
        rows = [row(0, False), row(1, True)]
        mutate(rows)
        bad_contexts[suffix] = context(2, None, rows)
    for suffix, model in bad_contexts.items():
        add(f"context-negative-{suffix}", model, "Negative syntax-only context input.")

    for carrying, label in [(False, "producer"), (True, "carrying")]:
        add(f"evidence-tuple-{label}", evidence(carrying), "Encoder-only nine-field tuple.")
    add("evidence-selected-one", [row(0, False)], "Encoder-only selected-row projection.")
    add("evidence-selected-two", [row(0, False), row(1, True)], "Encoder-only sorted selected-row projection.")
    add("evidence-selected-none", None, "Absent encoder projection; not a CBOR evidence record.", b"")

    for layout in ["inline", "manifest", "directory", "symlink"]:
        model = statement(layout)
        add(f"disclosure-statement-{layout}", model, "Encoder-only disclosure statement body.")
        add(f"disclosure-preimage-{layout}", [PROOF_PREFIX, model],
            "Encoder-only ASCII purpose plus zero byte plus canonical statement.",
            PROOF_PREFIX + encode(model))
    for variant in ["original", "signatures", "opaque"]:
        complete = target_commit(variant)
        normalized = target_commit(variant, normalized=True)
        add(f"disclosure-target-{variant}", complete, "Untrusted complete target commit fields.")
        add(f"disclosure-normalized-{variant}", normalized, "Unsigned normalized target preimage fields.")
        binding = raw_digest(binary, TARGET_PREFIX + encode(normalized))
        add(f"disclosure-binding-{variant}", binding,
            "Raw registered target-binding relationship; not an immutable identity.", binding)
    return result


def check_section(original, expected):
    """Compares one contiguous section, ignoring only LF boundary newlines."""
    headings = list(re.finditer(r"^## .*?$", original, re.MULTILINE))
    matches = [index for index, match in enumerate(headings) if match[0] == HEADING]
    if len(matches) != 1:
        raise ValueError("expected one selector/evidence reference section")

    index = matches[0]
    start = headings[index].start()
    end = headings[index + 1].start() if index + 1 < len(headings) else len(original)
    if original[start:end].rstrip("\n") != expected.rstrip("\n"):
        raise ValueError("selector/evidence fields or bytes differ")


def self_check(binary):
    """Checks fixed primitive bytes and precise projection relationships."""
    check_cbor()
    assert encode(["preset", "any"]).hex() == "826670726573657463616e79"
    assert encode(["not", ["group", "baseline"]]).hex() == (
        "82636e6f74826567726f757068626173656c696e65"
    )
    witnesses = models(binary)
    assert len(witnesses) == 86
    assert sum("Negative" in role for _, _, role in witnesses.values()) == 32
    assert target_commit("original", True) == target_commit("signatures", True)
    normalized = target_commit("original", True)
    original = target_commit("original")
    expected = deepcopy(original)
    del expected[8]
    for receipt in expected[6][7]:
        if len(receipt) == 6:
            receipt[5][4] = bytes(64)
    assert normalized == expected
    assert witnesses["disclosure-binding-original"][1] == witnesses["disclosure-binding-signatures"][1]
    assert witnesses["disclosure-binding-original"][1] != witnesses["disclosure-binding-opaque"][1]
    assert normalized[3][10] == original[3][10]
    assert normalized[6][3] == original[6][3]
    assert evidence(True)[6] != evidence(True)[7][0]
    assert evidence(False)[6] == evidence(False)[7][0]
    assert context(1, None)[0] == 1 and context(2, None)[0] == 2

    section = render(binary)
    check_section(section, section)
    check_section(section.rstrip("\n"), section)
    check_section("## Earlier\ntext\n" + section + "\n## Later\ntext\n", section)
    for invalid in [
        "",
        section + section,
        section.replace("```hex\n", "```hex\n00", 1),
        section.replace("### selector-issuer", "## Interrupted", 1),
        section.replace("\n", "\r\n"),
        section[:-1] + " \n",
        "prefix " + section,
    ]:
        try:
            check_section(invalid, section)
        except ValueError:
            continue
        raise ValueError("missing, duplicate, tampered or interrupted section was accepted")
    print("PASS: fixed CBOR oracles and 86 selector/evidence witnesses (32 negatives)")


def render(binary):
    """Renders complete diagnostics, byte strings and explicit projection roles."""
    parts = [HEADING, "", textwrap.fill(
        "These TEST-1/2 format witnesses describe selector ASTs, syntax-only "
        "trust contexts, selected side-evidence tuples, disclosure statement "
        "preimages and whole-target normalization. Encoder-only projections "
        "have no owning typed decoder. Signatures and token fields are opaque "
        "data; no history, evaluator, producer or disclosure authority is "
        "established. Raw target-binding hashes express field relationships "
        "only, without immutable descriptors or content identities.", 78), ""]
    for name, (model, wire, role) in models(binary).items():
        parts.extend([f"### {name}", "", role, "", "```text",
                      *diagnostic_lines(model), "```", "", "```hex",
                      *textwrap.wrap(wire.hex(), 72), "```", ""])
    return "\n".join(parts)


def main():
    """Emits or checks one bounded reference section without changing files."""
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
    section = render(arguments.blake3_bin)
    if arguments.emit:
        print(section, end="")
        return
    try:
        check_section(arguments.check.read_bytes().decode("utf-8"), section)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    print("PASS: independent selector/evidence reference section matches")


if __name__ == "__main__":
    main()
