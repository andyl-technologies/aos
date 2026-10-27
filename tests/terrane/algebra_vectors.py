"""Constructs canonical recipe wire models without executing tree operations.

The inputs transcribe registered CDDL fields. The inert trust profile and
represented ownership labels never establish verified inputs or authority.
Only primitive CBOR writers and a raw digest helper reproduce these bytes.
"""

import argparse
from copy import deepcopy
from pathlib import Path
import textwrap

from collection_vectors import encode, self_check as check_cbor
from pack_vectors import digest
from retirement_vectors import diagnostic_lines


HEADING = "## Canonical composition recipe witnesses"
ROOTS = [bytes([number]) * 32 for number in [1, 2, 3]]
POLICIES = ["prefer-ours", "prefer-theirs", "prefer-trusted", "prefer-newer",
            "keep-conflict", "error"]
INERT_TRUST = {1: ["preset", "any"], 2: "terrane-preset-any/v1", 3: None, 4: []}
NEGATIVE_REASONS = {
    "recipe-unknown-operation": "The operation name has no registered schema.",
    "recipe-graft-target-mismatch": "The embedded tree entry names a different target root.",
    "recipe-graft-missing-entry": "The graft omits its complete canonical entry field.",
    "recipe-merge-wrong-arity": "The merge requires exactly base, ours and theirs.",
    "recipe-merge-missing-trust": "A trusted/newer policy requires its explicit trust argument.",
}


def models():
    """Constructs positive and rejecting inputs independently of format codecs."""
    witnesses = {
        "recipe-overlay-empty": {1: "overlay", 2: []},
        "recipe-overlay-ordered": {1: "overlay", 2: [ROOTS[2], ROOTS[0], ROOTS[1]]},
        "recipe-overlay-empty-domains": {1: "overlay", 2: ROOTS, 3: {"domains": []}},
    }
    for replace, label in [(False, "preserve"), (True, "replace")]:
        for domains, suffix in [(False, ""), (True, "-empty-domains")]:
            arguments = {"at": b"subtree", "entry": encode({1: 4, 6: ROOTS[1]}),
                         "replace": replace}
            if domains:
                arguments["domains"] = []
            witnesses[f"recipe-graft-{label}{suffix}"] = {
                1: "graft", 2: ROOTS[:2], 3: arguments,
            }
    variants = [
        ("empty-policy", [], False),
        ("ordered-policy", [POLICIES[index] for index in [1, 0, 4, 5]], False),
        ("empty-domains", [POLICIES[4]], True),
        ("inert-trust", POLICIES, False),
        ("inert-trust-empty-domains", POLICIES, True),
    ]
    for label, policies, domains in variants:
        arguments = {"policy": policies}
        if any(policy in ["prefer-trusted", "prefer-newer"] for policy in policies):
            arguments["trust"] = INERT_TRUST
        if domains:
            arguments["domains"] = []
        witnesses[f"recipe-merge-{label}"] = {1: "merge", 2: ROOTS, 3: arguments}

    witnesses["recipe-unknown-operation"] = {1: "unknown", 2: []}
    negative = deepcopy(witnesses["recipe-graft-preserve"])
    negative[3]["entry"] = encode({1: 4, 6: ROOTS[2]})
    witnesses["recipe-graft-target-mismatch"] = negative
    negative = deepcopy(witnesses["recipe-graft-preserve"])
    del negative[3]["entry"]
    witnesses["recipe-graft-missing-entry"] = negative
    negative = deepcopy(witnesses["recipe-merge-empty-policy"])
    negative[2] = ROOTS[:2]
    witnesses["recipe-merge-wrong-arity"] = negative
    witnesses["recipe-merge-missing-trust"] = {
        1: "merge", 2: ROOTS, 3: {"policy": ["prefer-trusted"]},
    }
    return witnesses


def self_check():
    """Checks fixed primitive bytes and exact field relationships."""
    check_cbor()
    witnesses = models()
    assert len(witnesses) == 17 and len(NEGATIVE_REASONS) == 5
    assert encode(witnesses["recipe-overlay-empty"]).hex() == "a201676f7665726c61790280"
    assert encode({1: 4, 6: ROOTS[1]}).hex() == "a20104065820" + "02" * 32
    assert encode(INERT_TRUST).hex() == (
        "a401826670726573657463616e79027574657272616e652d7072657365742d616e792f7631"
        "03f60480"
    )
    for name, model in witnesses.items():
        if name not in NEGATIVE_REASONS and model[1] == "merge":
            assert len(model[2]) == 3
            uses_trust = any(policy in ["prefer-trusted", "prefer-newer"]
                             for policy in model[3]["policy"])
            assert uses_trust == ("trust" in model[3])


def render(binary):
    """Renders complete field models and recipe digests without materialization."""
    parts = [HEADING, "", textwrap.fill(
        "These TEST-2 witnesses cover the implemented graft, overlay and merge "
        "schemas, including operand order, replacement, policy order and optional "
        "empty domain records. Positive format inputs carry recipe hashes in the "
        "registered memo domain, without acquiring immutable-content descriptors. "
        "The explicit `terrane-preset-any/v1` trust profile is inert: its decoding "
        "cannot authorize trusted/newer policies. No tree operation, view "
        "verification or effective ownership resolution is performed. Five "
        "negative wires require structural decoder rejection.", 78,
        break_on_hyphens=False), ""]
    for name, model in models().items():
        wire = encode(model)
        negative = name in NEGATIVE_REASONS
        description = ("Negative vector: " + NEGATIVE_REASONS[name]
                       if negative else "Positive format vector.")
        parts += [f"### {name}", "", textwrap.fill(description, 78), "", "```text",
                  *diagnostic_lines(model), "```", "", "```hex",
                  *textwrap.wrap(wire.hex(), 72), "```", ""]
        if not negative:
            parts += ["Recipe hash:", "", "```hex",
                      digest(binary, "terrane-memo-v1", wire).hex(), "```", ""]
    return "\n".join(parts)


def main():
    """Emits or checks one bounded section without modifying normative inputs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blake3-bin", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-check", action="store_true")
    mode.add_argument("--emit", action="store_true")
    mode.add_argument("--check", type=Path)
    arguments = parser.parse_args()
    self_check()
    if arguments.self_check:
        print("PASS: fixed CBOR oracles and seventeen independent recipe models")
        return
    section = render(arguments.blake3_bin)
    if arguments.emit:
        print(section, end="")
        return
    reference = arguments.check.read_text(encoding="utf-8")
    if reference.count(HEADING + "\n") != 1:
        raise SystemExit("expected one canonical recipe reference section")
    existing = reference.split(HEADING + "\n", 1)[1].split("\n## ", 1)[0]
    if (HEADING + "\n" + existing).rstrip() != section.rstrip():
        raise SystemExit("recipe models, bytes or digests differ")
    print("PASS: independent recipe reference section matches")


if __name__ == "__main__":
    main()
