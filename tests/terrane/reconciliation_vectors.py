"""Reproduces ordinary local-v1 reconciliation records with primitive CBOR.

All digests, fence pointers and exclusion fields are unverified format data.
This generator performs no hashing, signing, clock, backend or GC operation.
"""

import argparse
from copy import deepcopy
from pathlib import Path
import re
import textwrap

from collection_vectors import diagnostic, encode, head


HEADING = "## Local reconciliation record field witnesses"
MAX_UINT = (1 << 64) - 1


def fields(cycle=3, epoch=4, key="gc/5/fence/7", byte=1):
    """Constructs every required field, with independent original/current cycles."""
    return {0: 1, 1: bytes([byte]) * 32,
            2: [key, bytes([(byte + 1) % 256]) * 32],
            3: [bytes([(byte + 2) % 256]) * 16, cycle, epoch],
            4: bytes([(byte + 3) % 256]) * 32}


def positives():
    """Transcribes complete field models, including uint64 representation edges."""
    models = {
        "local-reconciliation-current-and-original": fields(),
        "local-reconciliation-zero-counters": fields(0, 0, "gc/0/fence/0", 0),
        "local-reconciliation-max-counters": fields(
            MAX_UINT, MAX_UINT, f"gc/{MAX_UINT}/fence/{MAX_UINT}", 252),
    }
    for value in [23, 24, 255, 256, 65535, 65536, (1 << 32) - 1, 1 << 32]:
        models[f"local-reconciliation-counter-{value}"] = fields(value, value)
    varied = fields(9, 2, "gc/12/fence/24")
    varied[1], varied[2][1] = bytes(range(32)), bytes(reversed(range(32)))
    varied[3][0], varied[4] = bytes(range(16)), bytes(range(32, 64))
    models["local-reconciliation-distinct-byte-fields"] = varied
    return models


def replace(model, path, value):
    """Replaces one independently transcribed field without a Terrane codec."""
    result = deepcopy(model)
    target = result
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return result


def raw_fields(model, path, raw):
    """Assembles a map with one raw field header for malformed-wire witnesses."""
    def value(item, prefix):
        if prefix == path:
            return raw
        if isinstance(item, list):
            return head(4, len(item)) + b"".join(
                value(child, prefix + (index,)) for index, child in enumerate(item))
        return encode(item)

    return head(5, len(model)) + b"".join(
        encode(key) + value(item, (key,)) for key, item in sorted(model.items()))


def negatives():
    """Reconstructs structural failures and exact pre-retention limit probes."""
    model = fields()
    wires = {}

    def add(name, changed):
        wires["bad-local-reconciliation-" + name] = encode(changed)

    for key in range(5):
        changed = deepcopy(model)
        del changed[key]
        add(f"missing-key-{key}", changed)
        add(f"null-key-{key}", replace(model, (key,), None))
    add("unknown-key", {**model, 5: 0})
    for version in [0, 2, MAX_UINT, True]:
        add(f"version-{version}", replace(model, (0,), version))
    for label, path, width in [
        ("authorization", (1,), 32), ("fence-digest", (2, 1), 32),
        ("pack", (3, 0), 16), ("index", (4,), 32),
    ]:
        for length in [0, width - 1, width + 1]:
            add(f"{label}-width-{length}", replace(model, path, bytes(length)))
        add(f"{label}-text", replace(model, path, "opaque"))
    for key, count in [(2, 2), (3, 3)]:
        for length in range(count + 2):
            if length != count:
                add(f"tuple-{key}-count-{length}", replace(model, (key,), [0] * length))
    for label, path in [("cycle", (3, 1)), ("epoch", (3, 2))]:
        for name, value in [("null", None), ("bool", False), ("text", "1")]:
            add(f"{label}-{name}", replace(model, path, value))
        for name, raw in [("negative", b"\x20"), ("nonminimal", b"\x18\x00")]:
            wires[f"bad-local-reconciliation-{label}-{name}"] = raw_fields(model, path, raw)
    for name, key in [
        ("empty", ""), ("wrong-prefix", "other/5/fence/7"),
        ("wrong-kind", "gc/5/reconcile/7"), ("cycle-leading-zero", "gc/05/fence/7"),
        ("revision-leading-zero", "gc/5/fence/07"), ("cycle-negative", "gc/-5/fence/7"),
        ("revision-plus", "gc/5/fence/+7"), ("extra-component", "gc/5/fence/7/more"),
        ("overflow", f"gc/{MAX_UINT + 1}/fence/7"),
        ("unicode", "gc/５/fence/7"), ("nul", "gc/5/fence/7\0"),
    ]:
        add(f"fence-key-{name}", replace(model, (2, 0), key))
    add("fence-key-bytes", replace(model, (2, 0), b"gc/5/fence/7"))
    wires["bad-local-reconciliation-fence-key-invalid-utf8"] = raw_fields(
        model, (2, 0), b"\x61\xff")
    wire = encode(model)
    for name, raw in [
        ("trailing", wire + b"\0"), ("truncated", wire[:-1]),
        ("nonminimal-map", b"\xb8\x05" + wire[1:]),
        ("indefinite-map", b"\xbf" + wire[1:] + b"\xff"),
        ("tag", b"\xc0" + wire),
    ]:
        wires["bad-local-reconciliation-" + name] = raw
    pairs = [(encode(key), encode(value)) for key, value in sorted(model.items())]
    wires["bad-local-reconciliation-key-order"] = head(5, 5) + b"".join(
        key + value for key, value in reversed(pairs))
    duplicate = deepcopy(pairs)
    duplicate[1] = (pairs[0][0], pairs[1][1])
    wires["bad-local-reconciliation-duplicate-key"] = head(5, 5) + b"".join(
        key + value for key, value in duplicate)

    wires["limit-local-reconciliation-map-count"] = head(5, MAX_UINT)
    for label, path, major in [
        ("authorization", (1,), 2), ("fence-tuple", (2,), 4),
        ("fence-key", (2, 0), 3), ("fence-digest", (2, 1), 2),
        ("exclusion-tuple", (3,), 4), ("pack", (3, 0), 2), ("index", (4,), 2),
    ]:
        wires["limit-local-reconciliation-" + label] = raw_fields(
            model, path, head(major, MAX_UINT))
    for label, path, width in [("authorization", (1,), 32), ("pack", (3, 0), 16)]:
        wires[f"limit-local-reconciliation-{label}-short-body"] = raw_fields(
            model, path, head(2, width + 1))
    long_key = replace(model, (2, 0), "x" * 4097)
    wires["limit-local-reconciliation-late-trailing"] = encode(long_key) + b"\0"
    return wires


def render():
    """Renders the complete non-content-addressed record field witnesses."""
    parts = [HEADING, "", textwrap.fill(
        "These TEST-1/TEST-2 witnesses cover the GC-29 local-v1 record-format "
        "prerequisite, using the exact LocalGcReconciliation CDDL. Authorization "
        "and fence digests, detached-index identities, pack IDs, original cycle "
        "and epoch are unverified claims. Registered fence-key spelling does "
        "not prove current selection. Current fence cycles may differ from "
        "original exclusion cycles. These non-content-addressed records have "
        "no immutable-content identity or descriptor. No native reconciliation, "
        "current-authority, elapsed-time, backend or deletion qualification is "
        "claimed. Decoder bounds are input and fixed-shape bounds; there is no "
        "invented record-size or 4096-byte fence-key cap.", 78), ""]
    for name, model in positives().items():
        parts += [f"### {name}", "", "```text", "fields = " + diagnostic(model),
                  "wire = " + encode(model).hex(), "```", ""]
    for name, wire in negatives().items():
        outcome = ("trailing input before key retention" if name.endswith("late-trailing")
                   else "input/fixed-shape limit" if name.startswith("limit-")
                   else "structural rejection")
        parts += [f"### {name}", "", "```text", "wire = " + wire.hex(),
                  "result = " + outcome, "```", ""]
    return "\n".join(parts)


def check_section(original, expected):
    """Requires one exact UTF-8 bounded section without newline normalization."""
    headings = list(re.finditer(r"^## .*?$", original, re.MULTILINE))
    matches = [index for index, match in enumerate(headings) if match[0] == HEADING]
    if len(matches) != 1:
        raise ValueError("expected exactly one local reconciliation witness section")
    index = matches[0]
    start = headings[index].start()
    end = headings[index + 1].start() if index + 1 < len(headings) else len(original)
    if original[start:end].rstrip("\n") != expected.rstrip("\n"):
        raise ValueError("local reconciliation fields or bytes differ")


def self_check():
    """Checks primitive edges, distinct fields and exact bounded refusal cases."""
    if encode({1: bytes(2), 0: 1}) != bytes.fromhex("a2000101420000"):
        raise ValueError("primitive CBOR oracle failed")
    if head(0, MAX_UINT) != b"\x1b" + b"\xff" * 8:
        raise ValueError("uint64 boundary oracle failed")
    positive, negative = positives(), negatives()
    if len(positive) != 12 or len(negative) != 79 or positive.keys() & negative.keys():
        raise ValueError("field-model count or names changed")
    section = render()
    check_section("## Earlier\ntext\n" + section + "\n## Later\ntext\n", section)
    for invalid in ["", section + section, section.replace("wire = ", "wire = 00", 1),
                    section.replace("### local-reconciliation-current-and-original", "## Split", 1),
                    section[:-1] + " \n", section.replace("\n", "\r\n")]:
        try:
            check_section(invalid, section)
        except ValueError:
            continue
        raise ValueError("missing, duplicate, split or tampered section was accepted")


def main():
    """Emits or checks one independently generated, additive reference section."""
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    for name in ["self-check", "emit", "check"]:
        modes.add_argument("--" + name, action="store_true")
    parser.add_argument("reference", type=Path, nargs="?")
    arguments = parser.parse_args()
    self_check()
    if arguments.self_check:
        print(f"PASS: {len(positives())} complete models; "
              f"{len(negatives())} independently assembled negative wires")
    elif arguments.emit:
        print(render(), end="")
    else:
        if arguments.reference is None:
            parser.error("--check requires a reference path")
        check_section(arguments.reference.read_bytes().decode("utf-8"), render())
        print("PASS: independent local reconciliation witness section matches")


if __name__ == "__main__":
    main()
