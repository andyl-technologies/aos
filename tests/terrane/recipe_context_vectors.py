"""Reproduces ordinary outer recipe fields using independent CBOR primitives.

Serialized domain and trust claims remain unauthenticated. Configuration is
retained canonical data; profile execution and fold re-evaluation are outside
these witnesses. No evaluator, authority, store or algebra operation is used.
"""

import argparse
from copy import deepcopy
from pathlib import Path
import tempfile
import textwrap

from collection_vectors import diagnostic, encode, head
from pack_vectors import digest


HEADING = "## Outer recipe domain and trust field witnesses"
ROOTS = [bytes([value]) * 32 for value in [1, 2, 3]]


def overlay(domains):
    """Constructs the entire enclosing overlay field map."""
    return {1: "overlay", 2: ROOTS, 3: {"domains": domains}}


def merge(trust):
    """Constructs an ordered merge retaining inert trust evidence."""
    return {1: "merge", 2: ROOTS, 3: {
        "trust": trust,
        "policy": ["prefer-trusted", "prefer-newer", "keep-conflict"],
    }}


def context(view, domain, selector, baseline, minimum):
    """Constructs complete version-one context bytes as ordinary data."""
    return encode([1, bytes([view]) * 32, domain, encode(selector), baseline, minimum])


def positives():
    """Transcribes complete enclosing recipes and every nested field."""
    values = {}
    for index, label in enumerate(["public", "tenant:tenant-a", "group:editors", "private:owner"]):
        values[f"recipe-domain-{index}"] = overlay([[ROOTS[0], label]])
    rows = [[ROOTS[0], "public"], [ROOTS[1], "private:owner"], [ROOTS[2], "group:editors"]]
    values["recipe-domain-multiple"] = overlay(rows)
    values["recipe-domain-graft"] = {1: "graft", 2: ROOTS[:2], 3: {
        "at": b"mount/child", "entry": encode({1: 4, 6: ROOTS[1]}),
        "replace": True, "domains": rows[:2],
    }}

    any_selector = ["preset", "any"]
    inert = {1: any_selector, 2: "terrane-preset-any/v1", 3: None, 4: []}
    values["recipe-trust-inert"] = merge(inert)
    general = {1: ["preset", "strict"], 2: "ordinary-evidence/v2",
               3: {1: [False, True, None, 24, b"context"], 2: "configuration"},
               4: [bytes([4]) * 32, bytes([5]) * 32]}
    values["recipe-trust-accepted"] = merge(general)
    timed = deepcopy(general)
    timed[5] = [[bytes([4]) * 32, 0], [bytes([5]) * 32, 2**64 - 1]]
    values["recipe-trust-timestamps"] = merge(timed)
    selector = ["all", [
        ["issuer", "issuer-a"], ["subject", "subject-*"], ["kind", "workload"],
        ["group", "editors"], ["source", "source-a"], ["signed-by-key", "ab" * 32],
        ["attested", "claim-a"], ["accepted-by", ["preset", "signed-baseline"]],
        ["not", ["preset", "attested"]], ["attr-by", "hash.sha256", ["kind", "human"]],
        ["any", [["kind", "service"], any_selector]],
    ]]
    complex_trust = deepcopy(general)
    complex_trust[1] = selector
    values["recipe-trust-selector"] = merge(complex_trust)
    contexts = [context(6, "private:ours", ["preset", "strict"], "baseline-a", 4096),
                context(7, "group:incoming", ["preset", "any"], None, 8192)]
    for suffix, preprocessing in [
        ("null", None),
        ("fold", [ROOTS[0], ROOTS[2], bytes([8]) * 32, [b"a", b"a/child", b"z"]]),
        ("fold-domain", [ROOTS[0], ROOTS[2], bytes([8]) * 32,
                         [b"a", b"a/child", b"z"], "private:incoming"]),
    ]:
        values[f"recipe-trust-verified-{suffix}"] = merge({
            1: any_selector, 2: "terrane-verified-path/v1",
            3: [contexts, preprocessing], 4: [],
        })
    return values


def negatives():
    """Builds malformed bytes independently, bypassing owning encoders."""
    values = {}
    rows = [[ROOTS[0], "public"]]
    domain_cases = {
        "short-digest": [[b"x" * 31, "public"]],
        "long-digest": [[b"x" * 33, "public"]],
        "digest-type": [[1, "public"]], "label-type": [[ROOTS[0], b"public"]],
        "short-pair": [[ROOTS[0]]], "long-pair": [[ROOTS[0], "public", None]],
        "duplicate": rows * 2,
        "reversed": [[ROOTS[1], "public"], [ROOTS[0], "public"]],
    }
    for label in ["unknown", "tenant:", "group:", "private:", "public:owner", ""]:
        domain_cases[f"grammar-{len(domain_cases)}"] = [[ROOTS[0], label]]
    for name, fields in domain_cases.items():
        values[f"recipe-domain-negative-{name}"] = encode(overlay(fields))
    base_domain = encode(overlay(rows))
    values["recipe-domain-negative-trailing"] = base_domain + b"\x00"
    values["recipe-domain-negative-truncated"] = base_domain[:-1]
    values["recipe-domain-negative-nonminimal"] = b"\xb8\x03" + base_domain[1:]
    prefix = head(5, 3) + encode(1) + encode("overlay") + encode(2) + encode(ROOTS)
    prefix += encode(3) + head(5, 1) + encode("domains")
    values["recipe-domain-negative-huge-count"] = prefix + head(4, 2**64 - 1)
    values["recipe-domain-negative-invalid-utf8"] = prefix + b"\x81\x82" + encode(ROOTS[0]) + b"\x61\xff"

    trust = {1: ["preset", "strict"], 2: "ordinary-evidence/v2", 3: None, 4: [bytes([4]) * 32]}
    cases = {}
    for key in [1, 2, 3, 4]:
        fields = deepcopy(trust)
        del fields[key]
        cases[f"missing-{key}"] = fields
    for name, key, field in [
        ("unknown", 6, None), ("version-empty", 2, ""), ("version-type", 2, 1),
        ("accepted-short", 4, [b"x" * 31]), ("accepted-long", 4, [b"x" * 33]),
        ("accepted-type", 4, [1]), ("accepted-duplicate", 4, [ROOTS[0], ROOTS[0]]),
        ("accepted-reversed", 4, [ROOTS[1], ROOTS[0]]),
        ("timestamps-empty", 5, []), ("timestamps-null", 5, None),
        ("timestamp-short", 5, [[b"x" * 31, 1]]),
        ("timestamp-pair-short", 5, [[ROOTS[0]]]),
        ("timestamp-pair-long", 5, [[ROOTS[0], 1, 2]]),
        ("timestamp-value", 5, [[ROOTS[0], "1"]]),
        ("timestamp-duplicate", 5, [[ROOTS[0], 1], [ROOTS[0], 2]]),
        ("timestamp-reversed", 5, [[ROOTS[1], 1], [ROOTS[0], 2]]),
        ("selector-unknown", 1, ["unknown", "x"]),
        ("selector-kind", 1, ["kind", "unknown"]),
        ("selector-preset", 1, ["preset", "unknown"]),
        ("selector-attr", 1, ["attr-by", "unknown", ["preset", "any"]]),
        ("selector-empty-all", 1, ["all", []]),
        ("selector-empty-any", 1, ["any", []]),
        ("selector-short", 1, ["issuer"]),
        ("selector-long", 1, ["issuer", "x", "y"]),
        ("selector-atom-type", 1, ["issuer", 1]),
        ("selector-attribute-limit", 1, ["attr-by", "x" * 256, ["preset", "any"]]),
    ]:
        fields = deepcopy(trust)
        fields[key] = field
        cases[name] = fields
    for name, fields in cases.items():
        values[f"recipe-trust-negative-{name}"] = encode(merge(fields))
    base_trust = encode(merge(trust))
    values["recipe-trust-negative-trailing"] = base_trust + b"\x00"
    values["recipe-trust-negative-truncated"] = base_trust[:-1]
    values["recipe-trust-negative-nonminimal"] = b"\xb8\x03" + base_trust[1:]
    for name, raw in [
        ("configuration-tag", b"\xc0\x00"),
        ("configuration-float", b"\xf9\x00\x00"),
        ("configuration-unsorted", b"\xa2\x02\x00\x01\x00"),
        ("configuration-duplicate", b"\xa2\x01\x00\x01\x00"),
        ("configuration-huge", head(4, 2**64 - 1)),
        ("configuration-nonminimal", b"\x18\x00"),
        ("configuration-key-type", b"\xa1\x80\x00"),
    ]:
        marker = encode(trust)
        position = marker.index(b"\x03\xf6") + 1
        malformed = marker[:position] + raw + marker[position + 1:]
        wire = head(5, 3) + encode(1) + encode("merge") + encode(2) + encode(ROOTS)
        wire += encode(3) + head(5, 2) + encode("trust") + malformed
        wire += encode("policy") + encode(["prefer-trusted", "prefer-newer", "keep-conflict"])
        values[f"recipe-trust-negative-{name}"] = wire
    for name, key, raw in [
        ("accepted-huge", 4, head(4, 2**64 - 1)),
        ("timestamps-huge", 5, head(4, 2**64 - 1)),
        ("version-invalid-utf8", 2, b"\x61\xff"),
    ]:
        fields = deepcopy(trust)
        fields[key] = None
        encoded = encode(fields)
        position = encoded.index(encode(key) + b"\xf6") + len(encode(key))
        malformed = encoded[:position] + raw + encoded[position + 1:]
        wire = head(5, 3) + encode(1) + encode("merge") + encode(2) + encode(ROOTS)
        wire += encode(3) + head(5, 2) + encode("trust") + malformed
        wire += encode("policy") + encode(["prefer-trusted", "prefer-newer", "keep-conflict"])
        values[f"recipe-trust-negative-{name}"] = wire
    return values


def render(binary):
    """Renders all fields and only proper enclosing positive recipe identities."""
    parts = [HEADING, "", textwrap.fill(
        "These TEST-1/TEST-2/TEST-3 witnesses cover ordinary outer recipe fields "
        "for ALG-29/ALG-37/ALG-38 using the registered recipe CDDL. Complete "
        "domain labels, selectors, evaluator versions, accepted identities, "
        "timestamps, context bytes and fold fields remain unauthenticated data. "
        "Configuration is retained canonical CBOR; profile execution, context "
        "verification and fold re-evaluation are separate obligations. Only "
        "positive enclosing recipes have registered memo identities. Negative "
        "wires require structural decoder rejection and have no identity.", 78), ""]
    for name, fields in positives().items():
        wire = encode(fields)
        identity = digest(binary, "terrane-memo-v1", wire)
        parts.extend([f"### {name}", "", "```text", diagnostic(fields), "```", "",
                      "```text", f"wire = {wire.hex()}", f"memo = {identity.hex()}", "```", ""])
    for name, wire in negatives().items():
        parts.extend([f"### {name}", "", "```text", f"wire = {wire.hex()}",
                      "result = structural rejection", "```", ""])
    return ("\n".join(parts).rstrip() + "\n").encode("utf-8")


def check(reference, expected):
    """Checks the exact bounded UTF-8 section, refusing ambiguous headings."""
    data = Path(reference).read_bytes()
    data.decode("utf-8")
    heading = HEADING.encode("ascii") + b"\n"
    lines = data.splitlines(keepends=True)
    starts = [index for index, line in enumerate(lines) if line == heading]
    if len(starts) != 1:
        raise ValueError("reference must contain exactly one complete section heading")
    start = starts[0]
    end = next((index for index in range(start + 1, len(lines))
                if lines[index].startswith(b"## ")), len(lines))
    # A following section may add one blank framing line without changing the
    # reproduced section. EOF and all other whitespace remain exact.
    if end < len(lines) and lines[end - 1] == b"\n":
        end -= 1
    actual = b"".join(lines[start:end])
    if actual != expected:
        raise ValueError("outer recipe reference section differs byte-for-byte")


def self_check(binary):
    """Checks table independence, unique names and comparator refusal controls."""
    positive = positives()
    negative = negatives()
    if set(positive) & set(negative) or len(positive) != 13 or len(negative) != 62:
        raise ValueError("unexpected outer recipe witness inventory")
    expected = render(binary)
    with tempfile.TemporaryDirectory() as directory:
        reference = Path(directory) / "reference.md"
        for data in [expected, b"## Earlier\n\n" + expected + b"## Later\n",
                     expected + b"\n## Later\n"]:
            reference.write_bytes(data)
            check(reference, expected)
        for data in [b"", expected + expected, expected.replace(b"wire = ", b"wire= ", 1),
                     expected.replace(b"\n", b"\r\n"), expected + b" ",
                     expected + b"\n", expected + b"EOF junk",
                     expected + b"\n\n## Later\n", expected + b" \n## Later\n",
                     expected + b"\r\n## Later\n",
                     expected.replace(b"memo = ", b"memo = 0", 1),
                     expected.replace(b"wire = ", b"## Split section\nwire = ", 1),
                     expected.replace(HEADING.encode(), b"## Outer recipe\n domain and trust field witnesses")]:
            reference.write_bytes(data)
            try:
                check(reference, expected)
            except (ValueError, UnicodeDecodeError):
                continue
            raise ValueError("reference comparator accepted damaged section bytes")
    return len(positive), len(negative)


def main():
    """Runs the independent reproduction or exact reference comparison."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blake3-bin", required=True, type=Path)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--self-check", action="store_true")
    modes.add_argument("--emit", action="store_true")
    modes.add_argument("--check", type=Path)
    arguments = parser.parse_args()
    if arguments.self_check:
        positive, negative = self_check(arguments.blake3_bin)
        print(f"PASS: {positive} positive and {negative} negative outer recipe witnesses")
    elif arguments.emit:
        import sys
        sys.stdout.buffer.write(render(arguments.blake3_bin))
    else:
        check(arguments.check, render(arguments.blake3_bin))
        print("PASS: exact outer recipe reference section")


if __name__ == "__main__":
    main()
