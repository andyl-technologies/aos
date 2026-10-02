"""Reproduces D-79 format witnesses without importing implementation codecs.

The models below transcribe the registered CDDL. The encoder implements only
the canonical CBOR primitives they need. No hash, signature, filesystem or
publication authority is inferred from these represented record fields.
"""

import argparse
from pathlib import Path
import textwrap


HEADING = "## D-79 publication and original-control format witnesses"

BEHAVIOR_NAMES = [
    "acl",
    "baseline",
    "chunk",
    "classify",
    "compaction_threshold",
    "compression",
    "dedup",
    "degraded",
    "domain",
    "durability",
    "encryption",
    "gap_merge_bytes",
    "hashes",
    "home",
    "index",
    "merge",
    "on-release",
    "passthrough",
    "prefetch",
    "quota",
    "reassembly",
    "redundancy",
    "reflog_retain",
    "replicate",
    "retain",
    "span_max_bytes",
    "store",
    "strict-attrs",
    "trust",
    "warm",
    "whole_pack_threshold",
    "wipe",
    "writers",
]


def head(major, value):
    """Encodes an unsigned argument with its shortest CBOR head."""
    if value < 0:
        raise ValueError("negative integers are outside these witnesses")
    if value < 24:
        return bytes([(major << 5) | value])
    for size, additional in [(1, 24), (2, 25), (4, 26), (8, 27)]:
        if value < 1 << (8 * size):
            return bytes([(major << 5) | additional]) + value.to_bytes(size, "big")
    raise ValueError("integer exceeds uint64")


def encode(value):
    """Encodes the CDDL models independently in deterministic CBOR."""
    if value is None:
        return b"\xf6"
    if type(value) is int:
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode("utf-8")
        return head(3, len(data)) + data
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(encode(item) for item in value)
    if isinstance(value, dict):
        fields = [(encode(key), encode(item)) for key, item in value.items()]
        fields.sort(key=lambda field: (len(field[0]), field[0]))
        return head(5, len(fields)) + b"".join(key + item for key, item in fields)
    raise TypeError(f"unsupported witness value: {type(value).__name__}")


def diagnostic(value):
    """Renders every model field in CBOR diagnostic notation."""
    if value is None:
        return "null"
    if type(value) is int:
        return str(value)
    if isinstance(value, bytes):
        return f"h'{value.hex()}'"
    if isinstance(value, str):
        # All witness strings are ASCII and contain no quote or escape.
        if not value.isascii() or '"' in value or "\\" in value:
            raise ValueError("string requires diagnostic escaping")
        return f'"{value}"'
    if isinstance(value, list):
        return "[" + ", ".join(diagnostic(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(
            f"{diagnostic(key)}: {diagnostic(item)}"
            for key, item in value.items()
        ) + "}"
    raise TypeError("unsupported diagnostic value")


def models():
    """Constructs named schema inputs without parsing encoded fixtures."""
    local = [1, bytes([1]) * 32, b"/r", "public", 1, 2, 3, 4, b"/c"]
    acl = [["p", 1], ["p", 2]]
    bootstrap = [1, bytes([1]) * 32, "refs/heads/_/main", 3, acl]
    association = [1, bytes([2]) * 32, bytes([1]) * 32, "refs/heads/_/main", 3]
    profile = [262144, 1048576, 4194304, 48, 2, bytes([7]) * 32]
    config = {
        0: 1,
        1: "s",
        2: "hint",
        3: {1: "r", 3: "h"},
        4: acl,
        5: 262144,
        6: "public",
        7: "cdc-1m",
        8: profile,
        9: None,
    }
    registry = {
        0: 1,
        1: 1,
        2: BEHAVIOR_NAMES,
        3: 1,
        4: 1,
        5: 1,
        6: 1,
        7: "terrane-v1",
        8: [],
    }
    root = [bytes([8]) * 32, b"/", [[encode({}), encode({})]]]
    binding = [0, b"/a", 1, 2, 3, 4]
    remote = [
        1,
        "s3",
        ["e", "b", b"", bytes([1]) * 32],
        [b"k", bytes([2]) * 32],
    ]
    remote_original = [
        2,
        bytes([1]) * 32,
        "public",
        [
            1,
            "s3",
            ["e", "b", b"", bytes([3]) * 32],
            [b"k", bytes([4]) * 32],
        ],
        b"c",
    ]
    return [
        ("d79-local-original", "local-original-registration", local),
        ("d79-bootstrap", "OriginalBootstrap", bootstrap),
        ("d79-association", "OriginalAssociation", association),
        ("d79-local-import", "OriginalImport", [1, local, bootstrap, association]),
        ("d79-issuer-row", "issuer-row", ["i", "k", bytes([5]) * 32, None]),
        (
            "d79-disclosure-row",
            "disclosure-row",
            ["01" * 32, "public", bytes([6]) * 32, 1, 2],
        ),
        ("d79-seeded-profile", "seeded-chunk-profile", profile),
        ("d79-guard-config", "trusted-guard-config", config),
        ("d79-registries", "configured-registry-inputs", registry),
        (
            "d79-guard-snapshot",
            "GuardSnapshot",
            {0: 1, 1: local, 2: [], 3: [], 4: config, 5: registry},
        ),
        ("d79-root-policy", "consumed-root-policy", root),
        ("d79-view-policy", "consumed-view-policy", [bytes([9]) * 32, "public", [root]]),
        ("d79-remote-original", "physical-registration", remote_original),
        ("d79-remote-import", "OriginalImport", [2, remote_original, bootstrap, association]),
        ("d79-local-binding", "backend-binding", binding),
        ("d79-remote-binding", "backend-binding", remote),
        (
            "d79-registration-pending",
            "BackendRegistration",
            {0: 1, 1: binding, 2: 0, 3: None},
        ),
        (
            "d79-registration-active",
            "BackendRegistration",
            {0: 1, 1: binding, 2: 1, 3: bytes([5]) * 32},
        ),
        ("d79-selection-never", "committed-selection", [0]),
        ("d79-selection-unknown", "committed-selection", [2]),
        ("d79-empty-history", "SelectedHistory", {0: 1, 1: [], 2: binding}),
    ]


def section():
    """Reproduces the complete additive reference section."""
    parts = [
        HEADING,
        "",
        "D-84 publishes these positive byte witnesses for the registered D-79",
        "CDDL. They describe represented format inputs only: decoded controls,",
        "bindings and policy rows do not establish native ownership, selected",
        "history, current authorization or a source-preservation fence. Every",
        "record here is non-content-addressed and has no immutable descriptor",
        "or domain-separated identity. Repeated ACL entries preserve order;",
        "the seeded profile intentionally uses a nonzero seed.",
        "",
        "Each named witness supplies its complete diagnostic input and exact",
        "canonical encoding. Compound inputs repeat their full nested records.",
        "All key, digest and registration values are public fixture data.",
        "Import bindings/trust, consumed pins/lineage and the remaining selected",
        "publication and collection formats require additional byte witnesses;",
        "these examples do not establish complete TEST-2 coverage.",
    ]
    for name, schema, model in models():
        data = encode(model)
        parts += ["", f"### {name}", "", f"Schema: `{schema}`.", "", "```text"]
        parts += textwrap.wrap(
            diagnostic(model),
            width=78,
            break_long_words=False,
            break_on_hyphens=False,
        )
        parts += ["```", "", f"Canonical CBOR ({len(data)} bytes):", "", "```hex"]
        parts += textwrap.wrap(data.hex(), width=64)
        parts += ["```"]
    return "\n".join(parts) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", type=Path, help="compare the published section")
    parser.add_argument("--insert", type=Path, help="insert once before Reproduction")
    args = parser.parse_args()
    if args.check and args.insert:
        parser.error("select either --check or --insert")

    generated = section()
    if args.check:
        document = args.check.read_text(encoding="utf-8")
        start = document.index(HEADING + "\n")
        end = document.index("\n## Reproduction\n", start)
        if document[start:end] != generated:
            raise SystemExit("published D-79 vectors differ from reference inputs")
        print(f"PASS: {len(models())} independent D-79 format witnesses")
    elif args.insert:
        document = args.insert.read_text(encoding="utf-8")
        if HEADING in document:
            raise SystemExit("D-79 section already exists; refuse duplicate insertion")
        marker = "## Reproduction\n"
        if document.count(marker) != 1:
            raise SystemExit("expected exactly one Reproduction heading")
        args.insert.write_text(
            document.replace(marker, generated + "\n" + marker),
            encoding="utf-8",
        )
    else:
        print(generated, end="")


if __name__ == "__main__":
    main()
