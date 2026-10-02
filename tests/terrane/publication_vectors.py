"""Reproduces D-79 format witnesses without importing implementation codecs.

The models below transcribe the registered CDDL. The encoder implements only
the canonical CBOR primitives they need. No hash, signature, filesystem or
publication authority is inferred from these represented record fields.
"""

import argparse
from pathlib import Path
import subprocess
import textwrap


HEADING = "## D-79 publication and original-control format witnesses"

NEGATIVE_REASONS = {
    "d79-full-snapshot-missing-inventory": (
        "Negative vector: a full checkpoint omits the mandatory CAPABILITIES "
        "and lease rows. Its format decoder rejects these exact bytes."
    ),
    "d79-genesis-transaction-missing-inventory": (
        "Negative vector: genesis omits the mandatory initial CAPABILITIES, "
        "lease and selected-history changes. Its format decoder rejects "
        "these exact bytes."
    ),
}

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


def models(raw_digest):
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
    original_import = [1, local, bootstrap, association]
    import_digest = raw_digest(encode(original_import))
    import_binding = [
        1,
        bytes([2]) * 32,
        bytes([1]) * 32,
        bytes([9]) * 32,
        import_digest,
    ]
    issuer = ["i", "k", bytes([5]) * 32, None]
    disclosure = ["01" * 32, "public", bytes([6]) * 32, 1, 2]
    guard = {0: 1, 1: local, 2: [], 3: [], 4: config, 5: registry}
    pin = [0, local, "registration.cbor", raw_digest(encode(local))]
    used = {0: 1, 1: [], 2: [], 3: [pin], 4: registry, 5: config, 6: []}

    # The exact signed legacy Commit is the earlier reference input. Its
    # absent modern context and deliberately incomplete controls demonstrate
    # only structural lineage encoding, never a qualified native source.
    legacy_commit = bytes.fromhex(
        "a70158209366ec79c4c37d11877e5767bab653177f4e80be8ed6aeb0cdcf4c3c"
        "20bbc392028003a8016e6973737565722e6578616d706c650250010203040506"
        "0708090a0b0c0d0e0f10036663692d6a6f620402067274657272616e652d636c"
        "692f636f6d6d6974071a68e7780008010901041a68e778000567696e69746961"
        "6c06a2010102666364632d316d0858400b1b8d248ff55846868046c342ee3ae5"
        "ca049862cec1c4c8ad9207f6fab19e73a6f5013337b587370634e366d70998ed"
        "715d1105f7ba505f6f519bd967dd710d"
    )
    legacy_identity = bytes.fromhex(
        "c8efdd180de6c5b1e04abe4435238e8969776497759682c6094a4cede9c579d6"
    )
    legacy_ref = {1: legacy_identity, 2: 1, 3: 1, 4: {1: "eu-west-1"}}
    lineage = {
        0: 1,
        1: "refs/tags/_/alias",
        2: encode(legacy_ref),
        3: legacy_identity,
        4: legacy_commit,
        5: raw_digest(encode(guard)),
        6: 0,
        7: [pin],
        8: local,
        9: used,
    }

    state = {0: 1, 1: 0, 2: 0, 3: [], 4: binding, 5: [], 6: None}
    next_state = {**state, 1: 1}
    pointer = ["publication/snapshots/0:" + "00" * 32, bytes([7]) * 32]
    next_pointer = ["publication/snapshots/1:" + "00" * 32, bytes([7]) * 32]
    history = {0: 1, 1: [], 2: binding}
    full_snapshot = {
        0: 1,
        1: 0,
        2: binding,
        3: [["publication/SELECTED-HISTORY", encode(history)]],
        4: None,
    }
    transaction = {
        0: 1,
        1: bytes(32),
        2: encode(state),
        3: encode(next_state),
        4: [],
        5: [0],
        6: [0, bytes([3]) * 32],
        7: next_pointer,
    }
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
        (
            "d79-remote-import",
            "OriginalImport",
            [2, remote_original, bootstrap, association],
        ),
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
        ("d79-import-binding", "OriginalImportBinding", import_binding),
        (
            "d79-import-trust",
            "OriginalImportTrust",
            [
                1,
                import_digest,
                bytes([1]) * 32,
                bytes([9]) * 32,
                [issuer],
                [disclosure],
            ],
        ),
        ("d79-registration-pin", "required-control-pin", pin),
        ("d79-used-inputs-claim", "lineage-used-inputs", used),
        ("d79-legacy-lineage-claim", "CheckedLineage", lineage),
        ("d79-selection-whole", "committed-selection", [1, legacy_ref]),
        ("d79-empty-state", "PublicationState", state),
        (
            "d79-publication-current",
            "PublicationCurrent",
            {0: 1, 1: 0, 2: bytes([6]) * 32},
        ),
        (
            "d79-portable-current",
            "PortableCurrent",
            {0: 1, 1: pointer[0], 2: pointer[1]},
        ),
        (
            "d79-genesis-commit",
            "PublicationCommit",
            {
                0: 1,
                1: 0,
                2: None,
                3: "publication/transactions/" + "00" * 32,
                4: bytes([1]) * 32,
            },
        ),
        ("d79-proof-raw", "publication-proof", [0]),
        ("d79-proof-candidate", "publication-proof", [1, bytes([3]) * 32]),
        ("d79-proof-guard", "publication-proof", [4, bytes([3]) * 32]),
        (
            "d79-proof-collection-claim",
            "publication-proof",
            [2, "gc/0/fence/0", bytes([4]) * 32, [], []],
        ),
        ("d79-full-snapshot-missing-inventory", "PortableSnapshot", full_snapshot),
        (
            "d79-delta-snapshot",
            "PortableSnapshot",
            {0: 1, 1: 1, 2: binding, 3: [], 4: pointer},
        ),
        ("d79-next-transaction", "PublicationTransaction", transaction),
        (
            "d79-genesis-transaction-missing-inventory",
            "PublicationTransaction",
            {**transaction, 2: None, 3: encode(state), 6: None, 7: pointer},
        ),
    ]


def section(witnesses):
    """Reproduces the complete additive reference section."""
    parts = [
        HEADING,
        "",
        "D-84 publishes these byte witnesses for the registered D-79",
        "CDDL. They describe represented format inputs only: decoded controls,",
        "bindings and policy rows do not establish native ownership, selected",
        "history, current authorization or a source-preservation fence. Every",
        "record here is non-content-addressed and has no immutable descriptor",
        "or domain-separated identity. Repeated ACL entries preserve order;",
        "the seeded profile intentionally uses a nonzero seed.",
        "",
        "Explicitly negative witnesses require format-decoder rejection.",
        "Each named witness supplies its complete diagnostic input and exact",
        "canonical encoding. Compound inputs repeat their full nested records.",
        "All key, digest and registration values are public fixture data.",
        "Raw digest fields use BLAKE3 over the exact represented canonical bytes.",
        "The legacy-lineage and collection-proof examples are structural claims",
        "with incomplete authority evidence; they cannot qualify a native fork",
        "or collection. The remaining current-collection and retirement formats",
        "need their own witnesses before complete TEST-2 coverage is claimed.",
    ]
    for name, schema, model in witnesses:
        data = encode(model)
        parts += ["", f"### {name}", "", f"Schema: `{schema}`."]
        if name in NEGATIVE_REASONS:
            parts += [""] + textwrap.wrap(NEGATIVE_REASONS[name], width=78)
        parts += ["", "```text"]
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
    parser.add_argument("--replace", type=Path, help="replace only this generated section")
    parser.add_argument(
        "--blake3-bin",
        type=Path,
        required=True,
        help="path to the source-built reference_blake3 example",
    )
    args = parser.parse_args()
    if sum(option is not None for option in (args.check, args.insert, args.replace)) > 1:
        parser.error("select only one of --check, --insert or --replace")

    def raw_digest(data):
        result = subprocess.run(
            [str(args.blake3_bin)],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        hex_digest = result.stdout.decode("ascii").strip()
        if len(hex_digest) != 64 or any(
            digit not in "0123456789abcdef" for digit in hex_digest
        ):
            raise ValueError("reference hash tool returned malformed digest")
        return bytes.fromhex(hex_digest)

    witnesses = models(raw_digest)
    generated = section(witnesses)
    if args.check:
        document = args.check.read_text(encoding="utf-8")
        start = document.index(HEADING + "\n")
        end = document.index("\n## Reproduction\n", start)
        if document[start:end] != generated:
            raise SystemExit("published D-79 vectors differ from reference inputs")
        print(f"PASS: {len(witnesses)} independent D-79 format witnesses")
    elif args.replace:
        document = args.replace.read_text(encoding="utf-8")
        start = document.index(HEADING + "\n")
        end = document.index("\n## Reproduction\n", start)
        args.replace.write_text(
            document[:start] + generated + document[end:],
            encoding="utf-8",
        )
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
