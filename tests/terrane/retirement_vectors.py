"""Reproduces inert retirement record models from registered CDDL fields.

This generator emits bytes only. Represented nonce, ownership, elapsed and
placement fields are untrusted format data, without backend access, clocks,
selection, signing, verification or effects. The raw hash helper supplies
primitive digests for embedded-record relationships.
"""

import argparse
from copy import deepcopy
from pathlib import Path
import textwrap

from collection_vectors import diagnostic, encode, self_check as check_cbor
from foundation_vectors import raw_digest
from pack_vectors import digest


HEADING = "## Permanent-retirement record format witnesses"
PACK = bytes([0x12]) * 16
NONCE = bytes([0x34]) * 32
LEASE = {1: "A", 2: 2, 3: 100}
EXCLUSION = [PACK, 3, 2]
TOMBSTONE = {1: PACK, 2: 3, 3: 4, 4: 0, 5: 2}

NEGATIVE_REASONS = {
    "retirement-sweep-missing-witness": "The sweep map requires its index witness.",
    "retirement-copy-extra-witness": "The copied alternative excludes the sweep witness key.",
    "retirement-plan-wrong-version": "The copied plan requires its disjoint version two.",
    "retirement-operation-reserved-phase": "The operation has no phase three or terminal Done phase.",
    "retirement-owner-long-pack": "A permanent burn owner requires a 16-byte pack ID.",
    "retirement-pass-reversed-coverage": "Coverage kinds must occur exactly in order 0, 1, 2.",
    "retirement-local-pass-missing-placement": "A local copied pass requires its placement-fence field.",
}


def backend(local):
    """Constructs ordinary local or remote backend-binding fields."""
    if local:
        return [0, b"/a", 1, 2, 3, 4]
    return [1, "s3", ["e", "b", b"", bytes([1]) * 32],
            [b"c", bytes([2]) * 32]]


def pointer(key, byte):
    """Constructs a represented record pointer without resolving its key."""
    return [key, bytes([byte]) * 32]


def operation_key():
    """Returns the fixed schema fixture's canonical relative operation key."""
    return f"gc/3/delete/{PACK.hex()}/{NONCE.hex()}"


def trash_key():
    """Returns the fixed schema fixture's canonical relative trash key."""
    return f"trash/3/{PACK.hex()}"


def authorization(binary, copied, local, lineage=False):
    """Constructs disjoint sweep/copied field maps, without establishing premises."""
    tombstone = encode(TOMBSTONE)
    trash = [trash_key(), raw_digest(binary, tombstone), len(tombstone)]
    if copied:
        barrier = ([trash_key(), bytes([5]) * 32, [2, tombstone], b"\x06"]
                   if local else trash)
        artifacts = [None, None, barrier]
    else:
        pack_key = f"objects/pack/12/{PACK.hex()}"
        witness = b"TRPK" + (1).to_bytes(2, "little") + bytes(2) + PACK
        witness += b"TRIX" + bytes(8)
        artifacts = [
            [pack_key + ".pack", bytes([7]) * 32, 52],
            [pack_key + ".idx", digest(binary, "terrane-index-v1", witness), 36],
            trash,
        ]
    fields = {
        0: 2, 1: NONCE, 2: backend(local), 3: EXCLUSION, 4: LEASE,
        5: 2, 6: artifacts, 8: tombstone, 9: 2000000000,
        10: pointer("gc/3/fence/2", 8), 11: 1, 12: 1000000000, 13: 1,
    }
    if copied:
        fields.update({14: 1, 15: [0, bytes([9]) * 32],
                       16: [1, bytes([10]) * 32]})
        if lineage:
            fields[17] = pointer("gc/3/fence/2", 21)
    else:
        fields[7] = witness
    return fields


def plan(local):
    """Constructs the version-two preparation plan's ordinary ten fields."""
    return {
        0: 2, 1: NONCE, 2: backend(local), 3: EXCLUSION, 4: LEASE,
        5: [0, bytes([9]) * 32], 6: pointer("gc/3/fence/0", 11),
        7: encode(TOMBSTONE), 8: 1, 9: 2,
    }


def state(revision, local, owners, guard=None, loss=1):
    """Constructs an ordinary publication-state model embedded in record bytes."""
    return {0: 1, 1: revision, 2: loss, 3: [], 4: backend(local), 5: [],
            6: guard, 7: owners}


def fence(copied, local):
    """Constructs common/copy fence fields without asserting current placement."""
    capabilities = {
        1: 2, 2: True, 3: True, 4: True, 5: False, 6: 1, 7: 4,
        8: {1: "terrane-v1", 2: "blake3", 3: "cdc-1m", 4: bytes(32)},
        9: 1, 10: [], 11: 1,
    }
    manifest = {1: 1, 2: [], 3: 4, 4: 3, 5: [], 6: [EXCLUSION],
                7: [PACK] if copied else []}
    guard = bytes([17]) * 32
    owners = [[PACK, [0]]] if copied else []
    fields = {
        0: 2 if copied else 1, 1: encode(capabilities), 2: encode(manifest),
        3: [], 4: guard, 5: encode(state(2, local, owners, guard, 0)),
        6: pointer("gc/3/roots", 18), 7: pointer("gc/3/state", 19),
        8: backend(local), 9: [],
    }
    if copied:
        fields[10] = [0, bytes([9]) * 32]
        fields[11] = pointer("publication/snapshots/2:" + "00" * 32, 20)
    return fields


def progress(binary, local, completed, copied=None):
    """Constructs a bounded pass record, including sorted ordinary observations."""
    if copied is None:
        copied = local
    auth_digest = raw_digest(binary, encode(authorization(binary, copied, local)))
    owners = [[PACK, [1, operation_key(), auth_digest]]]
    observations = [[0, [0], 1], [1, [0], 2], [2, 3, [0], 3]]
    if not local:
        observations.insert(1, [0, [1, 0, b"version"], 1])
        observations.insert(2, [0, [1, 1, b"marker"], 2])
    fields = {
        0: 2, 1: auth_digest, 2: [3, bytes([12]) * 32],
        3: 2 if copied else 1, 4: [0, 0], 5: [4, bytes([13]) * 32],
        6: encode(state(4, local, owners)), 7: LEASE, 8: backend(local),
        9: 1 if completed else 0, 10: observations,
        11: [[0, 1], [1, 1], [2, 1]] if completed else [[0, 0], [1, 0], [2, 0]],
        12: bytes([14]) * 32,
    }
    if local:
        fields[13] = pointer("gc/3/fence/4", 15)
    return fields


def models(binary):
    """Constructs all positive and negative wire models from fields alone."""
    witnesses = {"retirement-sweep": authorization(binary, False, False)}
    for local, label in [(False, "remote"), (True, "local")]:
        for lineage in [False, True]:
            suffix = "-lineage" if lineage else ""
            witnesses[f"retirement-copy-{label}{suffix}"] = authorization(
                binary, True, local, lineage,
            )
        witnesses[f"retirement-plan-{label}"] = plan(local)
        for phase, revision, name in [(3, 0, "preparing"), (4, 1, "abandoned")]:
            witnesses[f"retirement-preparation-{label}-{name}"] = [
                2, revision, phase, plan(local),
            ]
        for completed, name in [(False, "open"), (True, "completed")]:
            witnesses[f"retirement-pass-{label}-{name}"] = progress(binary, local, completed)
        witnesses[f"retirement-copied-fence-{label}"] = fence(True, local)
    witnesses["retirement-current-fence"] = fence(False, False)
    selection = [1, operation_key(), bytes([7]) * 32]
    witnesses["retirement-selection-copy"] = [0]
    witnesses["retirement-selection-permanent"] = selection
    witnesses["retirement-owner-copy"] = [PACK, [0]]
    witnesses["retirement-owner-permanent"] = [PACK, selection]
    for phase, revision, name in [(0, 0, "proposed"), (2, 1, "cancelled")]:
        witnesses[f"retirement-operation-{name}"] = [
            2, revision, phase, authorization(binary, False, False), None, None,
        ]
    for copied, local, label in [(False, False, "sweep"), (True, False, "remote"),
                                 (True, True, "local")]:
        revision = 2 if copied else 1
        pass_key = f"gc/3/reconcile/{'0e' * 32}/{revision}"
        pass_digest = raw_digest(binary, encode(progress(binary, local, False, copied)))
        witnesses[f"retirement-operation-owned-{label}"] = [
            2, revision, 1, authorization(binary, copied, local),
            [3, bytes([12]) * 32], [pass_key, pass_digest],
        ]

    negative = deepcopy(witnesses["retirement-sweep"])
    del negative[7]
    witnesses["retirement-sweep-missing-witness"] = negative
    negative = deepcopy(witnesses["retirement-copy-remote"])
    negative[7] = b""
    witnesses["retirement-copy-extra-witness"] = negative
    negative = deepcopy(witnesses["retirement-plan-local"])
    negative[0] = 1
    witnesses["retirement-plan-wrong-version"] = negative
    negative = deepcopy(witnesses["retirement-operation-proposed"])
    negative[2] = 3
    witnesses["retirement-operation-reserved-phase"] = negative
    witnesses["retirement-owner-long-pack"] = [PACK + b"\x00", [0]]
    negative = deepcopy(witnesses["retirement-pass-remote-open"])
    negative[11].reverse()
    witnesses["retirement-pass-reversed-coverage"] = negative
    negative = deepcopy(witnesses["retirement-pass-local-open"])
    del negative[13]
    witnesses["retirement-local-pass-missing-placement"] = negative
    return witnesses


def self_check(binary):
    """Checks primitive fixed bytes and exact embedded-record relationships."""
    check_cbor()
    assert encode(LEASE) == bytes.fromhex("a30161410202031864")
    assert encode(backend(True)) == bytes.fromhex("8600422f6101020304")
    assert encode(TOMBSTONE) == bytes.fromhex(
        "a50150" + "12" * 16 + "0203030404000502"
    )
    witnesses = models(binary)
    assert len(witnesses) == 34 and len(NEGATIVE_REASONS) == 7
    for local, label in [(False, "remote"), (True, "local")]:
        fields = witnesses[f"retirement-copy-{label}"]
        assert 7 not in fields and fields[6][:2] == [None, None]
        assert fields[15][0] == 0 and fields[16][0] == 1
        if not local:
            artifact = fields[6][2]
            assert artifact[1] == raw_digest(binary, fields[8])
            assert artifact[2] == len(fields[8])
        pass_fields = witnesses[f"retirement-pass-{label}-open"]
        auth = witnesses[f"retirement-copy-{label}" if local else "retirement-sweep"]
        assert pass_fields[1] == raw_digest(binary, encode(auth))

    for copied, local, label in [(False, False, "sweep"), (True, False, "remote"),
                                 (True, True, "local")]:
        operation = witnesses[f"retirement-operation-owned-{label}"]
        record = progress(binary, local, False, copied)
        assert operation[1] == record[3]
        assert operation[4] == record[2]
        assert operation[5][1] == raw_digest(binary, encode(record))
        assert record[1] == raw_digest(binary, encode(operation[3]))

    assert diagnostic_lines("a" * 100) == [
        '"' + "a" * 48 + '"',
        '"' + "a" * 48 + '" "aaaa"',
    ]
    print("PASS: fixed CBOR oracles and 34 independent retirement wire models")


def diagnostic_tokens(value):
    """Keeps literal tokens intact and splits long strings by EDN concatenation."""
    # RFC 8610 Appendix G.4 permits adjacent same-kind string literals.
    # Line wrapping inside a quoted text literal would change its value.
    if isinstance(value, str):
        chunks = [value[offset:offset + 48] for offset in range(0, len(value), 48)]
        return [diagnostic(chunk) for chunk in chunks or [""]]
    if isinstance(value, bytes):
        hexadecimal = value.hex()
        chunks = [hexadecimal[offset:offset + 64]
                  for offset in range(0, len(hexadecimal), 64)]
        return [f"h'{chunk}'" for chunk in chunks or [""]]
    if isinstance(value, list):
        tokens = ["["]
        for index, item in enumerate(value):
            if index:
                tokens.append(",")
            tokens.extend(diagnostic_tokens(item))
        return tokens + ["]"]
    if isinstance(value, dict):
        tokens = ["{"]
        for index, (key, item) in enumerate(sorted(value.items())):
            if index:
                tokens.append(",")
            tokens.extend(diagnostic_tokens(key))
            tokens.append(":")
            tokens.extend(diagnostic_tokens(item))
        return tokens + ["}"]
    return [diagnostic(value)]


def diagnostic_lines(value):
    """Wraps diagnostic tokens at 78 columns without splitting any literal."""
    lines = []
    line = ""
    for token in diagnostic_tokens(value):
        if len(token) > 78:
            raise ValueError("diagnostic literal exceeds the line width")
        if line and len(line) + len(token) + 1 > 78:
            lines.append(line)
            line = token
        else:
            line += (" " if line else "") + token
    if line:
        lines.append(line)
    return lines


def render(binary):
    """Renders complete diagnostic fields and wire bytes, without authority claims."""
    parts = [HEADING, "", textwrap.fill(
        "These TEST-2 witnesses transcribe the disjoint D-82 schemas. They "
        "represent ordinary field models for authorizations, preparations, "
        "operations, fences, ownership selectors and progress records. "
        "Digest and embedded-value relationships are computed from independent "
        "CBOR and the raw hash primitive. No represented nonce, ownership, "
        "current placement or elapsed bound establishes physical permission. "
        "The seven negative wires isolate structural decoder refusals.", 78), ""]
    for name, model in models(binary).items():
        description = ("Negative vector: " + NEGATIVE_REASONS[name]
                       if name in NEGATIVE_REASONS else "Positive format vector.")
        parts += [f"### {name}", "", textwrap.fill(description, 78), "", "```text",
                  *diagnostic_lines(model), "```", "", "```hex",
                  *textwrap.wrap(encode(model).hex(), 72), "```", ""]
    return "\n".join(parts)


def main():
    """Emits or checks a bounded section without editing normative inputs."""
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
    reference = arguments.check.read_text(encoding="utf-8")
    if reference.count(HEADING + "\n") != 1:
        raise SystemExit("expected one permanent-retirement reference section")
    existing = reference.split(HEADING + "\n", 1)[1].split("\n## ", 1)[0]
    if (HEADING + "\n" + existing).rstrip() != section.rstrip():
        raise SystemExit("retirement models or bytes differ")
    print("PASS: independent retirement reference section matches")


if __name__ == "__main__":
    main()
