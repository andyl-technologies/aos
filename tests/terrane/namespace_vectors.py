"""Constructs inert entry and root-property witnesses with primitive CBOR.

Only complete nodes receive their registered immutable identity. Embedded
entries, provenance digests, grants and selectors are ordinary field data;
the generator performs no tree operations or authority verification.
"""

import argparse
from copy import deepcopy
from pathlib import Path
import textwrap

from collection_vectors import encode, self_check as check_cbor
from pack_vectors import digest
from retirement_vectors import diagnostic_lines


HEADING = "## Entry and root-property format witnesses"
MIN_CHUNK = 262144
CONTENT = bytes([0x11]) * 32
ROOT = bytes([0x22]) * 32
PROVENANCE = bytes([0x33]) * 32
ATTRS = {"uid": 1000, "custom.fixture": [None, True, b"\x00\xff", {"n": 24}]}
XATTRS = {b"\xff": b"", b"user.fixture": b"\x00\xffvalue"}
GRAFT_PROPS = {
    "domain": {"value": "tenant:fixture", "inherit": False},
    "quota": {"bytes-per-root": 0, "bytes-per-principal-unreferenced": 2**64 - 1},
}


def file_entry(size=0, manifest=False):
    """Constructs all required file fields independently of an entry codec."""
    return {1: 1, 2: 420, 3: size, 4: [int(manifest), CONTENT]}


def metadata(entry, empty=False):
    """Preserves explicit map presence, including distinct empty maps."""
    result = deepcopy(entry)
    result.update({9: {} if empty else ATTRS, 10: {} if empty else XATTRS})
    if not empty:
        result[11] = PROVENANCE
    return result


def entry_models():
    """Covers every kind, common metadata state and conflict-base alternative."""
    inline = file_entry(MIN_CHUNK)
    inline[8] = b"a"
    tree = {1: 4, 6: ROOT}
    conflict = {1: 6, 12: [{1: 2, 2: 493}, {1: 3, 5: b"../raw\xff"}]}
    nested_base = deepcopy(conflict)
    nested_base[13] = None
    models = {
        "entry-file-inline-absent": file_entry(),
        "entry-file-inline-empty": metadata(file_entry(23), True),
        "entry-file-inline-metadata": metadata(inline),
        "entry-file-manifest-metadata": metadata(file_entry(2**64 - 1, True)),
        "entry-directory-absent": {1: 2, 2: 0},
        "entry-directory-empty": metadata({1: 2, 2: 4095}, True),
        "entry-directory-metadata": metadata({1: 2, 2: 493}),
        "entry-symlink-absent": {1: 3, 5: b""},
        "entry-symlink-empty": metadata({1: 3, 5: b"."}, True),
        "entry-symlink-metadata": metadata({1: 3, 5: b"../raw\x00\xff"}),
        "entry-tree-absent": tree,
        "entry-tree-empty": metadata({**tree, 7: {}}, True),
        "entry-tree-metadata": metadata({**tree, 7: GRAFT_PROPS}),
        "entry-whiteout-absent": {1: 5},
        "entry-whiteout-provenance": {1: 5, 11: PROVENANCE},
        "entry-conflict-base-absent": conflict,
        "entry-conflict-base-null": metadata({**conflict, 13: None}, True),
        "entry-conflict-base-entry": metadata({**conflict, 13: metadata(file_entry(24))}),
        "entry-conflict-base-conflict": {**conflict, 13: nested_base},
        "entry-index-absent": {1: 7, 14: [CONTENT]},
        "entry-index-empty": metadata({1: 7, 14: [CONTENT, ROOT]}, True),
        "entry-index-metadata": metadata({1: 7, 14: [CONTENT, ROOT, PROVENANCE]}),
    }
    return models


def usage(entry):
    """Names the local decoding context, without selecting a consumer policy."""
    return {5: "OverlayLayer", 7: "Index"}.get(entry[1], "Ordinary")


def leaf(entry, props=None, include_props=False):
    """Embeds one full entry in a root leaf with an explicit wire key."""
    key = b"\x00/\xff" if entry[1] == 7 else b"a"
    node = {1: 0, 2: [[key, 0, entry]]}
    if include_props:
        node[3] = props
    return node


def root_models():
    """Uses every registered property name and representative nested bindings."""
    registered = {
        "store": "local", "chunk": "cdc-1m", "compression": "zstd:text",
        "encryption": "none", "retain": ["ttl", 2**64 - 1],
        "domain": "group:fixture", "dedup": "domain",
        "redundancy": "replicated(3,ack=2)", "degraded": "refuse",
        "durability": "regions(2)", "replicate": "sync(2)", "home": "r1",
        "warm": ["r2", "r1", "r2"],
        "quota": {"bytes-per-root": 24, "bytes-per-principal-unreferenced": 65536},
        "compaction_threshold": 0, "whole_pack_threshold": 10000,
        "gap_merge_bytes": 0, "span_max_bytes": 2**64 - 1, "trust": "any",
        "baseline": "fixture", "merge": ["prefer-ours", "keep-conflict", "error"],
        "writers": "many", "reflog_retain": ["count", 24], "prefetch": "rules",
        "reassembly": "smart", "passthrough": "auto", "wipe": "volatile",
        "on-release": "commit", "acl": [["fixture:one", 31], ["fixture:two", 0]],
        "hashes": ["sha256", "git-blob-sha256"], "classify": ["text", "elf"],
        "index": ["uid", "hash.sha256"], "strict-attrs": True,
    }
    selector = ["all", [["preset", "any"], ["not", ["kind", "human"]],
                         ["attr-by", "hash.sha256", ["source", "derived"]]]]
    return {
        "root-properties-absent": {1: 0, 2: []},
        "root-properties-empty": {1: 0, 2: [], 3: {}},
        "root-properties-registered": leaf({1: 2, 2: 493}, registered, True),
        "root-properties-bindings": leaf(file_entry(24), {
            "store": {"value": "local", "inherit": False},
            "domain": {"value": "public", "inherit": True},
            "quota": {"value": GRAFT_PROPS["quota"], "inherit": False},
            "acl": {"value": [["fixture:one", 7]], "inherit": True},
            "strict-attrs": {"value": False, "inherit": False},
        }, True),
        "root-properties-selector": leaf({1: 3, 5: b"raw"}, {"trust": selector}, True),
        "root-properties-nested-empty": leaf({1: 4, 6: ROOT, 7: {}}, {
            "warm": [], "hashes": [], "index": [], "classify": [], "acl": [],
        }, True),
    }


def namespace_models():
    """Models only the wire fields of complete ancestors and hard-link sets."""
    child = file_entry(23)
    conflict = entry_models()["entry-conflict-base-absent"]
    first = metadata(file_entry(24))
    first[8] = b"a"
    second = deepcopy(first)
    second[11] = bytes([0x44]) * 32
    return {
        "namespace-directory-descendant": {1: 0, 2: [[b"a", 0, {1: 2, 2: 493}], [b"/b", 1, child]]},
        "namespace-conditional-descendant": {1: 0, 2: [[b"a", 0, conflict], [b"/b", 1, child]]},
        "namespace-hardlink-pair": {1: 0, 2: [[b"a", 0, first], [b"b", 0, second]]},
    }


def negative_models():
    """Constructs invalid fields directly; no rejecting encoder is invoked."""
    entries = {
        "namespace-file-missing-mode": ({1: 1, 3: 0, 4: [0, CONTENT]}, "File mode is required."),
        "namespace-file-reserved-content": ({**file_entry(), 4: [2, CONTENT]}, "Content tag two is unregistered."),
        "namespace-file-inline-too-large": (file_entry(MIN_CHUNK + 1), "An inline file exceeds the minimum chunk size."),
        "namespace-file-manifest-too-small": (file_entry(MIN_CHUNK, True), "A manifest file does not exceed the minimum chunk size."),
        "namespace-file-mode-high": ({**file_entry(), 2: 4096}, "Mode has bits above the low twelve."),
        "namespace-file-short-digest": ({**file_entry(), 4: [0, CONTENT[:-1]]}, "The content digest has only thirty-one bytes."),
        "namespace-file-empty-link": ({**file_entry(), 8: b""}, "A link ID must be a nonempty canonical path."),
        "namespace-directory-content": ({1: 2, 2: 493, 4: [0, CONTENT]}, "Directories exclude file content."),
        "namespace-symlink-mode": ({1: 3, 2: 493, 5: b"a"}, "Symlinks exclude mode."),
        "namespace-tree-null-property": ({1: 4, 6: ROOT, 7: {"domain": None}}, "Property values exclude null."),
        "namespace-whiteout-empty-attrs": ({1: 5, 9: {}}, "Even an empty attribute field is excluded for whiteouts."),
        "namespace-whiteout-empty-xattrs": ({1: 5, 10: {}}, "Even an empty xattr field is excluded for whiteouts."),
        "namespace-conflict-one-candidate": ({1: 6, 12: [{1: 2, 2: 493}]}, "A conflict requires at least two candidates."),
        "namespace-conflict-nested-candidate": ({1: 6, 12: [{1: 6, 12: [{1: 5}, {1: 5}]}, {1: 5}]}, "A direct candidate cannot itself be a conflict."),
        "namespace-conflict-bool-base": ({1: 6, 12: [{1: 5}, {1: 5}], 13: False}, "A present base is null or a complete entry."),
        "namespace-index-empty": ({1: 7, 14: []}, "Index targets are nonempty."),
        "namespace-index-duplicate": ({1: 7, 14: [CONTENT, CONTENT]}, "Index targets are strictly unique."),
        "namespace-index-unsorted": ({1: 7, 14: [ROOT, CONTENT]}, "Index targets are sorted by digest bytes."),
        "namespace-empty-provenance": ({1: 2, 2: 493, 11: b""}, "A present provenance reference requires thirty-two bytes."),
        "namespace-empty-attribute-name": ({1: 2, 2: 493, 9: {"": 1}}, "Attribute names are nonempty."),
        "namespace-empty-xattr-name": ({1: 2, 2: 493, 10: {b"": b"a"}}, "Xattr names are nonempty."),
    }
    for kind in range(8, 16):
        entries[f"namespace-reserved-kind-{kind}"] = ({1: kind}, "The entry kind is reserved.")
    result = {name: (leaf(entry), reason, usage(entry), True, entry)
              for name, (entry, reason) in entries.items()}
    node_cases = {
        "namespace-root-bytes-property": (leaf({1: 2, 2: 493}, {"domain": b"public"}, True), "Property values exclude byte strings.", True),
        "namespace-root-empty-property-name": (leaf({1: 2, 2: 493}, {"": True}, True), "Property names are nonempty.", True),
        "namespace-nonroot-properties": (leaf({1: 2, 2: 493}, {}, True), "Properties are carried only on root nodes.", False),
        "namespace-first-prefix": ({1: 0, 2: [[b"a", 1, {1: 2, 2: 493}]]}, "The first prefix has no prior key to share.", True),
        "namespace-nonmaximal-prefix": ({1: 0, 2: [[b"aa", 0, {1: 2, 2: 493}], [b"ab", 0, {1: 2, 2: 493}]]}, "The second key fails maximal prefix compression.", True),
        "namespace-duplicate-key": ({1: 0, 2: [[b"a", 0, {1: 2, 2: 493}], [b"", 1, {1: 2, 2: 493}]]}, "Leaf keys must be strictly increasing.", True),
        "namespace-extra-item-field": ({1: 0, 2: [[b"a", 0, {1: 2, 2: 493}, 0]]}, "A leaf item has exactly three fields.", True),
        "namespace-whiteout-ordinary": (leaf({1: 5}), "Ordinary trees exclude whiteouts.", True),
        "namespace-index-ordinary": ({1: 0, 2: [[b"a", 0, {1: 7, 14: [CONTENT]}]]}, "Ordinary trees exclude index entries.", True),
    }
    result.update({name: (node, reason, "Ordinary", is_root, None)
                   for name, (node, reason, is_root) in node_cases.items()})
    return result


def self_check():
    """Checks fixed primitive oracles and explicit alternative relationships."""
    check_cbor()
    entries, roots, negatives = entry_models(), root_models(), negative_models()
    assert len(entries) == 22 and len(roots) == 6 and len(negatives) == 38
    assert len(namespace_models()) == 3
    assert encode(entries["entry-whiteout-absent"]).hex() == "a10105"
    assert encode(roots["root-properties-absent"]).hex() == "a201000280"
    assert encode(roots["root-properties-empty"]).hex() == "a30100028003a0"
    assert len(roots["root-properties-registered"][3]) == 33
    assert 13 not in entries["entry-conflict-base-absent"]
    assert entries["entry-conflict-base-null"][13] is None
    assert entries["entry-conflict-base-entry"][13][1] == 1
    assert entries["entry-conflict-base-conflict"][13][1] == 6
    for name, entry in entries.items():
        assert (9 in entry) == (10 in entry), name
        if entry[1] == 1:
            assert (entry[4][0] == 0) == (entry[3] <= MIN_CHUNK), name
        if entry[1] == 7:
            assert entry[14] == sorted(set(entry[14])), name


def block(label, model, wire):
    """Shows the complete diagnostic field model adjacent to its exact bytes."""
    return [label, "", "```text", *diagnostic_lines(model), "```", "",
            "```hex", *textwrap.wrap(wire.hex(), 72), "```", ""]


def render(binary):
    """Emits a separate reference section without modifying published bytes."""
    parts = [HEADING, "", textwrap.fill(
        "Twenty-two complete entry models cover all seven kinds, absent and "
        "explicit empty metadata, opaque nonempty metadata, both file content "
        "tags, link IDs and all conflict-base alternatives. Six root leaf models "
        "cover absent/empty properties, every registered property name, nested "
        "values and inheritance wrappers. "
        "Three further leaf models retain directory/conditional ancestors and "
        "a complete hard-link set. Entries have no immutable identity; "
        "only complete positive nodes receive a terrane-node-v1 identity. "
        "Provenance, selectors, grants and represented root/content references "
        "are inert field data. Thirty-eight independently constructed negative "
        "wires require structural decoder rejection. These witnesses do not "
        "perform tree operations, signing, verification or policy selection.", 78,
        break_on_hyphens=False), ""]
    for name, entry in entry_models().items():
        node = leaf(entry)
        wire = encode(node)
        parts += [f"### {name}", "", f"Positive root leaf; TreeUse::{usage(entry)}.", ""]
        parts += block("Entry:", entry, encode(entry))
        parts += block("Node:", node, wire)
        parts += ["Node identity:", "", "```hex", digest(binary, "terrane-node-v1", wire).hex(), "```", ""]
    for name, node in {**root_models(), **namespace_models()}.items():
        wire = encode(node)
        parts += [f"### {name}", "", "Positive root leaf; TreeUse::Ordinary.", ""]
        parts += block("Node:", node, wire)
        parts += ["Node identity:", "", "```hex", digest(binary, "terrane-node-v1", wire).hex(), "```", ""]
    for name, (node, reason, context, is_root, entry) in negative_models().items():
        parts += [f"### {name}", "", textwrap.fill("Negative vector: " + reason, 78), "",
                  f"Decoder context: TreeUse::{context}; is_root={str(is_root).lower()}.", ""]
        if entry is not None:
            parts += block("Entry:", entry, encode(entry))
        parts += block("Node:", node, encode(node))
    return "\n".join(parts)


def main():
    """Checks or emits the bounded independent reference section."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blake3-bin", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-check", action="store_true")
    mode.add_argument("--emit", action="store_true")
    mode.add_argument("--check", type=Path)
    arguments = parser.parse_args()
    self_check()
    if arguments.self_check:
        print("PASS: fixed CBOR oracles; 22 entry, 6 root-property, 3 namespace and 38 negative models")
        return
    section = render(arguments.blake3_bin)
    if arguments.emit:
        print(section, end="")
        return
    reference = arguments.check.read_text(encoding="utf-8")
    if reference.count(HEADING + "\n") != 1:
        raise SystemExit("expected one entry/root-property reference section")
    existing = reference.split(HEADING + "\n", 1)[1].split("\n## ", 1)[0]
    if (HEADING + "\n" + existing).rstrip() != section.rstrip():
        raise SystemExit("namespace field models, bytes or identities differ")
    print("PASS: independent namespace reference section matches")


if __name__ == "__main__":
    main()
