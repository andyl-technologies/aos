"""Constructs descriptor and internal-node witnesses from independent models.

CBOR and container fields use primitive reference writers. BLAKE3 is supplied
by the source-built raw primitive helper. Deferred filter and memo payloads are
CDDL models for descriptor coverage; this tool implements neither feature.
"""

import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import textwrap

from collection_vectors import diagnostic, encode, self_check as check_cbor
from pack_vectors import digest, witnesses as pack_witnesses


HEADING = "## Immutable descriptors and internal-node witnesses"
DOMAINS = [
    ("chunk", "terrane-chunk-v1"),
    ("manifest", "terrane-manifest-v1"),
    ("node", "terrane-node-v1"),
    ("commit", "terrane-commit-v1"),
    ("bundle", "terrane-bundle-v1"),
    ("pack", "terrane-pack-v1"),
    ("index", "terrane-index-v1"),
    ("filter", "terrane-filter-v1"),
    ("attr", "terrane-attr-v1"),
    ("policy", "terrane-policy-v1"),
    ("memo", "terrane-memo-v1"),
]

COMMIT_SIGNATURE = bytes.fromhex(
    "0b1b8d248ff55846868046c342ee3ae5ca049862cec1c4c8ad9207f6fab19e73"
    "a6f5013337b587370634e366d70998ed715d1105f7ba505f6f519bd967dd710d"
)
AUTHORITY_SIGNATURE = bytes.fromhex(
    "7239961b2b42911f2f2ad53e5b8715d82f18ba850cad724863832e43d45bbd4c"
    "cffd924ffa1189b7695a7d6c610fb766ff7ea30a26cd69924f9f140edac5f609"
)
ATTENUATION_SIGNATURE = bytes.fromhex(
    "3fda3b61fb042cf3fe81e027fb7968fef6f8e40fb59e7ccb98117c97392ba0bbd"
    "5aa8e92a5faf958af1cb6f61f739b5c6cec2e194e644058ea2d4f8989ac700c"
)
NEXT_KEY = bytes.fromhex(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
)


def models(binary):
    """Transcribes complete CDDL inputs without reading published wire fixtures."""
    payloads = {"chunk": b"hello, terrane\n"}
    chunk_hash = digest(binary, "terrane-chunk-v1", payloads["chunk"])
    entry = {1: 1, 2: 420, 3: 15, 4: [0, chunk_hash]}
    hello = {1: 0, 2: [[b"hello.txt", 0, entry]]}
    world = {1: 0, 2: [[b"world.txt", 0, entry]]}
    hello_wire, world_wire = encode(hello), encode(world)
    hello_hash = digest(binary, "terrane-node-v1", hello_wire)
    world_hash = digest(binary, "terrane-node-v1", world_wire)
    internal = {1: 1, 2: [
        [b"hello.txt", hello_hash, 1, len(hello_wire)],
        [b"world.txt", world_hash, 1, len(world_wire)],
    ]}
    payloads["node"] = encode(internal)

    plaintext = bytes(index % 251 for index in range(300000))
    chunks = [plaintext[:262144], plaintext[262144:]]
    manifest = {
        1: len(plaintext),
        2: [[digest(binary, "terrane-chunk-v1", chunk), len(chunk)]
            for chunk in chunks],
        3: {"blake3": raw_digest(binary, plaintext),
            "sha256": hashlib.sha256(plaintext).digest()},
    }
    payloads["manifest"] = encode(manifest)

    commit = {
        1: hello_hash, 2: [],
        3: {1: "issuer.example", 2: bytes(range(1, 17)), 3: "ci-job", 4: 2,
            6: "terrane-cli/commit", 7: 1760000000, 8: 1, 9: 1},
        4: 1760000000, 5: "initial", 6: {1: 1, 2: "cdc-1m"},
        8: COMMIT_SIGNATURE,
    }
    payloads["commit"] = encode(commit)
    commit_hash = digest(binary, "terrane-commit-v1", payloads["commit"])
    payloads["bundle"] = encode({1: commit_hash, 2: [[2, hello_hash, hello_wire]]})
    _, _, _, packs = pack_witnesses(binary)
    payloads["pack"] = packs["pack-two-entry"]
    payloads["index"] = packs["pack-detached-index"]
    payloads["filter"] = encode({1: 1, 2: 9, 3: 1, 4: 0, 5: 8, 6: b""})
    manifest_hash = digest(binary, "terrane-manifest-v1", payloads["manifest"])
    payloads["attr"] = encode({
        1: manifest_hash, 2: "hash.sha256", 3: manifest[3]["sha256"],
        4: "sha256/1", 5: commit_hash,
    })
    token = [
        {1: "issuer.example", 2: "k1", 3: "ci-job", 4: 2, 5: ["builders"],
         6: 1760003600, 8: bytes(range(1, 17)),
         9: [["refs/heads/pr/**", 7]], 11: NEXT_KEY, 12: AUTHORITY_SIGNATURE},
        {4: [["ref", "refs/heads/pr/1234"], ["epoch", "refs/heads/pr/1234", 1]],
         5: NEXT_KEY, 6: ATTENUATION_SIGNATURE},
    ]
    payloads["policy"] = encode(token)
    empty_root = digest(binary, "terrane-node-v1", encode({1: 0, 2: []}))
    recipe_hash = digest(binary, "terrane-memo-v1", encode({1: "overlay", 2: []}))
    payloads["memo"] = encode({1: recipe_hash, 2: empty_root})

    descriptors = {
        f"descriptor-{kind}": ["blake3", domain,
                               digest(binary, domain, payloads[kind]),
                               len(payloads[kind])]
        for kind, domain in DOMAINS
    }
    nodes = {"foundation-leaf-hello": hello, "foundation-leaf-world": world,
             "foundation-internal-node": internal}
    return payloads, descriptors, nodes


def raw_digest(binary, payload):
    """Invokes only the existing primitive helper's bounded raw hash protocol."""
    result = subprocess.run([str(binary)], input=payload, stdout=subprocess.PIPE,
                            check=True).stdout.decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", result):
        raise ValueError("raw BLAKE3 helper must return one lowercase digest")
    return bytes.fromhex(result)


def self_check(binary):
    """Checks primitive and preserved legacy identities before reference emission."""
    check_cbor()
    assert raw_digest(binary, b"").hex() == (
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    )
    payloads, descriptors, nodes = models(binary)
    preserved = {
        "chunk": "9479e1e57491078eb09f9decc2c56c63110c372de01557d73560dbc2ba9f3ba0",
        "manifest": "012fb6dded774e62a96a38b832da9f2f8f7eb5caa5dddefd2b405a4602b53e0c",
        "commit": "c8efdd180de6c5b1e04abe4435238e8969776497759682c6094a4cede9c579d6",
        "attr": "d66a8b356e79357277b5ef355d78ec061591ce79a13a3ea68675251a454bf592",
    }
    for kind, expected in preserved.items():
        assert descriptors[f"descriptor-{kind}"][2].hex() == expected, kind
    assert digest(binary, "terrane-node-v1", encode(nodes["foundation-leaf-hello"])).hex() == (
        "9366ec79c4c37d11877e5767bab653177f4e80be8ed6aeb0cdcf4c3c20bbc392"
    )
    assert len(descriptors) == 11 and len(nodes) == 3
    for kind, _ in DOMAINS:
        assert descriptors[f"descriptor-{kind}"][3] == len(payloads[kind])
    print("PASS: raw hash oracle, five preserved identities and 14 independent models")


def render(binary):
    """Renders complete descriptor payloads and node models for independent checking."""
    payloads, descriptors, nodes = models(binary)
    parts = [HEADING, "", textwrap.fill(
        "These TEST-2 witnesses cover all eleven registered immutable descriptor "
        "domains and a level-one internal node with two real leaf models. "
        "Each child count is one; its weight is the complete leaf's encoded "
        "size. Descriptor payloads are reproduced independently from CDDL and "
        "the pack field tables. Deferred filter and memo payloads are ordinary "
        "schema models: descriptor checks do not qualify those features. "
        "Legacy signatures retain their byte-format role and establish no "
        "current authorization or verified history.", 78), ""]
    for kind, _ in DOMAINS:
        name = f"descriptor-{kind}"
        parts += [f"### {name}", "", "```text",
                  *textwrap.wrap(diagnostic(descriptors[name]), 78), "```", "",
                  "Descriptor bytes:", "", "```hex",
                  *textwrap.wrap(encode(descriptors[name]).hex(), 72), "```", "",
                  "Complete immutable payload bytes:", "", "```hex",
                  *textwrap.wrap(payloads[kind].hex(), 72), "```", ""]
    for name, model in nodes.items():
        wire = encode(model)
        parts += [f"### {name}", "", "```text",
                  *textwrap.wrap(diagnostic(model), 78), "```", "", "```hex",
                  *textwrap.wrap(wire.hex(), 72), "```", "", "Node identity:", "",
                  "```text", digest(binary, "terrane-node-v1", wire).hex(), "```", ""]
    return "\n".join(parts)


def main():
    """Emits or checks this reference section without editing normative inputs."""
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
        raise SystemExit("expected one descriptor and internal-node section")
    existing = reference.split(HEADING + "\n", 1)[1].split("\n## ", 1)[0]
    if (HEADING + "\n" + existing).rstrip() != section.rstrip():
        raise SystemExit("descriptor or internal-node models/bytes differ")
    print("PASS: independent descriptor and internal-node reference matches")


if __name__ == "__main__":
    main()
