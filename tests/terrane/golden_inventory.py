"""Assigns every published golden section to its mandatory owning consumers.

This inventory detects unassigned additions and omitted witnesses. Owning
codec suites independently compare the actual bytes, identities and models.
"""

import argparse
from pathlib import Path
import re


# Counts are (hex blocks, named wire fields, named witness subsections).
# Changes require review alongside the corresponding owning codec consumers.
SECTIONS = {
    "Test keys": ((0, 0, 0), ()),
    "Gear table": ((0, 0, 0), ("prefix",)),
    "Chunk identities": ((0, 0, 0), ("prefix",)),
    "Descriptor": ((1, 0, 0), ("prefix",)),
    "Leaf node with one inline file": ((2, 0, 0), ("prefix",)),
    "Node boundaries": ((0, 0, 0), ("prefix",)),
    "Manifest (encoding vector)": ((1, 0, 0), ("legacy",)),
    "Commit": ((2, 0, 0), ("legacy",)),
    "Ref record and reflog record": ((2, 0, 0), ("legacy",)),
    "Attribute record": ((1, 0, 0), ("legacy",)),
    "Capability token": ((3, 0, 0), ("legacy", "prefix")),
    "Layout and physical-intent record vectors": ((21, 0, 21), ("legacy",)),
    "D-79 publication and original-control format witnesses":
        ((39, 0, 39), ("publication",)),
    "Two-entry pack and detached index": ((4, 0, 4), ("pack",)),
    "Collection-record format witnesses": ((20, 0, 20), ("collection",)),
    "Immutable descriptors and internal-node witnesses":
        ((26, 0, 15), ("foundation",)),
    "Canonical composition recipe witnesses": ((29, 0, 17), ("algebra",)),
    "Entry and root-property format witnesses": ((151, 0, 69), ("namespace",)),
    "Derived-attribute field model witnesses": ((194, 0, 110), ("attribute",)),
    "Reproduction": ((0, 0, 0), ()),
    "Chunk-envelope and merged-shard field witnesses":
        ((131, 0, 85), ("container",)),
    "Permanent-retirement record format witnesses":
        ((34, 0, 34), ("retirement",)),
    "Selector and private evidence field witnesses": ((86, 0, 86), ("evidence",)),
    "Modern commit and ref record field witnesses": ((0, 147, 147), ("refs",)),
    "Local reconciliation record field witnesses":
        ((0, 91, 91), ("reconciliation",)),
    "Publication and original-control alternative witnesses":
        ((126, 0, 126), ("control",)),
    "Consumed-lineage record field witnesses": ((0, 191, 191), ("lineage",)),
    "Outer recipe domain and trust field witnesses":
        ((0, 75, 75), ("recipe-context",)),
    "Owner-bound index and occurrence-carrier field witnesses":
        ((0, 176, 176), ("index",)),
    "Recorded property trust context field witnesses":
        ((0, 113, 113), ("recorded-context",)),
}

# These two sections contain only fixture metadata and reproduction instructions.
METADATA = {"Test keys", "Reproduction"}


def validate(document, consumers):
    """Rejects missing, duplicate, unassigned or changed witness inventories."""
    chunks = re.split(r"^## ", document, flags=re.MULTILINE)
    if not chunks[0].startswith("# Reference: golden vectors\n"):
        raise ValueError("missing golden reference title")
    observed = set()
    for chunk in chunks[1:]:
        name, body = chunk.split("\n", 1)
        if name in observed or name not in SECTIONS:
            raise ValueError(f"duplicate or unassigned golden section: {name}")
        observed.add(name)
        counts, owners = SECTIONS[name]
        actual = (len(re.findall(r"^```hex$", body, re.MULTILINE)),
                  len(re.findall(r"^wire = ", body, re.MULTILINE)),
                  len(re.findall(r"^### ", body, re.MULTILINE)))
        if actual != counts:
            raise ValueError(f"reviewed witness inventory differs: {name}")
        names = re.findall(r"^### (.+)$", body, re.MULTILINE)
        if len(names) != len(set(names)):
            raise ValueError(f"duplicate witness names: {name}")
        if not owners and name not in METADATA:
            raise ValueError(f"golden section has no owning consumer: {name}")
        if not set(owners).issubset(consumers):
            raise ValueError(f"owning consumer is absent from gate dependencies: {name}")
    if observed != set(SECTIONS):
        raise ValueError("missing reviewed golden sections")


def self_check(document, consumers):
    """Checks omission, duplication, unassigned additions and count changes."""
    validate(document, consumers)
    invalid = [
        document.replace("## Descriptor\n", "## Unassigned descriptor\n", 1),
        document + "\n## Descriptor\n",
        document + "\n## Unassigned format\n```hex\n00\n```\n",
        document.replace("## Descriptor\n", "## Descriptor\n```hex\n00\n```\n", 1),
        document.replace("## Chunk identities\n", "# Chunk identities\n", 1),
    ]
    for candidate in invalid:
        try:
            validate(candidate, consumers)
        except ValueError:
            continue
        raise ValueError("inventory accepted an unreviewed or omitted witness")
    try:
        validate(document, consumers - {"prefix"})
    except ValueError:
        return
    raise ValueError("inventory accepted a missing owning consumer dependency")


def main():
    """Checks the exact published reference against mandatory consumer names."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", type=Path)
    parser.add_argument("consumers", nargs="+")
    arguments = parser.parse_args()
    document = arguments.reference.read_bytes().decode("utf-8")
    consumers = set(arguments.consumers)
    if len(consumers) != len(arguments.consumers):
        parser.error("consumer names must be unique")
    self_check(document, consumers)
    print(f"PASS: {len(SECTIONS)} reviewed golden sections have required owning consumers")


if __name__ == "__main__":
    main()
