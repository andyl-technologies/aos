# SPDX-License-Identifier: GPL-2.0-or-later
"""Compare semantic inode metadata while EROFS compressed extents change.

The check uses the pinned erofs-utils 1.9.4 reader, not a second filesystem
parser. The labeled source producer admits only ``security.selinux`` xattrs;
its existing exact-map verifier checks every label and complete inode mode.
Numeric NIDs may change, but their path equivalence classes must not.
"""

from __future__ import annotations

import argparse
import json
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class InodeRecord:
    """Carry the metadata exposed by the pinned package-native reader."""

    nid: int
    size: int
    links: int
    uid: int
    gid: int
    permissions: int
    timestamp: str


def one_match(pattern: str, text: str) -> tuple[str, ...]:
    """Reject missing or repeated native metadata fields."""

    matches = list(re.finditer(pattern, text, re.MULTILINE))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one native metadata field: {pattern}")
    return matches[0].groups()


def parse_inode(output: bytes) -> InodeRecord:
    """Parse the fixed 1.9.4 inode report, excluding physical layout fields."""

    text = output.decode("utf-8", errors="strict")
    (size,) = one_match(r"^Size: ([0-9]+)  On-disk size: [0-9]+  .+$", text)
    nid, links = one_match(r"^NID: ([0-9]+)   Links: ([0-9]+)   Layout: .+$", text)
    uid, gid, permissions = one_match(
        r"^Uid: ([0-9]+)   Gid: ([0-9]+)  Access: ([0-7]{4})/[rwx-]{9}$", text
    )
    (timestamp,) = one_match(
        r"^Timestamp: ([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8}\.[0-9]{9})$", text
    )
    return InodeRecord(
        nid=int(nid),
        size=int(size),
        links=int(links),
        uid=int(uid),
        gid=int(gid),
        permissions=int(permissions, 8),
        timestamp=timestamp,
    )


def compare_metadata(path: str, mode: int, before: InodeRecord, after: InodeRecord) -> None:
    """Compare semantic metadata, not directory encoding or compressed size."""

    if before.permissions != mode & 0o777 or after.permissions != mode & 0o777:
        raise ValueError(f"native mode reports disagree for {path!r}")
    before_metadata = (before.links, before.uid, before.gid, before.timestamp)
    after_metadata = (after.links, after.uid, after.gid, after.timestamp)
    if before_metadata != after_metadata:
        raise ValueError(f"inode metadata differs for {path!r}")
    if not stat.S_ISDIR(mode) and before.size != after.size:
        raise ValueError(f"inode content size differs for {path!r}")


def compare_mapping(
    path: str,
    before: int,
    after: int,
    forward: dict[int, int],
    reverse: dict[int, int],
) -> None:
    """Require a bijection so neither independent inodes nor hardlinks collapse."""

    if forward.setdefault(before, after) != after:
        raise ValueError(f"an original hardlink split for {path!r}")
    if reverse.setdefault(after, before) != before:
        raise ValueError(f"separate original inodes merged for {path!r}")


def read_native(dump_erofs: Path, image: Path, path: str, *options: str) -> bytes:
    """Read one inode through the package tool with bounded error output."""

    completed = subprocess.run(
        [dump_erofs, f"--path={path}", *options, image],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr[-4096:].decode("utf-8", errors="replace")
        raise ValueError(f"native EROFS read failed for {path!r}: {detail}")
    return completed.stdout


def verify(options: argparse.Namespace) -> dict[str, int]:
    """Verify complete inventories, labels, metadata and inode equivalence."""

    sys.path.insert(0, str(options.policy_support))
    from labeled_erofs_tar import inventory, load_contexts
    from verify_erofs_contexts import parse_record, verify_record

    contexts = load_contexts(options.expected)
    for tree in (options.baseline_tree, options.candidate_tree):
        observed = {path for path, _, _ in inventory(tree)}
        if observed != contexts.keys():
            raise ValueError(f"extracted names differ from exact context map: {tree}")

    version = subprocess.run(
        [options.dump_erofs, "--version"], capture_output=True, check=True
    ).stdout.strip()
    if version != b"dump.erofs (erofs-utils) 1.9.4":
        raise ValueError(f"unqualified native inode report version: {version!r}")

    forward: dict[int, int] = {}
    reverse: dict[int, int] = {}
    for index, (path, (kind, context)) in enumerate(contexts.items(), start=1):
        records = []
        for image in (options.baseline_image, options.candidate_image):
            label = parse_record(
                read_native(
                    options.dump_erofs, image, path, "--get-xattr=security.selinux"
                )
            )
            verify_record(label, path, kind, context)
            inode = parse_inode(read_native(options.dump_erofs, image, path))
            records.append((label.mode, inode))

        (before_mode, before), (after_mode, after) = records
        if before_mode != after_mode:
            raise ValueError(f"complete inode mode differs for {path!r}")
        compare_metadata(path, before_mode, before, after)
        compare_mapping(path, before.nid, after.nid, forward, reverse)
        if index % 1000 == 0:
            print(f"verified {index}/{len(contexts)} inode names", file=sys.stderr)

    before_bytes = options.baseline_image.stat().st_size
    after_bytes = options.candidate_image.stat().st_size
    if after_bytes >= before_bytes:
        raise ValueError("deduplicated cohort did not reduce physical image bytes")
    return {
        "version": 1,
        "paths": len(contexts),
        "independentInodes": len(forward),
        "baselineBytes": before_bytes,
        "deduplicatedBytes": after_bytes,
        "savedBytes": before_bytes - after_bytes,
    }


def main() -> None:
    """Read explicit image/tree inputs and emit successful measurement evidence."""

    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "dump-erofs",
        "policy-support",
        "expected",
        "baseline-image",
        "candidate-image",
        "baseline-tree",
        "candidate-tree",
    ):
        parser.add_argument(f"--{name}", type=Path, required=True)
    result = verify(parser.parse_args())
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
        print(f"verify-erofs-repack: {error}", file=sys.stderr)
        raise SystemExit(1) from error
