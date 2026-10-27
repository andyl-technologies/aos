# SPDX-License-Identifier: GPL-2.0-or-later
"""Encode an exact inode-context map as a PAX tar for mkfs.erofs.

The AOS builder cannot set ``security.selinux`` on staging files without host
privilege. EROFS's tar importer accepts SCHILY xattrs and writes them directly
into image metadata, so no builder-side security xattr mutation is needed.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import tarfile
from pathlib import Path


KINDS = {
    stat.S_IFBLK: "block",
    stat.S_IFCHR: "character",
    stat.S_IFDIR: "directory",
    stat.S_IFIFO: "fifo",
    stat.S_IFREG: "regular",
    stat.S_IFSOCK: "socket",
    stat.S_IFLNK: "symlink",
}


def inventory(root: Path) -> list[tuple[str, Path, os.stat_result]]:
    """Return the no-follow image inventory in bytewise path order."""

    pending = [("/", root)]
    entries = []
    while pending:
        image_path, source = pending.pop()
        metadata = source.lstat()
        entries.append((image_path, source, metadata))

        if stat.S_ISDIR(metadata.st_mode):
            children = sorted(source.iterdir(), key=os.fsencode, reverse=True)
            pending.extend(
                (
                    image_path.rstrip("/") + "/" + child.name,
                    child,
                )
                for child in children
            )
    return entries


def load_contexts(path: Path) -> dict[str, tuple[str, str | None]]:
    """Read the exact planner map, rejecting duplicate or malformed records."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("version") != 1 or not isinstance(payload.get("entries"), list):
        raise ValueError("unsupported exact inode-context map")

    contexts = {}
    for entry in payload["entries"]:
        image_path = entry["path"]
        if image_path in contexts:
            raise ValueError(f"duplicate inode-context path: {image_path}")
        contexts[image_path] = (entry["kind"], entry["context"])
    return contexts


def make_tar(root: Path, contexts: dict[str, tuple[str, str | None]], output: Path) -> None:
    """Write every validated source inode with its planned physical label."""

    entries = inventory(root)
    if {image_path for image_path, _, _ in entries} != contexts.keys():
        raise ValueError("source tree and exact inode-context map differ")

    physical_labels = {}
    with tarfile.open(output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for image_path, source, metadata in entries:
            kind = KINDS.get(stat.S_IFMT(metadata.st_mode))
            planned_kind, context = contexts[image_path]
            if kind is None or kind != planned_kind:
                raise ValueError(f"inode kind differs from context map: {image_path}")
            if context is not None and (not context.isascii() or "\x00" in context):
                raise ValueError(f"invalid SELinux context: {image_path}")
            unexpected_xattrs = set(os.listxattr(source, follow_symlinks=False)) - {
                "security.selinux"
            }
            if unexpected_xattrs:
                raise ValueError(f"unmodeled source xattrs: {image_path}")
            if kind != "symlink":
                identity = (metadata.st_dev, metadata.st_ino)
                previous = physical_labels.setdefault(identity, context)
                if previous != context:
                    raise ValueError(f"hardlinked inode has conflicting labels: {image_path}")

            archive_name = "." if image_path == "/" else "." + image_path
            member = archive.gettarinfo(os.fspath(source), arcname=archive_name)
            if member is None:
                raise ValueError(f"unsupported image inode: {image_path}")
            member.pax_headers = {}
            if context is not None:
                member.pax_headers["SCHILY.xattr.security.selinux"] = context

            if member.isfile():
                with source.open("rb") as contents:
                    archive.addfile(member, contents)
            else:
                archive.addfile(member)


def main() -> None:
    """Encode the exact context map without accessing host SELinux authority."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--map", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    make_tar(args.root, load_contexts(args.map), args.output)


if __name__ == "__main__":
    main()
