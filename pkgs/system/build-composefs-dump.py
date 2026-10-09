# SPDX-License-Identifier: MIT
# Ported from nixpkgs:
#   nixos/modules/system/etc/build-composefs-dump.py (commit pinned in
#   pkgs/system/build-composefs-dump.py's containing derivation).
# Copyright (c) 2003-2026 Eelco Dolstra and the Nixpkgs/NixOS contributors.
#
# AOS port differs from upstream: when an entry's `source` is a
# directory and `mode == "symlink"`, the script recurses into the
# source tree and emits one composefs entry per path. The recursion
# is what allows another lower (e.g. the evaluated per-generation writes)
# to merge files into the same directory at runtime: overlayfs can
# only merge two directory inodes, not a directory and a symlink. The
# canonical caller is `environment.etc."systemd/system".source =
# generateUnits {…}`, where role-derived unit files need to merge
# with the system's.
#
# This script is invoked by name from the build derivation with the
# AOS python store-path interpreter; no shebang (CLAUDE.md forbids
# /usr/bin/env outside the bootstrap chain).

"""Build a composefs dump from a JSON config.

See the composefs-dump(5) man page for the per-line format:

    PATH SIZE FILETYPE|MODE NLINK UID GID RDEV MTIME PAYLOAD CONTENT DIGEST

Filetype codes (octal): 4=directory, 10=regular file, 12=symlink.
"""

import argparse
import glob
import json
import os
import sys
from enum import Enum
from pathlib import Path
from typing import Any

Attrs = dict[str, Any]


class FileType(Enum):
    """Filetype prefix of the composefs mode field, in octal."""

    directory = "4"
    file = "10"
    symlink = "12"


class ComposefsPath:
    path: str
    size: int
    filetype: FileType
    mode: str
    uid: str
    gid: str
    payload: str
    rdev: str = "0"
    nlink: int = 1
    mtime: str = "1.0"
    content: str = "-"
    digest: str = "-"
    selinux_context: str | None = None

    def __init__(
        self,
        attrs: Attrs,
        size: int,
        filetype: FileType,
        mode: str,
        payload: str,
        path: str | None = None,
    ):
        if path is None:
            path = attrs["target"]
        self.path = path
        self.size = size
        self.filetype = filetype

        match len(mode):
            case 3 | 4:
                # Pad to 4 digits — composefs's `filetype|mode` field
                # concatenates the two without a separator and expects
                # a fixed 4-digit mode.
                self.mode = f"{mode:0>4}"
            case _:
                raise ValueError(
                    f"mode should be 3 or 4 octal digits, got: {mode}"
                )

        self.uid = attrs["uid"]
        self.gid = attrs["gid"]
        self.payload = payload

    def write_line(self) -> str:
        line_list = [
            str(self.path),
            str(self.size),
            f"{self.filetype.value}{self.mode}",
            str(self.nlink),
            str(self.uid),
            str(self.gid),
            str(self.rdev),
            str(self.mtime),
            str(self.payload),
            str(self.content),
            str(self.digest),
        ]
        if self.selinux_context is not None:
            # composefs-dump represents the conventional terminating NUL as an
            # explicit xattr byte; mkcomposefs preserves the supplied length.
            encoded_context = self.selinux_context.encode("ascii") + b"\x00"
            line_list.append(
                "security.selinux=" + escape_xattr_value(encoded_context)
            )
        return " ".join(line_list)


def escape_xattr_value(value: bytes) -> str:
    """Escapes one composefs dump xattr value canonically."""

    escaped: list[str] = []
    for byte in value:
        if byte == ord("\\"):
            escaped.append("\\\\")
        elif 0x21 <= byte <= 0x7E and byte != ord("="):
            escaped.append(chr(byte))
        else:
            escaped.append(f"\\x{byte:02x}")
    return "".join(escaped)


def load_context_map(path: str) -> dict[tuple[str, FileType], str | None]:
    """Loads the canonical context plan consumed by image builders."""

    with open(path, "rb") as context_file:
        document = json.load(context_file)
    if document.get("version") != 1 or not isinstance(document.get("entries"), list):
        raise ValueError("SELinux context map must use schema version 1")

    kind_map = {
        "directory": FileType.directory,
        "regular": FileType.file,
        "symlink": FileType.symlink,
    }
    contexts: dict[tuple[str, FileType], str | None] = {}
    for entry in document["entries"]:
        try:
            image_path = normalize_path(entry["path"])
            file_type = kind_map[entry["kind"]]
            context = entry["context"]
        except (KeyError, TypeError) as error:
            raise ValueError("invalid SELinux context-map entry") from error
        if context is not None:
            if not isinstance(context, str):
                raise ValueError(f"invalid SELinux context for {image_path}")
            try:
                context.encode("ascii")
            except UnicodeEncodeError as error:
                raise ValueError(
                    f"non-ASCII SELinux context for {image_path}"
                ) from error
            if "\x00" in context or any(character.isspace() for character in context):
                raise ValueError(f"invalid SELinux context for {image_path}")
            if len(context.split(":", 3)) not in {3, 4}:
                raise ValueError(f"invalid SELinux context for {image_path}")

        key = (image_path, file_type)
        if key in contexts:
            raise ValueError(f"duplicate SELinux context-map entry for {image_path}")
        contexts[key] = context
    return contexts


def apply_context_map(
    paths: list[ComposefsPath], contexts: dict[tuple[str, FileType], str | None]
) -> None:
    """Assigns exactly one non-default SELinux context to every image inode."""

    for composefs_path in paths:
        key = (normalize_path(composefs_path.path), composefs_path.filetype)
        if key not in contexts:
            raise ValueError(
                "SELinux context map has no entry for "
                f"{composefs_path.path} ({composefs_path.filetype.name})"
            )
        context = contexts[key]
        if context is None or context.split(":", 3)[2] in {
            "default_t",
            "unlabeled_t",
        }:
            raise ValueError(f"unsafe SELinux context for {composefs_path.path}")
        composefs_path.selinux_context = context


def eprint(*args: Any, **kwargs: Any) -> None:
    print(*args, **kwargs, file=sys.stderr)


def normalize_path(path: str) -> str:
    return str("/" + os.path.normpath(path).lstrip("/"))


def leading_directories(path: str) -> list[str]:
    """Return every leading directory of ``path``.

    Given the path ``alsa/conf.d/50-pipewire.conf``, this returns
    ``["alsa", "alsa/conf.d"]``.
    """
    parents = list(Path(path).parents)
    parents.reverse()
    # Drop the implicit `.` (relative) or `/` (absolute) sentinel.
    del parents[0]
    return [str(i) for i in parents]


def add_leading_directories(
    target: str, attrs: Attrs, paths: dict[str, ComposefsPath]
) -> None:
    """Synthesise composefs directory entries for ``target``'s parents.

    mkcomposefs requires every leading directory of every file path to
    appear explicitly in the dump.
    """
    for component in leading_directories(target):
        if component in paths:
            continue
        composefs_path = ComposefsPath(
            attrs,
            path=component,
            size=4096,
            filetype=FileType.directory,
            mode="0755",
            payload="-",
        )
        paths[component] = composefs_path


def recurse_symlink_source(
    target: str, source: str, attrs: Attrs, paths: dict[str, ComposefsPath]
) -> None:
    """Walk a directory ``source`` and emit one composefs entry per
    descendant under ``target``.

    Semantics (spec v12 §5.2):
      - ``target`` itself becomes a composefs directory entry with
        ``payload = "-"`` (plain directory; children listed explicitly,
        no `redirect_dir`).
      - Subdirectories: composefs directory entries, ``payload = "-"``.
      - Symlinks: composefs symlink entries with the target preserved
        verbatim from ``os.readlink`` (relative if relative, absolute
        if absolute — we do *not* resolve through ``os.path.realpath``).
      - Regular files: composefs symlink entries pointing at the
        source's ``/nix/store/...`` path. The basedir is NOT extended
        for these leaves — the leaves stay as symlinks into the Nix
        store.
    """
    # The target itself.
    paths[target] = ComposefsPath(
        attrs,
        path=target,
        size=4096,
        filetype=FileType.directory,
        mode="0755",
        payload="-",
    )
    add_leading_directories(target, attrs, paths)

    # os.walk is depth-first by default; followlinks=False keeps any
    # symlinks-to-directories in the source tree as symlink leaves
    # rather than recursing through them.
    for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
        # Map the on-disk dirpath back into the composefs in-image
        # namespace by replacing the source prefix with the target.
        rel = os.path.relpath(dirpath, source)
        if rel == ".":
            in_image_dir = target
        else:
            in_image_dir = normalize_path(f"{target}/{rel}")

        # Subdirectories (the dir entry for in_image_dir itself is
        # already in `paths` either from the outer call or from the
        # parent iteration).
        for dname in sorted(dirnames):
            child = normalize_path(f"{in_image_dir}/{dname}")
            child_on_disk = os.path.join(dirpath, dname)
            if os.path.islink(child_on_disk):
                # A symlink-to-directory: emit a symlink entry, do not
                # recurse into it. Remove from dirnames so os.walk
                # doesn't descend.
                dirnames.remove(dname)
                paths[child] = ComposefsPath(
                    attrs,
                    path=child,
                    size=100,
                    filetype=FileType.symlink,
                    mode="0777",
                    payload=os.readlink(child_on_disk),
                )
            elif child not in paths:
                paths[child] = ComposefsPath(
                    attrs,
                    path=child,
                    size=4096,
                    filetype=FileType.directory,
                    mode="0755",
                    payload="-",
                )

        # Files and file-symlinks.
        for fname in sorted(filenames):
            child = normalize_path(f"{in_image_dir}/{fname}")
            child_on_disk = os.path.join(dirpath, fname)
            if os.path.islink(child_on_disk):
                # Preserve the symlink target verbatim (per spec §5.2,
                # don't realpath-resolve — matches `cp -RP`).
                paths[child] = ComposefsPath(
                    attrs,
                    path=child,
                    size=100,
                    filetype=FileType.symlink,
                    mode="0777",
                    payload=os.readlink(child_on_disk),
                )
            else:
                # Regular file: composefs symlink back to the source
                # `/nix/store/...` path; the basedir is NOT extended.
                paths[child] = ComposefsPath(
                    attrs,
                    path=child,
                    size=100,
                    filetype=FileType.symlink,
                    mode="0777",
                    payload=child_on_disk,
                )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("config_file")
    parser.add_argument("--context-map")
    options = parser.parse_args()
    config_file = options.config_file

    with open(config_file, "rb") as f:
        config = json.load(f)

    if not config:
        eprint("Config is empty.")
        sys.exit(1)

    eprint("Building composefs dump...")

    paths: dict[str, ComposefsPath] = {}
    for attrs in config:
        # Normalize the target path to work around variations in how
        # callers declare paths under environment.etc.
        attrs["target"] = normalize_path(attrs["target"])

        target = attrs["target"]
        source = attrs["source"]
        mode = attrs["mode"]

        if "*" in source:  # Globbed source.
            for glob_source in glob.glob(source):
                basename = os.path.basename(glob_source)
                glob_target = f"{target}/{basename}"

                paths[glob_target] = ComposefsPath(
                    attrs,
                    path=glob_target,
                    size=100,
                    filetype=FileType.symlink,
                    mode="0777",
                    payload=glob_source,
                )
                add_leading_directories(glob_target, attrs, paths)
            continue

        if mode == "symlink" and os.path.isdir(source):
            # AOS extension: recurse into directory sources so the
            # EROFS image carries a real directory of entries — see
            # spec v12 §5.2.
            recurse_symlink_source(target, source, attrs, paths)
            continue

        if mode == "symlink" or mode == "direct-symlink":
            paths[target] = ComposefsPath(
                attrs,
                size=100,
                filetype=FileType.symlink,
                mode="0777",
                payload=source,
            )
        elif os.path.isdir(source):
            paths[target] = ComposefsPath(
                attrs,
                size=4096,
                filetype=FileType.directory,
                mode=mode,
                payload=source,
            )
        else:
            paths[target] = ComposefsPath(
                attrs,
                size=os.stat(source).st_size,
                filetype=FileType.file,
                mode=mode,
                # File content lives in the basedir at the same
                # relative path; payload here is the in-basedir path.
                payload=target.lstrip("/"),
            )
        add_leading_directories(target, attrs, paths)

    root = ComposefsPath(
        {"target": "/", "uid": "0", "gid": "0"},
        size=4096,
        filetype=FileType.directory,
        mode="0755",
        payload="-",
    )
    # Preserve the historical root record exactly when labeling is disabled.
    root.mtime = "0.0"
    ordered_paths = [root, *(paths[key] for key in sorted(paths))]
    if options.context_map is not None:
        apply_context_map(ordered_paths, load_context_map(options.context_map))

    composefs_dump = []
    for composefs_path in ordered_paths:
        eprint(composefs_path.path)
        composefs_dump.append(composefs_path.write_line())

    print("\n".join(composefs_dump))


if __name__ == "__main__":
    main()
