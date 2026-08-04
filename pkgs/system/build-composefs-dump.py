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
        return " ".join(line_list)


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
    config_file = sys.argv[1]
    if not config_file:
        eprint("No config file was supplied.")
        sys.exit(1)

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

    composefs_dump = ["/ 4096 40755 1 0 0 0 0.0 - - -"]  # Root inode.
    for key in sorted(paths):
        composefs_path = paths[key]
        eprint(composefs_path.path)
        composefs_dump.append(composefs_path.write_line())

    print("\n".join(composefs_dump))


if __name__ == "__main__":
    main()
