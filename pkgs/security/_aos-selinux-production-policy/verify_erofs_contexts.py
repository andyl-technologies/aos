# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify generic EROFS SELinux xattrs through the package-native reader."""

from __future__ import annotations

import argparse
import json
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


MARKER = b"EROFS_XATTR_V1\t"


class VerificationError(ValueError):
    """Reports malformed inspector output or an image/map mismatch."""


@dataclass(frozen=True)
class XattrRecord:
    """Carries one machine-readable inode mode and xattr result."""

    mode: int
    value: bytes | None


def parse_record(stdout: bytes) -> XattrRecord:
    """Parses exactly one versioned xattr marker from inspector stdout."""

    marker_lines = [line for line in stdout.splitlines() if line.startswith(MARKER)]
    if len(marker_lines) != 1:
        raise VerificationError(
            f"expected one EROFS xattr marker, observed {len(marker_lines)}"
        )

    try:
        fields = marker_lines[0].decode("ascii").split("\t")
    except UnicodeDecodeError as error:
        raise VerificationError("non-ASCII EROFS xattr marker") from error
    if len(fields) != 4 or fields[0] != "EROFS_XATTR_V1":
        raise VerificationError("malformed EROFS xattr marker")

    values: dict[str, str] = {}
    for field in fields[1:]:
        if "=" not in field:
            raise VerificationError("malformed EROFS xattr marker field")
        key, value = field.split("=", 1)
        if key in values:
            raise VerificationError(f"duplicate EROFS xattr marker field {key!r}")
        values[key] = value
    if values.keys() != {"mode", "status", "value"}:
        raise VerificationError("unexpected EROFS xattr marker fields")
    if re.fullmatch(r"[0-7]{7}", values["mode"]) is None:
        raise VerificationError("invalid EROFS xattr inode mode")

    status = values["status"]
    encoded_value = values["value"]
    if status == "absent":
        if encoded_value != "-":
            raise VerificationError("absent EROFS xattr carries a value")
        value = None
    elif status == "present":
        if (
            len(encoded_value) % 2 != 0
            or re.fullmatch(r"[0-9a-f]*", encoded_value) is None
        ):
            raise VerificationError("invalid EROFS xattr hexadecimal value")
        value = bytes.fromhex(encoded_value)
    else:
        raise VerificationError(f"unknown EROFS xattr status {status!r}")

    return XattrRecord(mode=int(values["mode"], 8), value=value)


def kind_from_mode(mode: int) -> str:
    """Returns the context-map kind represented by a complete inode mode."""

    kinds = {
        stat.S_IFBLK: "block",
        stat.S_IFCHR: "character",
        stat.S_IFDIR: "directory",
        stat.S_IFIFO: "fifo",
        stat.S_IFREG: "regular",
        stat.S_IFSOCK: "socket",
        stat.S_IFLNK: "symlink",
    }
    try:
        return kinds[stat.S_IFMT(mode)]
    except KeyError as error:
        raise VerificationError(f"unsupported EROFS inode mode 0o{mode:o}") from error


def verify_record(
    record: XattrRecord,
    path: str,
    expected_kind: str,
    expected_context: str | None,
) -> None:
    """Compares one native inspector record with its complete-map entry."""

    observed_kind = kind_from_mode(record.mode)
    if observed_kind != expected_kind:
        raise VerificationError(
            f"EROFS inode kind differs for {path!r}: "
            f"expected {expected_kind}, observed {observed_kind}"
        )

    # erofs-utils' --file-contexts writer deliberately stores strlen(context)
    # bytes. Keep this verifier specific to that producer and reject alternate
    # encodings, even though the kernel accepts a trailing NUL too.
    expected_value = None if expected_context is None else expected_context.encode("ascii")
    if record.value != expected_value:
        raise VerificationError(
            f"EROFS SELinux context differs for {path!r}: "
            f"expected {expected_value!r}, observed {record.value!r}"
        )


def verify(dump_erofs: Path, image: Path, expected_path: Path) -> None:
    """Reads and verifies every expected image path through ``dump.erofs``."""

    document = json.loads(expected_path.read_text(encoding="utf-8"))
    if document.get("version") != 1 or not isinstance(document.get("entries"), list):
        raise VerificationError("expected map must use schema version 1")

    for entry in document["entries"]:
        try:
            path = entry["path"]
            expected_kind = entry["kind"]
            expected_context = entry["context"]
        except (KeyError, TypeError) as error:
            raise VerificationError("invalid expected context-map entry") from error
        if not isinstance(path, str) or not isinstance(expected_kind, str):
            raise VerificationError("invalid expected path or inode kind")
        if expected_context is not None and not isinstance(expected_context, str):
            raise VerificationError(f"invalid expected context for {path!r}")

        completed = subprocess.run(
            [
                dump_erofs,
                f"--path={path}",
                "--get-xattr=security.selinux",
                image,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            diagnostic = completed.stderr[-4096:].decode("utf-8", errors="replace")
            raise VerificationError(
                f"dump.erofs failed for {path!r}: {diagnostic.rstrip()}"
            )
        verify_record(
            parse_record(completed.stdout),
            path,
            expected_kind,
            expected_context,
        )


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    """Parses verifier command-line arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--dump-erofs", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--expected", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Verifies one generic EROFS image and expected context map."""

    options = parse_args(sys.argv[1:] if argv is None else argv)
    verify(options.dump_erofs, options.image, options.expected)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, VerificationError) as error:
        print(f"verify-erofs-contexts: {error}", file=sys.stderr)
        raise SystemExit(1) from error
