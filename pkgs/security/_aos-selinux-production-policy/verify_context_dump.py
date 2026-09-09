"""Verify composefs-info output against a complete SELinux context map."""

from __future__ import annotations

import argparse
import json
import stat
import sys
from pathlib import Path
from typing import Sequence


class VerificationError(ValueError):
    """Reports a mismatch between an image dump and its label plan."""


def unescape_field(field: str) -> bytes:
    """Decodes the escape syntax used by composefs dump fields."""

    result = bytearray()
    index = 0
    named = {"\\": ord("\\"), "n": 10, "r": 13, "t": 9}
    while index < len(field):
        if field[index] != "\\":
            codepoint = ord(field[index])
            if codepoint > 0x7F:
                raise VerificationError("unescaped non-ASCII dump byte")
            result.append(codepoint)
            index += 1
            continue

        index += 1
        if index >= len(field):
            raise VerificationError("trailing dump escape")
        escape = field[index]
        if escape in named:
            result.append(named[escape])
            index += 1
            continue
        if escape != "x" or index + 2 >= len(field):
            raise VerificationError(f"invalid dump escape near {field[index:]!r}")
        try:
            result.append(int(field[index + 1 : index + 3], 16))
        except ValueError as error:
            raise VerificationError("invalid hexadecimal dump escape") from error
        index += 3
    return bytes(result)


def kind_from_dump_mode(field: str) -> str:
    """Returns the context-map kind represented by an octal dump mode."""

    try:
        mode = int(field.removeprefix("@"), 8)
    except ValueError as error:
        raise VerificationError(f"invalid dump mode {field!r}") from error
    file_type = stat.S_IFMT(mode)
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
        return kinds[file_type]
    except KeyError as error:
        raise VerificationError(f"unsupported dump mode {field!r}") from error


def parse_dump(path: Path) -> dict[tuple[str, str], bytes | None]:
    """Reads every path, inode kind, and SELinux xattr from a dump."""

    entries: dict[tuple[str, str], bytes | None] = {}
    for line_number, raw_line in enumerate(
        path.read_text(encoding="ascii").splitlines(), start=1
    ):
        fields = raw_line.split(" ")
        if len(fields) < 11:
            raise VerificationError(f"line {line_number}: fewer than 11 fields")
        image_path = unescape_field(fields[0]).decode("utf-8")
        kind = kind_from_dump_mode(fields[2])
        context = None
        for encoded_xattr in fields[11:]:
            if "=" not in encoded_xattr:
                raise VerificationError(f"line {line_number}: malformed xattr")
            encoded_key, encoded_value = encoded_xattr.split("=", 1)
            key = unescape_field(encoded_key)
            if key != b"security.selinux":
                continue
            if context is not None:
                raise VerificationError(
                    f"line {line_number}: duplicate security.selinux xattr"
                )
            context = unescape_field(encoded_value)

        key = (image_path, kind)
        if key in entries:
            raise VerificationError(f"duplicate image path and kind: {key}")
        entries[key] = context
    return entries


def load_expected(path: Path) -> dict[tuple[str, str], bytes | None]:
    """Loads the canonical expected-map representation."""

    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("version") != 1 or not isinstance(document.get("entries"), list):
        raise VerificationError("expected map must use schema version 1")
    result: dict[tuple[str, str], bytes | None] = {}
    for entry in document["entries"]:
        key = (entry["path"], entry["kind"])
        if key in result:
            raise VerificationError(f"duplicate expected path and kind: {key}")
        context = entry["context"]
        result[key] = None if context is None else context.encode("ascii") + b"\x00"
    return result


def verify(dump_path: Path, expected_path: Path) -> None:
    """Requires exact path/kind/context equality for the whole image."""

    observed = parse_dump(dump_path)
    expected = load_expected(expected_path)
    if observed.keys() != expected.keys():
        missing = sorted(expected.keys() - observed.keys())
        unexpected = sorted(observed.keys() - expected.keys())
        raise VerificationError(
            f"image path set differs: missing={missing}, unexpected={unexpected}"
        )
    mismatches = [
        (key, expected[key], observed[key])
        for key in sorted(expected)
        if expected[key] != observed[key]
    ]
    if mismatches:
        raise VerificationError(f"image SELinux contexts differ: {mismatches}")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    """Parses verifier command-line arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--dump", type=Path, required=True)
    parser.add_argument("--expected", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Verifies one composefs-info dump."""

    options = parse_args(sys.argv[1:] if argv is None else argv)
    verify(options.dump, options.expected)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, VerificationError) as error:
        print(f"verify-context-dump: {error}", file=sys.stderr)
        raise SystemExit(1) from error
