"""Verify composefs-info output against a complete SELinux context map."""

from __future__ import annotations

import argparse
import json
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


class VerificationError(ValueError):
    """Reports a mismatch between an image dump and its label plan."""


@dataclass(frozen=True)
class DumpRecord:
    """Describes one validated inode record from a composefs dump."""

    path: str
    kind: str
    link_count: int
    payload: bytes
    selinux_context: bytes | None


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


def _parse_nonnegative_decimal(field: str, description: str) -> int:
    """Parses one canonical nonnegative decimal dump field."""

    if not field or not field.isascii() or not field.isdecimal():
        raise VerificationError(f"invalid {description} {field!r}")
    if len(field) > 1 and field.startswith("0"):
        raise VerificationError(f"noncanonical {description} {field!r}")
    return int(field, 10)


def _decode_utf8_field(field: str, description: str) -> str:
    """Decodes one escaped UTF-8 dump field without control characters."""

    try:
        decoded = unescape_field(field).decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError(f"non-UTF-8 {description}") from error
    if "\x00" in decoded or "\n" in decoded or "\r" in decoded:
        raise VerificationError(f"control character in {description}")
    return decoded


def _validate_image_path(path: str) -> None:
    """Requires one canonical absolute path in an image namespace."""

    if not path.startswith("/"):
        raise VerificationError(f"image path is not absolute: {path!r}")
    if path == "/":
        return
    if path != "/" and path.endswith("/"):
        raise VerificationError(f"image path has a trailing slash: {path!r}")
    components = path.split("/")[1:]
    if any(component in {"", ".", ".."} for component in components):
        raise VerificationError(f"image path is not canonical: {path!r}")


def parse_dump_records(path: Path) -> list[DumpRecord]:
    """Reads and validates every inode record from a composefs dump."""

    records: list[DumpRecord] = []
    seen_paths: set[str] = set()
    for line_number, raw_line in enumerate(
        path.read_text(encoding="ascii").splitlines(), start=1
    ):
        fields = raw_line.split(" ")
        if len(fields) < 11:
            raise VerificationError(f"line {line_number}: fewer than 11 fields")

        image_path = _decode_utf8_field(fields[0], "image path")
        _validate_image_path(image_path)
        _parse_nonnegative_decimal(fields[1], "file size")
        kind = kind_from_dump_mode(fields[2])
        link_count = _parse_nonnegative_decimal(fields[3], "link count")
        if link_count == 0:
            raise VerificationError("link count must be positive")
        _parse_nonnegative_decimal(fields[4], "uid")
        _parse_nonnegative_decimal(fields[5], "gid")
        _parse_nonnegative_decimal(fields[6], "device number")
        payload = unescape_field(fields[8])

        context = None
        xattr_keys: set[bytes] = set()
        for encoded_xattr in fields[11:]:
            if "=" not in encoded_xattr:
                raise VerificationError(f"line {line_number}: malformed xattr")
            encoded_key, encoded_value = encoded_xattr.split("=", 1)
            key = unescape_field(encoded_key)
            if key in xattr_keys:
                raise VerificationError(
                    f"line {line_number}: duplicate xattr {key!r}"
                )
            xattr_keys.add(key)
            if key != b"security.selinux":
                continue
            context = unescape_field(encoded_value)

        if image_path in seen_paths:
            raise VerificationError(f"duplicate image path: {image_path}")
        seen_paths.add(image_path)
        records.append(
            DumpRecord(
                path=image_path,
                kind=kind,
                link_count=link_count,
                payload=payload,
                selinux_context=context,
            )
        )

    if not records:
        raise VerificationError("composefs dump is empty")

    records_by_path = {record.path: record for record in records}
    root = records_by_path.get("/")
    if root is None or root.kind != "directory":
        raise VerificationError("composefs dump has no root directory")
    for record in records:
        if record.path == "/":
            continue
        parent_path = record.path.rsplit("/", 1)[0] or "/"
        parent = records_by_path.get(parent_path)
        if parent is None:
            raise VerificationError(
                f"image path has no explicit parent directory: {record.path}"
            )
        if parent.kind != "directory":
            raise VerificationError(
                f"image path has a non-directory parent: {record.path}"
            )
    return records


def parse_dump(path: Path) -> dict[tuple[str, str], bytes | None]:
    """Reads every path, inode kind, and SELinux xattr from a dump."""

    return {
        (record.path, record.kind): record.selinux_context
        for record in parse_dump_records(path)
    }


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
