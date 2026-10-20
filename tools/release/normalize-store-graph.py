"""Repairs noncanonical NAR digest spellings in an unpublished registry tree.

The consumer format requires bare Nix base32 inside ``nar:sha256:`` tokens.
This utility repairs an emitter that nested an SRI hash in that token. It
preserves the digest bytes, NAR sizes, dependency edges, and record ordering.
It does not sign, commit, or publish the resulting tree.
"""

import argparse
import base64
import binascii
from pathlib import Path
import re


NIX_ALPHABET = "0123456789abcdfghijklmnpqrsvwxyz"
NAR_TOKEN = re.compile(r"(?<!\S)nar:sha256:([^\s]+)")


def encode_nix_base32(digest: bytes) -> str:
    """Encodes the same digest bytes in Nix's reversed base32 order."""
    if len(digest) != 32:
        raise ValueError("SHA-256 digest must contain exactly 32 bytes")

    value = int.from_bytes(digest, "little")
    return "".join(NIX_ALPHABET[(value >> (digit * 5)) & 31] for digit in range(51, -1, -1))


def normalize_record(content: str) -> str:
    """Validates NAR tokens and replaces only nested SRI digest spellings."""
    def normalize(match: re.Match) -> str:
        digest, separator, size = match.group(1).rpartition(":")
        if not separator or not size.isascii() or not size.isdecimal():
            raise ValueError(f"invalid NAR token size: {match.group(0)}")

        if digest.startswith("sha256-"):
            try:
                digest_bytes = base64.b64decode(digest[7:], validate=True)
            except binascii.Error as error:
                raise ValueError("invalid nested SRI SHA-256 digest") from error
            digest = encode_nix_base32(digest_bytes)

        if (len(digest) != 52 or digest[0] not in "01"
                or any(character not in NIX_ALPHABET for character in digest)):
            raise ValueError(f"invalid Nix base32 SHA-256 digest: {digest}")

        return f"nar:sha256:{digest}:{size}"

    return NAR_TOKEN.sub(normalize, content)


def normalize_tree(registry: Path, write: bool) -> tuple[int, int]:
    """Plans every repair before writing, so an invalid token stops the pass."""
    store = registry / "store"
    if not store.is_dir() or store.is_symlink():
        raise ValueError("registry must contain a regular store/ directory")

    changes = []
    records = 0
    for shard in sorted(store.iterdir()):
        if shard.is_symlink() or not shard.is_dir():
            raise ValueError(f"unexpected store graph shard: {shard}")

        for path in sorted(shard.iterdir()):
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"unexpected store graph record: {path}")
            content = path.read_text(encoding="utf-8")
            try:
                normalized = normalize_record(content)
            except ValueError as error:
                raise ValueError(f"{path}: {error}") from error

            records += 1
            if normalized != content:
                changes.append((path, normalized))

    if write:
        for path, normalized in changes:
            path.write_text(normalized, encoding="utf-8")

    return records, len(changes)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("registry", type=Path, help="unsigned working tree to repair")
    parser.add_argument("--write", action="store_true", help="apply the planned repairs")
    arguments = parser.parse_args()
    try:
        records, repairs = normalize_tree(arguments.registry, arguments.write)
    except (OSError, ValueError) as error:
        parser.exit(1, f"error: {error}\n")

    action = "Repaired" if arguments.write else "Would repair"
    print(f"{action} {repairs} of {records} store records.")


if __name__ == "__main__":
    main()
