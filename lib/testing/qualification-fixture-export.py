"""Builds a guest-importable Nix export from a realized reference graph.

Qualification fixture exports are assembled inside a Nix sandbox, where the
daemon database is deliberately unavailable. Each referenced store path is
already mounted by ``exportReferencesGraph``; this helper dumps those paths
through a private local-store configuration and writes the documented Nix
export framing directly.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import struct
import subprocess
import sys
from typing import Any, BinaryIO


EXPORT_MAGIC = 0x4558494E
NIX_BASE32 = "0123456789abcdfghijklmnpqrsvwxyz"
STORE_PATH = re.compile(
    rf"^/nix/store/[{NIX_BASE32}]{{32}}-[A-Za-z0-9+._?=-]+$"
)


def write_u64(destination: BinaryIO, value: int) -> None:
    """Writes one little-endian unsigned export field."""

    destination.write(struct.pack("<Q", value))


def write_nix_string(destination: BinaryIO, value: str) -> None:
    """Writes one aligned string in the Nix wire representation."""

    encoded = value.encode()
    write_u64(destination, len(encoded))
    destination.write(encoded)
    destination.write(b"\0" * ((8 - len(encoded) % 8) % 8))


def decode_nix_base32(encoded: str) -> bytes:
    """Decodes Nix's reverse-digit, little-endian base32 representation."""

    decoded = bytearray(len(encoded) * 5 // 8)
    for index, character in enumerate(reversed(encoded)):
        try:
            digit = NIX_BASE32.index(character)
        except ValueError as error:
            raise RuntimeError("reference graph contains an invalid NAR hash") from error
        bit = index * 5
        byte_index, shift = divmod(bit, 8)
        if byte_index >= len(decoded):
            raise RuntimeError("reference graph contains an invalid NAR hash")
        decoded[byte_index] |= (digit << shift) & 0xFF
        carry = digit >> (8 - shift)
        if byte_index + 1 < len(decoded):
            decoded[byte_index + 1] |= carry
        elif carry:
            raise RuntimeError("reference graph contains a noncanonical NAR hash")
    return bytes(decoded)


def expected_sha256(value: str) -> bytes:
    """Returns the SHA-256 bytes recorded by ``exportReferencesGraph``."""

    prefix, separator, encoded = value.partition(":")
    if prefix != "sha256" or not separator or len(encoded) != 52:
        raise RuntimeError("reference graph lacks a Nix-base32 SHA-256 NAR hash")
    decoded = decode_nix_base32(encoded)
    if len(decoded) != 32:
        raise RuntimeError("reference graph NAR hash is not 256 bits")
    return decoded


def load_members(path: pathlib.Path) -> list[dict[str, Any]]:
    """Validates and dependency-orders the realized closure inventory."""

    document = json.loads(path.read_bytes())
    if document.get("schema") != "aos.reference-graph/v1":
        raise RuntimeError("fixture export received another reference graph schema")
    raw_members = document.get("paths")
    if not isinstance(raw_members, list) or not raw_members:
        raise RuntimeError("fixture export reference graph is empty")

    members: dict[str, dict[str, Any]] = {}
    for member in raw_members:
        if not isinstance(member, dict) or set(member) != {
            "path",
            "narHash",
            "narSize",
            "references",
        }:
            raise RuntimeError("fixture export reference member is malformed")
        store_path = member["path"]
        references = member["references"]
        if (
            not isinstance(store_path, str)
            or STORE_PATH.fullmatch(store_path) is None
            or store_path in members
            or not isinstance(references, list)
            or any(
                not isinstance(reference, str)
                or STORE_PATH.fullmatch(reference) is None
                for reference in references
            )
            or len(set(references)) != len(references)
            or not isinstance(member["narSize"], int)
            or member["narSize"] <= 0
        ):
            raise RuntimeError("fixture export reference graph is malformed")
        expected_sha256(member["narHash"])
        members[store_path] = member

    closure = set(members)
    if any(set(member["references"]) - closure for member in members.values()):
        raise RuntimeError("fixture export reference graph is incomplete")

    ordered: list[dict[str, Any]] = []
    visited: set[str] = set()
    active: set[str] = set()

    def visit(store_path: str) -> None:
        if store_path in visited:
            return
        if store_path in active:
            raise RuntimeError("fixture export reference graph contains a cycle")
        active.add(store_path)
        for reference in sorted(members[store_path]["references"]):
            if reference != store_path:
                visit(reference)
        active.remove(store_path)
        visited.add(store_path)
        ordered.append(members[store_path])

    for store_path in sorted(members):
        visit(store_path)
    return ordered


def dump_nar(
    destination: BinaryIO,
    member: dict[str, Any],
    nix_store: pathlib.Path,
    environment: dict[str, str],
    diagnostics: pathlib.Path,
) -> None:
    """Streams and verifies one mounted store path's canonical NAR."""

    hashed = hashlib.sha256()
    observed_size = 0
    with diagnostics.open("wb") as errors:
        process = subprocess.Popen(
            [str(nix_store), "--dump", member["path"]],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=errors,
        )
        if process.stdout is None:
            process.kill()
            process.wait()
            raise RuntimeError("nix-store did not expose its NAR stream")
        try:
            while block := process.stdout.read(8 * 1024 * 1024):
                observed_size += len(block)
                if observed_size > member["narSize"]:
                    raise RuntimeError("dumped NAR exceeds its reference graph size")
                hashed.update(block)
                destination.write(block)
        except BaseException:
            process.kill()
            process.wait()
            raise
        finally:
            process.stdout.close()
        return_code = process.wait()

    if return_code != 0:
        detail = diagnostics.read_bytes()[-64 * 1024 :].decode(errors="replace")
        raise RuntimeError(f"nix-store could not dump {member['path']}: {detail}")
    if observed_size != member["narSize"]:
        raise RuntimeError("dumped NAR differs from its reference graph size")
    if hashed.digest() != expected_sha256(member["narHash"]):
        raise RuntimeError("dumped NAR differs from its reference graph hash")


def export_fixture(
    inventory: pathlib.Path,
    output: pathlib.Path,
    nix_store: pathlib.Path,
    work: pathlib.Path,
) -> None:
    """Writes the exact inventory as a dependency-ordered Nix export stream."""

    members = load_members(inventory)
    state = work / "nix-state"
    configuration = work / "nix-conf"
    home = work / "home"
    for directory in (state, configuration, home):
        directory.mkdir(parents=True, exist_ok=True)
    (configuration / "nix.conf").write_text("build-users-group =\n")

    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(home),
            "NIX_CONF_DIR": str(configuration),
            "NIX_REMOTE": "local",
            "NIX_STATE_DIR": str(state),
        }
    )
    diagnostics = work / "nix-dump.log"
    try:
        with output.open("xb") as destination:
            for member in members:
                write_u64(destination, 1)
                dump_nar(destination, member, nix_store, environment, diagnostics)
                write_u64(destination, EXPORT_MAGIC)
                write_nix_string(destination, member["path"])
                write_u64(destination, len(member["references"]))
                for reference in member["references"]:
                    write_nix_string(destination, reference)
                write_nix_string(destination, "")
                write_u64(destination, 0)
            write_u64(destination, 0)
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    finally:
        diagnostics.unlink(missing_ok=True)


def main() -> None:
    """Reads the four positional paths and produces one verified export."""

    if len(sys.argv) != 5:
        raise RuntimeError(
            "usage: qualification-fixture-export.py INVENTORY OUTPUT NIX_STORE WORK"
        )
    export_fixture(*(pathlib.Path(value) for value in sys.argv[1:]))


if __name__ == "__main__":
    main()
