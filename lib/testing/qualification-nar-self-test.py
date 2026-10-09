"""Exercises isolated import with a real self-referencing Nix output."""

from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import stat
import struct
import subprocess
import sys
from typing import Any


def load_support(path: pathlib.Path) -> Any:
    """Loads the NAR helper under the module name required by dataclasses."""

    name = "aos_qualification_nar_self_test_support"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load qualification NAR support")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def nix_string(value: bytes) -> bytes:
    """Encodes one byte string in the NAR wire representation."""

    padding = b"\0" * ((8 - len(value) % 8) % 8)
    return struct.pack("<Q", len(value)) + value + padding


def fixture_nar(root: pathlib.Path) -> bytes:
    """Serializes the real self-reference fixture as a canonical NAR."""

    expected = root / "self-reference"
    if expected.is_symlink() or not expected.is_file():
        raise RuntimeError("self-reference fixture lacks its regular witness")
    if expected.read_bytes() != (str(root) + "\n").encode():
        raise RuntimeError("self-reference fixture does not contain its own store path")

    def token(value: str) -> bytes:
        return nix_string(value.encode())

    def node(path: pathlib.Path) -> bytes:
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            encoded = token("(") + token("type") + token("directory")
            for child in sorted(path.iterdir(), key=lambda value: value.name.encode()):
                if child.is_symlink():
                    raise RuntimeError("self-reference fixture contains a symlink")
                encoded += token("entry") + token("(")
                encoded += token("name") + nix_string(child.name.encode())
                encoded += token("node") + node(child) + token(")")
            return encoded + token(")")
        if not stat.S_ISREG(mode):
            raise RuntimeError("self-reference fixture contains a special file")

        encoded = token("(") + token("type") + token("regular")
        if mode & 0o111:
            encoded += token("executable") + nix_string(b"")
        return encoded + token("contents") + nix_string(path.read_bytes()) + token(")")

    return token("nix-archive-1") + node(root)


def main() -> None:
    """Builds a one-node self-edge graph and restores it into an empty store."""

    if len(sys.argv) != 6:
        raise RuntimeError(
            "usage: qualification-nar-self-test.py SUPPORT NIX_STORE ZSTD ROOT WORK"
        )
    support = load_support(pathlib.Path(sys.argv[1]))
    nix_store = sys.argv[2]
    zstd = sys.argv[3]
    root = sys.argv[4]
    work = pathlib.Path(sys.argv[5])
    work.mkdir()

    nar_path = work / "root.nar.zst"
    nar_bytes = fixture_nar(pathlib.Path(root))
    nar_hash = "sha256:" + hashlib.sha256(nar_bytes).hexdigest()
    compressed = subprocess.run(
        [zstd, "-q", "-c"],
        check=False,
        input=nar_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    if compressed.returncode != 0:
        raise RuntimeError(
            "could not compress self-reference fixture: "
            + compressed.stderr.decode(errors="replace")
        )
    nar_path.write_bytes(compressed.stdout)
    transport_hash = "sha256:" + hashlib.sha256(compressed.stdout).hexdigest()

    narinfo_path = work / "root.narinfo"
    narinfo_path.write_text(
        "\n".join(
            [
                f"StorePath: {root}",
                f"NarHash: {nar_hash}",
                f"NarSize: {len(nar_bytes)}",
                "References: " + pathlib.PurePosixPath(root).name,
                "Deriver: unknown-deriver",
                "Compression: zstd",
                "",
            ]
        ),
        encoding="utf-8",
    )
    artifacts = {
        "root-nar": {
            "id": "root-nar",
            "kind": "package-nar",
            "media_type": "application/x-nix-nar",
            "compression": "zstd",
            "store_path": root,
            "nar_hash": nar_hash,
            "size_bytes": len(compressed.stdout),
            "sha256": transport_hash,
            "relationships": [
                {"relation": "authenticated-by", "target": "root-narinfo"},
                {"relation": "contains", "target": "root-nar"},
            ],
        },
        "root-narinfo": {
            "id": "root-narinfo",
            "kind": "nar-info",
            "size_bytes": narinfo_path.stat().st_size,
            "sha256": "sha256:" + hashlib.sha256(narinfo_path.read_bytes()).hexdigest(),
            "relationships": [],
        },
    }
    objects = {"root-nar": str(nar_path), "root-narinfo": str(narinfo_path)}

    def validate_object(artifact: dict[str, Any]) -> None:
        path = pathlib.Path(objects[artifact["id"]])
        observed = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        if path.stat().st_size != artifact["size_bytes"] or observed != artifact["sha256"]:
            raise RuntimeError("self-reference test object changed")

    closure = support.NarClosure(
        artifacts,
        objects,
        nix_store,
        zstd,
        work / "store",
        validate_object,
    )
    closure.resolve(["root-nar"])
    closure.import_roots([root])
    closure.export([root], work / "root.export")
    if closure.initially_absent != [root]:
        raise RuntimeError("self-reference root was not initially absent")


if __name__ == "__main__":
    main()
