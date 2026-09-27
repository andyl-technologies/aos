"""Remove downloaded compiled artifacts from workerd's fetched Bazel graph.

The fetched repositories contain upstream test fixtures and toolchain archives
that are outside the selected workerd target. The offline build supplies its
executables from AOS packages after this graph has been copied into the build.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import tarfile
from collections import Counter
from pathlib import Path, PurePosixPath


COMPILED_SUFFIXES = {
    ".a", ".bin", ".class", ".dll", ".dylib", ".exe", ".jar",
    ".lib", ".node", ".o", ".obj", ".pyc", ".pyo", ".so", ".wasm",
}
ARCHIVE_SUFFIXES = {".7z", ".bz2", ".gz", ".tar", ".tgz", ".whl", ".xz", ".zip"}
SOURCE_NPM_ARCHIVES = {
    "aspect_rules_js++npm+npm__undici-types__7.16.0/package.tgz": "package",
    "aspect_rules_js++npm+npm__capnp-es__0.0.14_typescript_5.9.3/package.tgz": "package",
    "aspect_rules_js++npm+npm__at_types_node__25.2.1/package.tgz": "node",
    "aspect_rules_js++npm+npm__eslint__9.39.2/package.tgz": "package",
}
SOURCE_NPM_SUFFIXES = {"", ".js", ".json", ".md", ".mjs", ".mts", ".ts"}
COMPILED_HEADERS = (
    b"\x7fELF",
    b"\x00asm",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"BC\xc0\xde",
    b"\xde\xc0\x17\x0b",
    b"MZ",
    b"!<arch>\n",
    b"PK\x03\x04",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"\x28\xb5\x2f\xfd",
    bytes.fromhex("feedface"),
    bytes.fromhex("cefaedfe"),
    bytes.fromhex("feedfacf"),
    bytes.fromhex("cffaedfe"),
)


def validate_source_npm_archive(path: Path, expected_root: str) -> None:
    """Reject compiled payloads and unsafe entries in a pinned source package."""
    total_size = 0
    with tarfile.open(path, "r:gz") as archive:
        for entry in archive:
            member = PurePosixPath(entry.name)
            if (
                not member.parts
                or member.is_absolute()
                or ".." in member.parts
                or member.parts[0] != expected_root
            ):
                raise ValueError(f"Unsafe npm archive entry: {path}: {entry.name}")
            if entry.isdir():
                continue
            if not entry.isfile() or member.suffix.lower() not in SOURCE_NPM_SUFFIXES:
                raise ValueError(f"Non-source npm archive entry: {path}: {entry.name}")

            total_size += entry.size
            if total_size > 64 * 1024 * 1024:
                raise ValueError(f"Oversized npm source archive: {path}")
            payload = archive.extractfile(entry)
            if payload is None:
                raise ValueError(f"Missing npm archive payload: {path}: {entry.name}")
            with payload:
                data = payload.read()
            if b"\0" in data or data.startswith(COMPILED_HEADERS):
                raise ValueError(f"Compiled npm archive payload: {path}: {entry.name}")
            data.decode("utf-8")


def retain_registry_metadata(external: Path) -> int:
    """Keep only verified text registry files needed for offline Bzlmod analysis."""
    lockfile = external / "aos-module-lock.json"
    lock = json.loads(lockfile.read_text())
    registry_hashes = lock.get("registryFileHashes")
    if not isinstance(registry_hashes, dict) or not registry_hashes:
        raise ValueError(f"Missing registry file hashes in {lockfile}")

    allowed_hashes = set(registry_hashes.values())
    if any(
        not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        for digest in allowed_hashes
    ):
        raise ValueError(f"Invalid registry file hash in {lockfile}")

    cache = external / "repository_cache"
    if not cache.is_dir() or cache.is_symlink():
        raise ValueError(f"Expected a repository cache directory: {cache}")

    content = cache / "content_addressable"
    if not content.is_dir() or content.is_symlink():
        raise ValueError(f"Expected content-addressed repository cache: {content}")

    removed = 0
    retained_hashes = set()
    for entry in content.iterdir():
        if entry.name != "sha256":
            shutil.rmtree(entry)
            removed += 1
            continue

        if not entry.is_dir() or entry.is_symlink():
            raise ValueError(f"Expected SHA-256 cache directory: {entry}")
        for digest in entry.iterdir():
            if digest.name not in allowed_hashes:
                shutil.rmtree(digest)
                removed += 1
                continue

            if not digest.is_dir() or digest.is_symlink():
                raise ValueError(f"Expected registry metadata directory: {digest}")
            if {entry.name for entry in digest.iterdir()} != {"file"}:
                raise ValueError(f"Unexpected registry cache entry: {digest}")
            payload = digest / "file"
            if not payload.is_file() or payload.is_symlink():
                raise ValueError(f"Expected registry metadata file: {payload}")
            data = payload.read_bytes()
            if hashlib.sha256(data).hexdigest() != digest.name or b"\0" in data:
                raise ValueError(f"Invalid registry metadata: {payload}")
            data.decode("utf-8")
            retained_hashes.add(digest.name)

    if retained_hashes != allowed_hashes:
        raise ValueError(f"Missing registry metadata: {allowed_hashes - retained_hashes}")

    for entry in cache.iterdir():
        if entry.name != "content_addressable":
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry)
            else:
                entry.unlink()
            removed += 1

    return removed


def strip_downloads(external: Path) -> Counter[str]:
    """Remove cached archives and executable payloads from the source graph."""
    removed: Counter[str] = Counter()
    removed["cache"] = retain_registry_metadata(external)

    pending = [external]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue

                path = Path(entry.path)
                suffix = path.suffix.lower()
                source_archive = SOURCE_NPM_ARCHIVES.get(path.relative_to(external).as_posix())
                if source_archive is not None:
                    validate_source_npm_archive(path, source_archive)
                    continue
                if suffix in COMPILED_SUFFIXES or suffix in ARCHIVE_SUFFIXES:
                    path.unlink()
                    removed[suffix] += 1
                    continue

                with path.open("rb") as source:
                    header = source.read(8)
                if header.startswith(COMPILED_HEADERS):
                    path.unlink()
                    removed["signature"] += 1

    return removed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("external", type=Path)
    arguments = parser.parse_args()

    external = arguments.external
    if not external.is_dir() or external.is_symlink():
        parser.error(f"Expected an extracted Bazel dependency directory: {external}")

    removed = strip_downloads(external)
    for kind, count in sorted(removed.items()):
        print(f"Removed {count} downloaded {kind} payloads")


if __name__ == "__main__":
    main()
