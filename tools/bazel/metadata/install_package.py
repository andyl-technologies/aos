"""Installs a selected exported package after checking its identity and bytes."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil


def install(build, label, name, version, output):
    """Checks package identity, artifact paths, modes, and export digests."""
    index = json.loads((build / "packages/index.json").read_text())
    identifier = index[label]
    if identifier != hashlib.sha256(label.encode()).hexdigest():
        raise ValueError("invalid package index identity")
    package = build / "packages" / identifier
    manifest = package / "manifest.json"
    metadata = json.loads(manifest.read_text())
    if (metadata["schema_version"], metadata["label"], metadata["name"], metadata["version"]) != (1, label, name, version):
        raise ValueError("Bazel package identity does not match Nix package metadata")
    destinations = set()
    for entry in metadata["artifacts"]:
        destination = entry["destination"]
        path = PurePosixPath(destination)
        if (not destination or path.is_absolute() or "\\" in destination
                or any(part in {"", ".", ".."} for part in destination.split("/"))):
            raise ValueError(f"invalid install destination: {destination}")
        if destination in destinations:
            raise ValueError(f"duplicate install destination: {destination}")
        destinations.add(destination)
        if entry["mode"] not in {"0644", "0755"}:
            raise ValueError("unsupported artifact mode")
        source = package / "files" / destination
        with source.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != entry["sha256"]:
            raise ValueError(f"artifact digest mismatch: {destination}")
        target = output / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(int(entry["mode"], 8))
    evidence = output / "nix-support"
    evidence.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(manifest, evidence / "bazel-package.json")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--label", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    install(options.build, options.label, options.name, options.version, options.output)


if __name__ == "__main__":
    main()
