"""Exports only completed Bazel package manifests and their declared artifacts.

Build-event file URIs locate current outputs without assuming a configuration
directory or searching bazel-bin. Installation paths are checked again here at
the Nix trust boundary, independently of Starlark analysis.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
from urllib.parse import unquote, urlparse


def relative_path(value):
    """Rejects absolute paths, traversal, ambiguous components, and backslashes."""
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"invalid artifact path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError(f"invalid artifact path: {value!r}")
    return path


def completed_manifests(events):
    """Finds manifests reachable from successful requested target output groups."""
    named_sets = {}
    roots = []
    for event in events:
        if "namedSet" in event.get("id", {}):
            named_sets[event["id"]["namedSet"]["id"]] = event["namedSetOfFiles"]
        if "targetCompleted" in event.get("id", {}):
            completed = event.get("completed", {})
            if not completed.get("success"):
                raise ValueError("cannot export an unsuccessful Bazel target")
            for group in completed.get("outputGroup", []):
                if group["name"] in {"default", "aos_package"}:
                    roots.extend(item["id"] for item in group.get("fileSets", []))
    visited = set()
    manifests = set()
    while roots:
        identifier = roots.pop()
        if identifier in visited:
            continue
        visited.add(identifier)
        files = named_sets[identifier]
        roots.extend(item["id"] for item in files.get("fileSets", []))
        for item in files.get("files", []):
            if item.get("name", "").endswith(".aos-package.json"):
                uri = urlparse(item["uri"])
                if uri.scheme != "file" or uri.netloc:
                    raise ValueError("package export requires a local Bazel output URI")
                manifests.add(Path(unquote(uri.path)))
    return sorted(manifests)


def export_manifest(manifest, output):
    """Validates and copies one package, recording digests of installed bytes."""
    metadata = json.loads(manifest.read_text())
    if metadata.get("schema_version") != 1:
        raise ValueError("unsupported package manifest version")
    for key in ["label", "name", "version", "license", "license_domain"]:
        if not isinstance(metadata.get(key), str) or not metadata[key]:
            raise ValueError(f"missing package metadata: {key}")
    identifier = hashlib.sha256(metadata["label"].encode()).hexdigest()
    package = output / identifier
    package.mkdir(parents=True)
    destinations = set()
    artifacts = []
    entries = []
    for entry in metadata["artifacts"]:
        destination = relative_path(entry["destination"])
        source = manifest.parent / relative_path(entry["source"])
        kind = entry.get("kind", "file")
        if kind == "file":
            entries.append((entry, source))
        elif kind == "directory":
            if not source.is_dir():
                raise ValueError(f"missing or invalid package directory: {source}")
            # Package rules alias declared tree artifacts just as they alias
            # regular files. Inspect the completed tree, never sandbox input links.
            source = source.resolve(strict=True)
            for path in sorted(source.rglob("*")):
                if path.is_symlink() or not (path.is_file() or path.is_dir()):
                    raise ValueError(f"nonregular package directory entry: {path}")
                if path.is_file():
                    entries.append(({
                        "destination": str(destination / path.relative_to(source)),
                        "mode": entry["mode"],
                    }, path))
        else:
            raise ValueError(f"unsupported package artifact kind: {kind}")
    for entry, source in entries:
        destination = relative_path(entry["destination"])
        if any(destination == previous or destination in previous.parents or previous in destination.parents
               for previous in map(PurePosixPath, destinations)):
            raise ValueError(f"overlapping package destination: {destination}")
        destinations.add(str(destination))
        mode = entry["mode"]
        if mode not in {"0644", "0755"}:
            raise ValueError(f"unsupported artifact mode: {mode}")
        if not source.is_file():
            raise ValueError(f"missing package artifact: {source}")
        target = package / "files" / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(int(mode, 8))
        with target.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        artifacts.append({
            "destination": str(destination), "mode": mode,
            "sha256": digest,
        })
    metadata["artifacts"] = artifacts
    (package / "manifest.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return metadata["label"], identifier


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    events = [json.loads(line) for line in options.events.read_text().splitlines() if line]
    options.output.mkdir(parents=True, exist_ok=True)
    index = {}
    for manifest in completed_manifests(events):
        label, identifier = export_manifest(manifest, options.output)
        if label in index:
            raise ValueError(f"multiple configurations export the same package label: {label}")
        index[label] = identifier
    (options.output / "index.json").write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
