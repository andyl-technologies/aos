"""Materializes an exact declared source audit as ordinary, immutable-input files.

Bazel runfiles are often symlinks. Repository scanners that deliberately skip
links need a generated tree of regular files to inspect the complete source set.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath


def materialize(source, manifest, output):
    """Copies every inventoried input after verifying its name and bytes."""
    value = json.loads(manifest.read_text())
    if set(value) != {"schema_version", "files"} or value["schema_version"] != 1:
        raise ValueError("unsupported repository source manifest")
    files = value["files"]
    if not isinstance(files, dict) or not files:
        raise ValueError("repository source manifest must contain files")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("repository source output must be empty")
    for name, expected in sorted(files.items()):
        relative = PurePosixPath(name)
        if (relative.is_absolute() or name != relative.as_posix()
                or any(part in {"", ".", ".."} for part in name.split("/"))):
            raise ValueError(f"ambiguous repository source path: {name}")
        if set(expected) != {"sha256", "size"}:
            raise ValueError(f"invalid repository source identity: {name}")
        data = (source / name).read_bytes()
        if len(data) != expected["size"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
            raise ValueError(f"repository source content differs: {name}")
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    materialize(options.source, options.manifest, options.output)
