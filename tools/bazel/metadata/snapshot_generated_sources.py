"""Hashes the exact regular-file inventory of a declared generator output tree."""

import argparse
import hashlib
import json
from pathlib import Path


def snapshot(directory, expected):
    """Returns the exact generated file inventory and content digests."""
    if len(expected) != len(set(expected)):
        raise ValueError("duplicate expected generated file")
    files = sorted(directory.rglob("*"))
    # Bazel materializes declared tree inputs as symlinks to their output files.
    # Read those bytes, while rejecting directory links and special files.
    if any(not (path.is_file() or (path.is_dir() and not path.is_symlink())) for path in files):
        raise ValueError("generated source tree contains a directory link or special file")
    actual = {path.relative_to(directory).as_posix(): path for path in files if path.is_file()}
    if set(actual) != set(expected):
        raise ValueError(f"generated source inventory differs: {set(actual) ^ set(expected)}")
    return {
        name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size}
        for name, path in sorted(actual.items())
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--file", action="append", required=True)
    options = parser.parse_args()
    options.output.write_text(json.dumps(snapshot(options.directory, options.file), indent=2, sort_keys=True) + "\n")
