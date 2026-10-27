"""Requires Cargo and Bazel comparisons to use identical first-party inputs.

The inventory comes from the actual Bazel compilation. Only its selected Rust
and API protocol inputs participate; unrelated checkout files do not establish
compiler parity. This check does not compare generated compiler outputs.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath


def compare(inventory, bazel_root, cargo_root):
    """Hashes selected first-party inputs after requiring exact source equality."""
    if inventory.get("schema_version") != 1:
        raise ValueError("unsupported compiler source inventory")
    names = inventory.get("source_files")
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise ValueError("compiler source inventory must contain file names")
    if len(names) != len(set(names)):
        raise ValueError("duplicate compiler source input")

    checked = {}
    for name in sorted(names):
        path = PurePosixPath(name)
        if (
            not name or path.is_absolute() or ".." in path.parts
            or path.as_posix() != name or "\\" in name
        ):
            raise ValueError("invalid compiler source input: " + name)
        if not (
            name.startswith("crates/") and name.endswith(".rs")
            or name.startswith("api/") and name.endswith(".proto")
        ):
            continue

        contents = []
        for root in [bazel_root, cargo_root]:
            source = root / name
            if not source.resolve().is_relative_to(root.resolve()):
                raise ValueError("compiler source escapes declared root: " + name)
            if not source.is_file():
                raise ValueError("missing compiler source input: " + name)
            contents.append(source.read_bytes())
        if contents[0] != contents[1]:
            raise ValueError("Cargo/Bazel compiler source bytes differ: " + name)
        checked[name] = hashlib.sha256(contents[0]).hexdigest()

    if not checked:
        raise ValueError("no selected first-party compiler inputs")
    return {"schema_version": 1, "sources_sha256": checked}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--bazel-root", type=Path, required=True)
    parser.add_argument("--cargo-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    result = compare(
        json.loads(options.inventory.read_text()), options.bazel_root, options.cargo_root,
    )
    options.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
