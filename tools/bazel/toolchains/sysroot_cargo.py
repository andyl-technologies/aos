"""Serves immutable upstream Rust-library metadata without executing Cargo.

The toolchain prepares these records offline from its installed, vendored Rust
sources. Editor requests for that exact library are the only accepted commands;
first-party discovery, compilation, updates and arbitrary manifests fail.
"""

import argparse
import json
from pathlib import Path
import sys


def metadata_request(arguments):
    """Validates one supported analyzer request against the immutable source root."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata-directory", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("command", choices=["metadata"])
    parser.add_argument("--manifest-path", type=Path, required=True)
    parser.add_argument("--format-version", choices=["1"], required=True)
    parser.add_argument("--filter-platform", required=True, choices=[
        "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown",
    ])
    parser.add_argument("--locked", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("-Zlockfile-path", action="store_true")
    parser.add_argument("-Zunstable-options", action="store_true")
    options = parser.parse_args(arguments)
    if options.manifest_path.resolve(strict=True) != (options.library / "Cargo.toml").resolve(strict=True):
        raise ValueError("Cargo execution is disabled in first-party Bazel builds; only prepared Rust-library editor metadata is available")
    return options


def metadata_file(arguments):
    """Returns the prepared record for a validated analyzer request."""
    options = metadata_request(arguments)
    return options.metadata_directory / (options.filter_platform + ".json")


def metadata(arguments):
    """Returns prepared metadata with paths rooted at the requested source alias."""
    options = metadata_request(arguments)
    contents = (options.metadata_directory / (options.filter_platform + ".json")).read_bytes()
    document = json.loads(contents)
    original = document["workspace_root"]
    requested = str(options.manifest_path.absolute().parent)
    if original == requested:
        return contents

    # rust-analyzer's VFS uses the supplied sysroot path. Canonical source paths
    # would make its file roots disagree when an adapter extends the toolchain.
    def rebase(value):
        if isinstance(value, str):
            return value.replace(original, requested)
        if isinstance(value, list):
            return [rebase(item) for item in value]
        if isinstance(value, dict):
            return {key: rebase(item) for key, item in value.items()}
        return value

    return (json.dumps(rebase(document)) + "\n").encode()


def main():
    try:
        sys.stdout.buffer.write(metadata(sys.argv[1:]))
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
