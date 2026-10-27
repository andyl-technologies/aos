"""Exports release package identities from Bazel's source ownership catalog.

The checked metadata lets Nix evaluate release manifests without invoking Bazel
or reading first-party Cargo manifests. Source hashes reject stale declarations;
the qualification check compares this export with a freshly built Bazel catalog.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath


DECLARATIONS = [
    "crates/BUILD.bazel",
    "pkgs/tools/crucible/_packages.nix",
    "tools/bazel/rules/rust_package.bzl",
    "tools/bazel/rules/source_package.bzl",
    "tools/bazel/metadata/export_release_packages.py",
]


def export(root, catalog, selection):
    """Requires unique selected identities and binds their current BUILD inputs."""
    if catalog.get("schema_version") != 1:
        raise ValueError("unsupported Bazel source catalog schema")
    if not isinstance(selection, list) or not selection or any(not isinstance(name, str) or not name for name in selection):
        raise ValueError("release package selection must contain nonempty names")
    if len(set(selection)) != len(selection):
        raise ValueError("duplicate release package selection")

    packages = {}
    for package in catalog["packages"]:
        name = package["name"]
        if name in packages:
            raise ValueError("duplicate Bazel source package identity: " + name)
        packages[name] = package
    if set(selection) - packages.keys():
        raise ValueError("Bazel source catalog omitted selected release packages")

    selected = {}
    sources = set(DECLARATIONS)
    directories = set()
    for name in sorted(selection):
        package = packages[name]
        directory = package["directory"]
        path = PurePosixPath(directory)
        if (not directory.startswith("crates/") or path.is_absolute()
                or path.as_posix() != directory or ".." in path.parts or "\\" in directory):
            raise ValueError("invalid release package directory: " + directory)
        if directory in directories:
            raise ValueError("duplicate release package directory")
        directories.add(directory)
        selected[name] = {key: package[key] for key in ["directory", "version", "edition", "license", "license_domain"]}
        if any(not isinstance(value, str) or not value for value in selected[name].values()):
            raise ValueError("incomplete release package metadata: " + name)
        sources.add(directory + "/BUILD.bazel")

    return {
        "schema_version": 1,
        "packages": selected,
        "declaration_sha256": {
            source: hashlib.sha256((root / source).read_bytes()).hexdigest()
            for source in sorted(sources)
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["root", "catalog", "selection", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    result = export(options.root, json.loads(options.catalog.read_text()), json.loads(options.selection.read_text()))
    options.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
