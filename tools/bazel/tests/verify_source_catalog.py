"""Checks declared Bazel source ownership against the migration oracle."""

import argparse
import json
from pathlib import Path, PurePosixPath


def relative_path(value):
    """Rejects noncanonical paths before consulting the filesystem."""
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or path.as_posix() != value
        or ".." in path.parts
        or "\\" in value
    ):
        raise ValueError(f"invalid source path: {value!r}")
    return path


def owned_sources(root, directory):
    """Mirrors Bazel package boundaries when discovering Rust audit inputs."""
    base = root / directory
    result = []
    for source in base.rglob("*.rs"):
        if not source.is_file():
            continue
        ancestors = [base / parent for parent in source.relative_to(base).parents if parent != Path(".")]
        if any((parent / build).is_file() for parent in ancestors for build in ["BUILD.bazel", "BUILD"]):
            continue
        result.append(source.relative_to(root).as_posix())
    return sorted(result)


def validate_catalog(root, catalog, oracle_packages):
    """Requires exact identities and complete, unique owned source sets."""
    if catalog.get("schema_version") != 1:
        raise ValueError("unsupported source catalog schema")
    packages = catalog["packages"]
    expected = {package["name"]: package for package in oracle_packages}
    names = [package["name"] for package in packages]
    if names != sorted(set(names)) or set(names) != set(expected):
        raise ValueError("source catalog package names differ from the oracle")

    directories = set()
    all_sources = set()
    for package in packages:
        oracle = expected[package["name"]]
        directory = relative_path(package["directory"]).as_posix()
        if directory in directories:
            raise ValueError("duplicate source package directory")
        directories.add(directory)
        identity = {
            "directory": str(PurePosixPath(oracle["manifest"]).parent),
            "version": oracle["version"],
            "license": oracle["license"],
        }
        if any(package[key] != value for key, value in identity.items()):
            raise ValueError(f"source package identity differs: {package['name']}")
        if {target["edition"] for target in oracle["targets"]} != {package["edition"]}:
            raise ValueError(f"source package edition differs: {package['name']}")
        domains = {"gpl-qemu"} if oracle["license"] == "GPL-2.0-only" else {"apache-host", "permissive-protocol"}
        if package["license_domain"] not in domains:
            raise ValueError(f"source package license domain differs: {package['name']}")

        sources = package["sources"]
        if not sources or sources != sorted(set(sources)):
            raise ValueError("source package files must be nonempty, unique, and sorted")
        for source in sources:
            path = relative_path(source)
            if not path.is_relative_to(directory) or path.suffix != ".rs":
                raise ValueError(f"source file escapes package ownership: {source}")
            if not (root / source).resolve().is_relative_to(root.resolve()):
                raise ValueError(f"source file escapes workspace: {source}")
            if source in all_sources:
                raise ValueError(f"source file has multiple owners: {source}")
            all_sources.add(source)
        if sources != owned_sources(root, directory):
            raise ValueError(f"source package coverage differs: {package['name']}")
    return {"packages": len(packages), "sources": len(all_sources)}


def validate_metadata_only(execution):
    """Requires metadata generation to execute no external build tools."""
    # Catalogs use only Bazel's built-in write/symlink actions. Any spawn,
    # including a compiler or manifest-reading generator, changes this contract.
    if execution.strip():
        raise ValueError("source catalog unexpectedly executed a build tool")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["root", "oracle", "repository", "crates", "execution", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    workspaces = json.loads(args.oracle.read_text())["workspaces"]
    repository = validate_catalog(
        args.root,
        json.loads(args.repository.read_text()),
        [package for workspace in workspaces for package in workspace["packages"]],
    )
    crates = validate_catalog(
        args.root,
        json.loads(args.crates.read_text()),
        next(workspace["packages"] for workspace in workspaces if workspace["manifest"] == "crates/Cargo.toml"),
    )
    validate_metadata_only(args.execution.read_text())
    args.output.write_text(json.dumps({
        "schema_version": 1,
        "repository": repository,
        "crates": crates,
        "external_build_actions": 0,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
