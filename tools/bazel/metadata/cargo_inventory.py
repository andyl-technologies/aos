"""Exports the Cargo oracle used to qualify the first-party Bazel migration.

This records declared targets and features, not resolved feature unification.
Cargo metadata is run offline, without compilation or dependency resolution.
Resolved family inventories and performance evidence remain separate gates.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib


EXCLUDED = {".git", ".worktrees", ".claude", ".direnv", "target", "node_modules"}


def source_files(root):
    """Walks checked-in source locations without following output symlinks."""
    for directory, subdirectories, files in root.walk(follow_symlinks=False):
        subdirectories[:] = sorted(
            name for name in subdirectories
            if name not in EXCLUDED and not name.startswith("bazel-")
        )
        for name in sorted(files):
            path = directory / name
            if not path.is_symlink():
                yield path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root, cargo):
    """Collects every first-party workspace and its declared build consumers."""
    files = list(source_files(root / "crates")) + list(source_files(root / "tools"))
    manifests = [path for path in files if path.name == "Cargo.toml"]
    workspaces = []
    members = set()
    contracts = {}

    for manifest in manifests:
        contents = tomllib.loads(manifest.read_text())
        if "workspace" not in contents:
            continue

        command = [
            cargo, "metadata", "--manifest-path", str(manifest),
            "--no-deps", "--offline", "--locked", "--format-version", "1",
        ]
        metadata = json.loads(subprocess.check_output(command, text=True))
        packages = []

        for package in sorted(metadata["packages"], key=lambda item: item["name"]):
            package_manifest = Path(package["manifest_path"])
            manifest_path = package_manifest.relative_to(root).as_posix()
            members.add(manifest_path)
            targets = []
            for target in sorted(package["targets"], key=lambda item: (item["kind"], item["name"])):
                targets.append({
                    key: target[key]
                    for key in [
                        "name", "kind", "crate_types", "edition", "doc", "doctest", "test",
                    ]
                } | {
                    "source": Path(target["src_path"]).relative_to(root).as_posix(),
                    "required_features": target.get("required-features", []),
                })

            packages.append({
                "name": package["name"],
                "version": package["version"],
                "manifest": manifest_path,
                "license": package["license"],
                "links": package.get("links"),
                "features": package["features"],
                "metadata": package["metadata"],
                "targets": targets,
            })
            contracts[manifest_path] = digest(package_manifest)

        lock = manifest.with_name("Cargo.lock")
        if not lock.is_file():
            raise ValueError(f"workspace has no lock: {manifest.relative_to(root)}")
        contracts[manifest.relative_to(root).as_posix()] = digest(manifest)
        contracts[lock.relative_to(root).as_posix()] = digest(lock)
        workspaces.append({
            "manifest": manifest.relative_to(root).as_posix(),
            "packages": packages,
        })

    unowned = sorted(path.relative_to(root).as_posix() for path in manifests
                    if path.relative_to(root).as_posix() not in members
                    and "workspace" not in tomllib.loads(path.read_text()))
    if unowned:
        raise ValueError(f"unowned first-party manifests: {unowned}")

    consumers = []
    for directory in [root / "pkgs", root / "tests", root / "stdenv"]:
        for path in source_files(directory):
            if path.suffix != ".nix":
                continue
            contents = path.read_text()
            interfaces = [name for name in [
                "mkAosCargoPackage", "mkCargoArtifacts", "mkCargoNextestCheck",
                "cargoWorkspaceMembers", "crates/Cargo.toml",
            ] if name in contents]
            if interfaces:
                consumers.append({"path": path.relative_to(root).as_posix(), "interfaces": interfaces})

    nextest = root / ".config/nextest.toml"
    if nextest.is_file():
        contracts[".config/nextest.toml"] = digest(nextest)

    return {
        "schema": 1,
        "feature_scope": "declared-only; resolved build-family features require separate evidence",
        "contracts": dict(sorted(contracts.items())),
        "workspaces": sorted(workspaces, key=lambda item: item["manifest"]),
        "nix_consumers": sorted(consumers, key=lambda item: item["path"]),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--cargo", required=True, help="AOS-built Cargo executable")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    try:
        contents = json.dumps(inventory(args.root.resolve(), args.cargo), indent=2, sort_keys=True) + "\n"
        if args.check:
            if args.output.read_text() != contents:
                raise ValueError("Cargo migration inventory is stale; regenerate it before conversion")
        else:
            args.output.write_text(contents)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"cargo inventory: {error}\n")


if __name__ == "__main__":
    main()
