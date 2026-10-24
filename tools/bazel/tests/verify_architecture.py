"""Compares exported Bazel architecture with the temporary Cargo source oracle."""

import argparse
import hashlib
import json
from pathlib import Path
import tomllib


def production_dependencies(manifest, inherited):
    """Unions normal/build dependencies across every Cargo target declaration."""
    result = set()
    for section in ["dependencies", "build-dependencies"]:
        for alias, declaration in manifest.get(section, {}).items():
            if isinstance(declaration, dict) and declaration.get("workspace"):
                declaration = inherited[alias]
            result.add(declaration.get("package", alias) if isinstance(declaration, dict) else alias)
    for target in manifest.get("target", {}).values():
        result.update(production_dependencies(target, inherited))
    return result


def verify(graph, directory):
    """Requires complete ownership and exact edges for every modeled package."""
    if graph["schema_version"] != 1:
        raise ValueError("unsupported architecture schema")
    packages = {}
    for package in graph["packages"]:
        if package["name"] in packages:
            raise ValueError("duplicate architecture package")
        packages[package["name"]] = package
    workspace = tomllib.loads((directory / "Cargo.toml").read_text())["workspace"]
    expected = {}
    for member in workspace["members"]:
        manifest = tomllib.loads((directory / member / "Cargo.toml").read_text())
        package = manifest["package"]
        name = package["name"]
        if name in expected:
            raise ValueError("duplicate Cargo package")
        identity = {}
        for field in ["version", "edition", "license"]:
            value = package[field]
            identity[field] = workspace["package"][field] if isinstance(value, dict) and value.get("workspace") else value
        expected[name] = {"identity": identity, "directory": "crates/" + member,
                          "dependencies": production_dependencies(manifest, workspace["dependencies"])}
    if packages.keys() != expected.keys():
        raise ValueError("Cargo/Bazel source package inventories differ")

    modeled = {}
    unmodeled = []
    for name, oracle in sorted(expected.items()):
        package = packages[name]
        if any(package[field] != value for field, value in oracle["identity"].items()) or package["directory"] != oracle["directory"]:
            raise ValueError("Cargo/Bazel source identity differs: " + name)
        dependencies = package["production_dependencies"]
        if dependencies is None:
            if package["production_targets"]:
                raise ValueError("unmodeled architecture package has production targets")
            unmodeled.append(name)
            continue
        if not package["production_targets"] or len(dependencies) != len(set(dependencies)) or set(dependencies) != oracle["dependencies"]:
            raise ValueError("Cargo/Bazel production dependencies differ: " + name)
        modeled[name] = dependencies
    if not modeled:
        raise ValueError("architecture comparison requires modeled production packages")
    return {"schema_version": 1, "status": "PASS: package ownership and modeled production dependency unions match",
            "source_packages": len(packages), "modeled_packages": len(modeled),
            "unmodeled_packages": unmodeled, "production_dependencies": modeled}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--architecture", type=Path, required=True)
    parser.add_argument("--workspace-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    result = verify(json.loads(options.architecture.read_text()), options.workspace_directory)
    result["architecture_sha256"] = hashlib.sha256(options.architecture.read_bytes()).hexdigest()
    options.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
