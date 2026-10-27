"""Checks source gates against Bazel's exported production package dependencies.

Requirements name packages rather than rule labels, so aliases and every
platform/feature selector branch retain the exporter's dependency semantics.
The package summary must agree with its owned production targets; absent or
unmodeled packages cannot satisfy either positive or negative requirements.
"""

import argparse
import hashlib
import json
from pathlib import Path


PRODUCTION_KINDS = {"rust_library", "rust_binary", "rust_proc_macro", "rust_shared_library", "rust_static_library"}


def names(value, context):
    """Rejects malformed, repeated, or unordered package-name lists."""
    if (not isinstance(value, list)
            or any(not isinstance(name, str) or not name for name in value)
            or value != sorted(set(value))):
        raise ValueError(f"{context}: expected unique sorted names")
    return set(value)


def verify(graph, requirements):
    """Checks every requested production relationship without a Cargo fallback."""
    if not isinstance(graph, dict) or graph.get("schema_version") != 1:
        raise ValueError("unsupported Bazel package graph")
    if not isinstance(graph.get("packages"), list):
        raise ValueError("missing Bazel package catalogue")
    packages = {}
    for package in graph["packages"]:
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            raise ValueError("invalid Bazel package identity")
        name = package["name"]
        if not name or name in packages:
            raise ValueError("duplicate or empty Bazel package identity")
        packages[name] = package

    if (not isinstance(requirements, dict) or requirements.get("schema_version") != 1
            or set(requirements) != {"schema_version", "packages"}
            or not isinstance(requirements["packages"], dict) or not requirements["packages"]):
        raise ValueError("invalid package requirements")
    target_dependencies = graph.get("target_dependencies")
    dependency_targets = graph.get("dependency_targets")
    compilations = graph.get("compilation_targets")
    if (not isinstance(target_dependencies, dict) or not isinstance(dependency_targets, dict)
            or not isinstance(compilations, dict)
            or any(not isinstance(target, dict) for target in compilations.values())):
        raise ValueError("missing Bazel production target dependencies")

    checked = {}
    for name, requirement in sorted(requirements["packages"].items()):
        if not isinstance(requirement, dict) or set(requirement) != {"required", "forbidden"}:
            raise ValueError(f"{name}: invalid dependency requirement")
        required = names(requirement["required"], name + " required dependencies")
        forbidden = names(requirement["forbidden"], name + " forbidden dependencies")
        if required & forbidden:
            raise ValueError(f"{name}: contradictory dependency requirement")
        if name not in packages:
            raise ValueError(f"{name}: missing Bazel source package")
        package = packages[name]
        dependencies = names(package.get("production_dependencies"), name + " production dependencies")
        targets = names(package.get("production_targets"), name + " production targets")
        if not targets:
            raise ValueError(f"{name}: no modeled production compilation")

        owned_targets = {label for label, target in compilations.items()
                         if target.get("package") == name and target.get("test_only") is False
                         and target.get("kind") in PRODUCTION_KINDS}
        if targets != owned_targets:
            raise ValueError(f"{name}: production target ownership differs")
        actual = set()
        for label in sorted(targets):
            target = dependency_targets.get(label)
            edges = target_dependencies.get(label)
            if (not isinstance(target, dict) or target.get("package") != name
                    or target.get("test_only") is not False or target.get("kind") not in PRODUCTION_KINDS
                    or not isinstance(edges, list) or target.get("dependencies") != edges):
                raise ValueError(f"{name}: inconsistent production target dependencies: {label}")
            for edge in edges:
                if (not isinstance(edge, dict) or edge.get("attribute") not in {"deps", "proc_macro_deps"}
                        or not isinstance(edge.get("label"), str)):
                    raise ValueError(f"{name}: malformed production dependency: {label}")
                actual.update(names(edge.get("packages"), label + " dependency packages"))
        actual.discard(name)
        if dependencies != actual:
            raise ValueError(f"{name}: production package summary differs from target dependencies")
        missing, banned = required - dependencies, forbidden & dependencies
        if missing:
            raise ValueError(f"{name}: missing required production dependencies: {', '.join(sorted(missing))}")
        if banned:
            raise ValueError(f"{name}: forbidden production dependencies: {', '.join(sorted(banned))}")
        checked[name] = {"production_targets": sorted(targets), "production_dependencies": sorted(dependencies),
                         "required": sorted(required), "forbidden": sorted(forbidden)}
    return {"schema_version": 1, "status": "PASS", "packages": checked}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", required=True, type=Path)
    parser.add_argument("--requirements", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()

    result = verify(json.loads(arguments.graph.read_text()), json.loads(arguments.requirements.read_text()))
    result["inputs_sha256"] = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in (("graph", arguments.graph), ("requirements", arguments.requirements))
    }
    arguments.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
