"""Exports production Rust package edges from Bazel's unconfigured query graph.

The structured query retains every selector branch. Only explicit Rust
compilation dependency attributes contribute package edges; test-only rules,
runfiles, generators' tool inputs, and implicit toolchains are excluded.
Uncompiled source packages remain explicitly unmodeled. A separate dependency
view retains test and build-script compilation edges for repository audits;
those edges never contribute to the production package graph.
"""

import argparse
import hashlib
import json
from pathlib import Path


RUST_RULES = {"rust_library", "rust_binary", "rust_proc_macro", "rust_shared_library", "rust_static_library"}
DEPENDENCY_RULES = RUST_RULES | {"rust_test", "cargo_build_script", "rust_doc", "rust_doc_test", "rust_clippy"}
PROFILE_RULES = {
    name + "_profile_required" for name in [
        "device", "store", "guest", "engine", "quota", "session", "control",
        "qemu_host", "store_s3", "daemon", "crucible_cli", "formats",
    ]
}


def attribute_values(attribute, expected):
    """Unions typed selector values without interpreting condition labels as edges."""
    if attribute["type"] == "SELECTOR_LIST":
        selector = attribute["selectorList"]
        if selector["type"] != expected:
            raise ValueError("unexpected selector value type")
        return [value for element in selector["elements"] for entry in element["entries"]
                for value in attribute_values({**entry, "type": expected}, expected)]
    if attribute["type"] != expected:
        raise ValueError("unexpected architecture attribute type")
    if expected in {"LABEL_LIST", "STRING_LIST"}:
        return attribute.get("stringListValue", [])
    if expected in {"LABEL", "STRING"}:
        return [attribute["stringValue"]] if "stringValue" in attribute else []
    raise ValueError("unsupported architecture attribute type: " + expected)


def attributes(rule):
    """Indexes attributes while rejecting duplicate entries in query output."""
    result = {}
    for attribute in rule["attribute"]:
        if attribute["name"] in result:
            raise ValueError("duplicate architecture rule attribute")
        result[attribute["name"]] = attribute
    return result


def compilation_target(label, rule, owner):
    """Retains artifact identity for every Rust root, including test-only copies.

    Feature variants remain separate records. Consumers decide which artifacts
    form a product surface; the exporter never hides examples or generators by
    guessing from their target names.
    """
    attrs = attributes(rule)
    if attrs["testonly"]["type"] != "BOOLEAN":
        raise ValueError("architecture test-only selection must not be configurable")
    roots = attribute_values(attrs["crate_root"], "LABEL")
    if not roots:
        # rules_rust accepts a single Rust source without an explicit crate_root.
        # Ambiguous implicit roots must be declared before metadata can own them.
        roots = [source for source in attribute_values(attrs["srcs"], "LABEL_LIST") if source.endswith(".rs")]
        if len(roots) != 1:
            raise ValueError("architecture artifact requires an unambiguous crate root: " + label)
    prefix = "//" + owner["directory"] + ":"
    relative_roots = []
    for root in roots:
        if not root.startswith(prefix):
            raise ValueError("architecture artifact root escapes its source package: " + label)
        relative = root.removeprefix(prefix)
        path = Path(relative)
        if path.is_absolute() or path.as_posix() != relative or ".." in path.parts or not relative.endswith(".rs"):
            raise ValueError("invalid architecture artifact root: " + label)
        relative_roots.append(relative)
    names = attribute_values(attrs["crate_name"], "STRING")
    if len(names) != 1:
        raise ValueError("architecture artifact requires an unambiguous crate name: " + label)
    return {
        "package": owner["name"],
        "kind": rule["ruleClass"],
        "crate_name": names[0] or label.partition(":")[2].replace("-", "_"),
        "crate_roots": sorted(set(relative_roots)),
        "features": sorted(set(attribute_values(attrs["crate_features"], "STRING_LIST"))),
        "tags": sorted(set(attribute_values(attrs["tags"], "STRING_LIST"))),
        "test_only": attrs["testonly"].get("booleanValue", False),
    }


def repository_packages(directory):
    """Reads authoritative upstream package names from pinned SDK source manifests."""
    result = {}
    manifests = {}
    for path in sorted(directory.glob("*/sources.json")):
        manifest = json.loads(path.read_text())
        if manifest["schema_version"] != 1:
            raise ValueError("unsupported SDK source manifest")
        manifests[str(path.relative_to(directory))] = hashlib.sha256(path.read_bytes()).hexdigest()
        for repository, source in manifest["sources"].items():
            name = source["name"]
            if repository in result and result[repository] != name:
                raise ValueError("conflicting SDK repository package name")
            result[repository] = name
    if not result:
        raise ValueError("architecture export requires pinned SDK source manifests")
    return result, manifests


def export(records, repositories):
    """Retains source ownership and unions production package edges across profiles."""
    rules = {}
    for record in records:
        if record["type"] != "RULE":
            raise ValueError("architecture query must contain only rules")
        rule = record["rule"]
        label = rule["name"]
        if label in rules:
            raise ValueError("duplicate architecture query rule: " + label)
        if rule["ruleClass"] not in DEPENDENCY_RULES | PROFILE_RULES | {"_source_package", "alias"}:
            raise ValueError("unexpected architecture query rule class")
        rules[label] = rule
    catalog = {}
    names = set()
    for label, rule in rules.items():
        if rule["ruleClass"] != "_source_package":
            continue
        identities = attribute_values(attributes(rule)["identity"], "STRING")
        if len(identities) != 1:
            raise ValueError("source package identity must be unambiguous")
        identity = json.loads(identities[0])
        directory = label.partition(":")[0]
        if not directory.startswith("//crates/") or directory in catalog or identity["name"] in names:
            raise ValueError("duplicate or invalid architecture source ownership")
        if not all(isinstance(identity.get(field), str) and identity[field]
                   for field in ["name", "version", "edition", "license", "license_domain"]):
            raise ValueError("incomplete architecture source identity")
        names.add(identity["name"])
        catalog[directory] = {**identity, "directory": directory.removeprefix("//")}
    if not catalog:
        raise ValueError("architecture query omitted source ownership")

    unavailable = {
        label: rule["ruleClass"] for label, rule in rules.items()
        if rule["ruleClass"] in PROFILE_RULES and label.startswith("//tools/bazel/rules:")
    }
    resolved = {}
    native = set()

    def resolve(label, active=(), development=False):
        if label in active:
            raise ValueError("architecture dependency alias cycle")
        key = (label, development)
        if key in resolved:
            return resolved[key]
        owner = catalog.get(label.partition(":")[0])
        if label in unavailable:
            result = set()
        elif label in rules and rules[label]["ruleClass"] == "alias":
            actual = attribute_values(attributes(rules[label])["actual"], "LABEL")
            result = set().union(*(resolve(value, (*active, label), development) for value in actual))
            if not result:
                raise ValueError("dependency alias has no modeled package: " + label)
        elif owner and label in rules and rules[label]["ruleClass"] in (
            DEPENDENCY_RULES if development else RUST_RULES | {"cargo_build_script"}
        ):
            result = {owner["name"]}
        elif label.startswith("@") and label[1:].partition("//")[0] in repositories:
            result = {repositories[label[1:].partition("//")[0]]}
        elif label.startswith(("@aos_native//", "//native/")):
            # Retain native edges separately; they are not Rust package names.
            native.add(label)
            result = set()
        else:
            raise ValueError("unmodeled architecture dependency: " + label)
        resolved[key] = result
        return result

    production = {name: set() for name in names}
    targets = {name: [] for name in names}
    target_edges = {}
    compilations = {}
    for label, rule in sorted(rules.items()):
        if rule["ruleClass"] not in RUST_RULES:
            continue
        attrs = attributes(rule)
        owner = catalog.get(label.partition(":")[0])
        if owner is None:
            raise ValueError("Rust target has no declared source package")
        compilations[label] = compilation_target(label, rule, owner)
        if attrs["testonly"]["type"] != "BOOLEAN":
            raise ValueError("architecture test-only selection must not be configurable")
        if attrs["testonly"].get("booleanValue", False):
            continue
        name = owner["name"]
        targets[name].append(label)
        edges = []
        for attribute in ["deps", "proc_macro_deps"]:
            if attribute not in attrs:
                continue
            for dependency in sorted(set(attribute_values(attrs[attribute], "LABEL_LIST"))):
                packages = sorted(resolve(dependency) - {name})
                production[name].update(packages)
                edges.append({"attribute": attribute, "label": dependency, "packages": packages})
        target_edges[label] = edges
    if not any(targets.values()):
        raise ValueError("architecture query omitted production Rust targets")

    # Preserve the production view's native membership before inspecting tests.
    # Audits of standalone dependencies need every compilation branch, whereas
    # release boundary audits must continue to exclude development-only edges.
    production_native = sorted(native)
    dependency_targets = {}
    for label, rule in sorted(rules.items()):
        if rule["ruleClass"] not in DEPENDENCY_RULES:
            continue
        owner = catalog.get(label.partition(":")[0])
        if owner is None:
            raise ValueError("dependency target has no declared source package")
        attrs = attributes(rule)
        if attrs["testonly"]["type"] != "BOOLEAN":
            raise ValueError("dependency test-only selection must not be configurable")
        edges = []
        for attribute, kind in [("deps", "LABEL_LIST"), ("proc_macro_deps", "LABEL_LIST"), ("crate", "LABEL")]:
            if attribute not in attrs:
                continue
            for dependency in sorted(set(attribute_values(attrs[attribute], kind))):
                edges.append({
                    "attribute": attribute, "label": dependency,
                    "packages": sorted(resolve(dependency, development=True) - {owner["name"]}),
                })
        dependency_targets[label] = {
            "package": owner["name"], "kind": rule["ruleClass"],
            "test_only": attrs["testonly"].get("booleanValue", False),
            "dependencies": edges,
        }
    return {
        "schema_version": 1,
        "selection": "union of all declared production platform/feature branches",
        "packages": sorted([
            {**identity, "production_targets": sorted(targets[identity["name"]]),
             "production_dependencies": sorted(production[identity["name"]]) if targets[identity["name"]] else None}
            for identity in catalog.values()
        ], key=lambda package: package["name"]),
        "target_dependencies": target_edges,
        "compilation_targets": compilations,
        "dependency_target_selection": "union of all declared Rust production, test, build-script, documentation, and lint branches",
        "dependency_targets": dependency_targets,
        "unavailable_profile_targets": dict(sorted(unavailable.items())),
        "native_dependencies": production_native,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--query", type=Path, required=True)
    parser.add_argument("--sdk-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    repositories, manifests = repository_packages(options.sdk_directory)
    records = [json.loads(line) for line in options.query.read_text().splitlines()]
    result = export(records, repositories)
    result["query_sha256"] = hashlib.sha256(options.query.read_bytes()).hexdigest()
    result["sdk_manifests_sha256"] = manifests
    options.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
