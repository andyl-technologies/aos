"""Audits Crucible feature declarations and default production dependency graphs.

The policy reads Bazel query/aspect output and owned Rust sources. It neither
parses Cargo manifests nor infers dependency edges from source text.
"""

import argparse
from copy import deepcopy
import json
from pathlib import Path, PurePosixPath
import xml.etree.ElementTree as ET


RUST_RULES = {"rust_library", "rust_binary", "rust_shared_library", "rust_test"}
GUEST = "//crates/crucible/crucible-guest:"
ENGINE = "//crates/crucible/crucible-engine:"
FEATURE_LAYOUT = {
    "crucible-engine": {"default", "test-support", "test-double"},
    "crucible-qemu-host": {"default", "test-support"},
    "crucible-device": {"default"},
}


def directory(label):
    """Requires a canonical first-party rule label."""
    package, separator, name = label.removeprefix("//").partition(":")
    path = PurePosixPath(package)
    if (not label.startswith("//crates/") or not separator or not name
            or path.as_posix() != package or ".." in path.parts or "\\" in label):
        raise ValueError("invalid first-party label: " + label)
    return package


def declarations(query, production_roots):
    """Collects every owned Rust target, including variants outside the build roots."""
    document = ET.fromstring(query)
    if document.tag != "query" or document.get("version") != "2":
        raise ValueError("unsupported Bazel query document")
    expected = {directory(label): name for name, label in production_roots.items()}
    owners = {}
    rules = {}
    for rule in document:
        label = rule.get("name", "")
        owner = directory(label)
        kind = rule.get("class")
        if rule.tag != "rule" or owner not in expected or kind not in RUST_RULES | {"_source_package"}:
            raise ValueError("unexpected feature-policy declaration: " + label)
        if label in rules:
            raise ValueError("duplicate feature-policy target: " + label)
        rules[label] = {
            "directory": owner, "kind": kind,
            "features": {item.get("value") for item in rule.findall('list[@name="crate_features"]/string')},
            "dependencies": {item.get("value") for item in rule.findall('list[@name="deps"]/label')},
        }
        if kind == "_source_package":
            identity = json.loads(rule.find('string[@name="identity"]').get("value"))
            if owner in owners or identity["name"] != expected[owner]:
                raise ValueError("duplicate or mismatched source ownership: " + owner)
            sources = set()
            for item in rule.findall('list[@name="srcs"]/label'):
                source = item.get("value", "")
                prefix = "//" + owner + ":"
                relative = source.removeprefix(prefix)
                path = PurePosixPath(relative)
                if (not source.startswith(prefix) or path.as_posix() != relative
                        or ".." in path.parts or path.is_absolute() or path.suffix != ".rs"):
                    raise ValueError("invalid owned feature-policy source: " + source)
                sources.add(owner + "/" + relative)
            if not sources:
                raise ValueError("empty feature-policy source ownership: " + owner)
            owners[owner] = sources
    if owners.keys() != expected.keys() or not set(production_roots.values()) <= rules.keys():
        raise ValueError("missing feature-policy package or production root")
    return rules, owners


def production_closures(inventory, production_roots, root):
    """Rejects guest dependencies and engine test doubles at any production depth."""
    if inventory.get("schema_version") != 1 or set(inventory["targets"]) != set(production_roots.values()):
        raise ValueError("production feature inventory has different roots")
    records = {}
    for record in inventory["configured_targets"]:
        label = record["label"]
        if record["external"]:
            continue
        if label in records and records[label] != record:
            raise ValueError("ambiguous production configuration: " + label)
        records[label] = record

    closures = {}
    for name, start in production_roots.items():
        pending = [start]
        visited = set()
        while pending:
            label = pending.pop()
            if label in visited:
                continue
            visited.add(label)
            if label.startswith(GUEST):
                raise ValueError("production guest dependency: " + name + " -> " + label)
            record = records.get(label)
            if record is None:
                # Aspect dependency lists also contain ordinary source labels.
                # A missing rule must not disappear as though it were a file.
                if label.startswith("//crates/"):
                    package, _, filename = label[2:].partition(":")
                    if not (root / package / filename).is_file():
                        raise ValueError("missing production dependency record: " + label)
                continue
            if label.startswith(ENGINE) and "test-double" in record["features"]:
                raise ValueError("production engine test double: " + name + " -> " + label)
            pending.extend(record["dependencies"])
        closures[name] = sorted(label for label in visited if label in records)
    return closures


def feature_consumption(root, rules, owners, production_roots):
    """Checks live cfg consumers or an independently selected forwarding variant."""
    result = {}
    for name, baseline_label in production_roots.items():
        owner = directory(baseline_label)
        declared = {feature for rule in rules.values() if rule["directory"] == owner for feature in rule["features"]}
        if name in FEATURE_LAYOUT and declared != FEATURE_LAYOUT[name]:
            raise ValueError("feature layout drift: " + name)
        actual_sources = {str(path.relative_to(root)) for path in (root / owner).rglob("*.rs")}
        if actual_sources != owners[owner]:
            raise ValueError("feature-policy Rust source ownership is incomplete: " + name)
        source = "\n".join((root / path).read_text() for path in sorted(actual_sources))
        baselines = [rule for rule in rules.values() if rule["directory"] == owner
                     and rule["kind"] in {"rust_library", "rust_binary", "rust_shared_library"}
                     and not (rule["features"] - {"default"})]
        consumers = {}
        for feature in sorted(declared - {"default"}):
            if 'feature = "' + feature + '"' in source:
                consumers[feature] = "owned Rust cfg"
                continue
            variants = [rule for rule in rules.values() if rule["directory"] == owner
                        and rule["kind"] in {"rust_library", "rust_binary", "rust_shared_library"}
                        and rule["features"] - {"default"} == {feature}]
            if not baselines or not any(all(variant["dependencies"] != base["dependencies"] for base in baselines)
                                        for variant in variants):
                raise ValueError("feature has no cfg or dependency-forwarding consumer: " + name + "/" + feature)
            consumers[feature] = "independent dependency-forwarding variant"
        result[name] = {"declared_features": sorted(declared), "consumers": consumers,
                        "owned_rust_sources": len(actual_sources)}
    return result


def feature_relationships(rules, compiled):
    """Preserves the three explicit feature layouts and their dependency deltas."""
    engine = "//crates/crucible/crucible-engine:lib"
    host = "//crates/crucible/crucible-qemu-host:lib"
    device = "//crates/crucible/crucible-device:lib"
    shared = "//crates/crucible/crucible-qemu-shmem:lib"
    expected = {}
    for suffix, features in {"": set(), "_test_support": {"test-support"},
                             "_test_double": {"test-double"}, "_all_features": {"test-support", "test-double"}}.items():
        dependencies = rules[engine]["dependencies"] | ({shared} if "test-double" in features else set())
        expected[engine + suffix] = (features | {"default"}, dependencies)
        no_default = "_no_default" if not suffix else suffix + "_no_default"
        expected[engine + no_default] = (features, dependencies)
    for suffix, features in {"": set(), "_test_support": {"test-support"}}.items():
        dependencies = rules[host]["dependencies"]
        if features:
            dependencies = (dependencies - {engine}) | {engine + "_test_double"}
        expected[host + suffix] = (features | {"default"}, dependencies)
        no_default = "_no_default" if not suffix else suffix + "_no_default"
        expected[host + no_default] = (features, dependencies)
    expected[device] = ({"default"}, rules[device]["dependencies"])
    expected[device + "_no_default"] = (set(), rules[device]["dependencies"])
    if engine not in rules[host]["dependencies"] or shared in rules[engine]["dependencies"]:
        raise ValueError("default feature dependency layout drift")

    for label, (features, dependencies) in expected.items():
        if label not in rules or rules[label]["features"] != features or rules[label]["dependencies"] != dependencies:
            raise ValueError("feature dependency layout drift: " + label)

    libraries = {record["label"]: record for record in compiled["configured_targets"]
                 if not record["external"] and record["kind"] == "rust_library"}
    checked = {}
    for label in expected.keys() & libraries.keys():
        record = libraries[label]
        features, dependencies = expected[label]
        actual = {dependency for dependency in record["dependencies"] if dependency in libraries}
        intended = {dependency for dependency in dependencies if dependency.startswith("//crates/")}
        if set(record["features"]) != features or actual != intended:
            raise ValueError("compiled feature layout differs from declarations: " + label)
        checked[label] = {"features": sorted(features), "first_party_dependencies": sorted(intended)}
    if not {engine, engine + "_test_double", host + "_no_default", host + "_test_support_no_default",
            device, device + "_no_default"} <= checked.keys():
        raise ValueError("missing compiled feature dependency layout")
    return {"declared_variants": len(expected), "compiled_variants": checked}


def negative_controls(root, roots, rules, inventory, compiled):
    """Mutates actual query/aspect records to exercise the migrated safeguards."""
    rejected = []

    def rejects(name, check, message):
        try:
            check()
        except ValueError as error:
            if message not in str(error):
                raise ValueError("negative control failed for a different reason: " + name) from error
            rejected.append(name)
        else:
            raise ValueError("negative control was accepted: " + name)

    engine = ENGINE + "lib"
    host = "//crates/crucible/crucible-qemu-host:lib"
    shared = "//crates/crucible/crucible-qemu-shmem:lib"
    for name, label, dependency in [
        ("default engine activates shared memory", engine, shared),
        ("engine test support activates a dependency", engine + "_test_support_no_default", shared),
        ("device no-default changes dependencies", "//crates/crucible/crucible-device:lib_no_default", engine),
    ]:
        changed = deepcopy(rules)
        changed[label]["dependencies"].add(dependency)
        rejects(name, lambda: feature_relationships(changed, compiled), "feature dependency layout drift")

    changed = deepcopy(rules)
    changed[host + "_test_support"]["dependencies"].remove(engine + "_test_double")
    changed[host + "_test_support"]["dependencies"].add(engine)
    rejects("host test support loses engine forwarding", lambda: feature_relationships(changed, compiled),
            "feature dependency layout drift")

    changed = deepcopy(compiled)
    record = next(record for record in changed["configured_targets"] if record["label"] == engine + "_test_double")
    record["features"].remove("default")
    rejects("compiled forwarded engine loses dependency defaults", lambda: feature_relationships(rules, changed),
            "compiled feature layout differs")

    changed = deepcopy(inventory)
    record = next(record for record in changed["configured_targets"] if record["label"] == engine)
    record["dependencies"].append(GUEST + "lib_host")
    rejects("default engine acquires a transitive guest edge", lambda: production_closures(changed, roots, root),
            "production guest dependency")

    changed = deepcopy(inventory)
    record = next(record for record in changed["configured_targets"] if record["label"] == engine)
    record["features"].append("test-double")
    rejects("default engine enables test double", lambda: production_closures(changed, roots, root),
            "production engine test double")
    return rejected


def verify(root, roots, query, inventory, feature_inventory=None):
    """Combines declaration, ownership, and production closure checks."""
    if any(path.name in {"Cargo.toml", "Cargo.lock"} for path in root.rglob("Cargo.*")):
        raise ValueError("feature-policy workspace contains Cargo metadata")
    rules, owners = declarations(query, roots)
    return {"schema_version": 1, "production_closures": production_closures(inventory, roots, root),
            "features": feature_consumption(root, rules, owners, roots),
            "feature_relationships": feature_relationships(rules, feature_inventory),
            "declared_rust_targets": sum(rule["kind"] in RUST_RULES for rule in rules.values()),
            "cargo_metadata_absent": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ["root", "roots", "query", "inventory", "feature-inventory", "output"]:
        parser.add_argument("--" + argument, type=Path, required=True)
    parser.add_argument("--negative-controls", action="store_true")
    options = parser.parse_args()
    roots = json.loads(options.roots.read_text())
    query = options.query.read_text()
    inventory = json.loads(options.inventory.read_text())
    features = json.loads(options.feature_inventory.read_text())
    report = verify(options.root, roots, query, inventory, features)
    if options.negative_controls:
        rules, _ = declarations(query, roots)
        report["rejected_negative_controls"] = negative_controls(options.root, roots, rules, inventory, features)
    options.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
