"""Checks compiled feature cases, including default suppression and forwarding."""

import argparse
import json
from pathlib import Path

from verify_cache import execution_events, require_action
from verify_compiler_options import compiler_options


def feature_options(arguments):
    """Returns the feature cfgs actually supplied to rustc."""
    return sorted(json.loads(cfg.removeprefix("feature="))
                  for cfg in compiler_options(arguments)["cfg"] if cfg.startswith("feature="))


def externs(arguments):
    """Reads explicit crate bindings without interpreting shell quoting."""
    result = {}
    position = 0
    while position < len(arguments):
        argument = arguments[position]
        if argument == "--extern":
            position += 1
            if position == len(arguments):
                raise ValueError("missing extern binding")
            binding = arguments[position]
        elif argument.startswith("--extern="):
            binding = argument.removeprefix("--extern=")
        else:
            position += 1
            continue

        name, separator, path = binding.partition("=")
        if not separator or not name or not path or name in result:
            raise ValueError("invalid or duplicate extern binding")
        result[name] = path
        position += 1
    return result


def unique(items, label, field):
    selected = [item for item in items if item[field] == label]
    if len(selected) != 1:
        raise ValueError("expected one configured compilation for " + label)
    return selected[0]


def outputs(events, label):
    event = unique([event for event in events if event["mnemonic"] == "Rustc"], label, "targetLabel")
    return {entry["path"] for entry in event["actualOutputs"]}


def validate_case(case, records, actions, events):
    """Requires a real uncached compilation and its intended dependency artifacts."""
    label = case["target"]
    record = unique(records, label, "label")
    action = unique(actions, label, "target_label")
    expected = sorted(case["expected_features"])
    if sorted(record["features"]) != expected or feature_options(action["arguments"]) != expected:
        raise ValueError("declared or compiled features differ: " + label)
    evidence = require_action(events, label, "Rustc", False)
    if evidence["runner"] != "linux-sandbox":
        raise ValueError("feature compilation escaped the Linux sandbox: " + label)

    bindings = externs(action["arguments"])
    for dependency in case["required_dependencies"]:
        if dependency not in record["dependencies"]:
            raise ValueError("missing feature dependency: " + dependency)
        dependency_record = unique(records, dependency, "label")
        artifact = bindings.get(dependency_record["crate_name"])
        if artifact not in outputs(events, dependency):
            raise ValueError("feature dependency uses the wrong compiled artifact: " + dependency)

    for dependency in case["forbidden_dependencies"]:
        if dependency in record["dependencies"]:
            raise ValueError("unexpected feature dependency: " + dependency)
        if any(record["label"] == dependency for record in records):
            if outputs(events, dependency) & set(bindings.values()):
                raise ValueError("unexpected feature artifact binding: " + dependency)

    return {"features": expected, "compilation": evidence, "externs": bindings,
            "outputs": sorted(outputs(events, label))}


def validate_contract(contract):
    """Rejects ambiguous cases and inconsistent default-feature expectations."""
    if contract.get("schema_version") != 1 or not contract.get("cases"):
        raise ValueError("unsupported or empty feature-case contract")
    names = set()
    targets = set()
    for case in contract["cases"]:
        if case["name"] in names or case["target"] in targets:
            raise ValueError("duplicate feature-case identity")
        names.add(case["name"])
        targets.add(case["target"])
        if not isinstance(case["no_default_features"], bool):
            raise ValueError("default feature policy must be boolean")
        requested = case["requested_features"]
        if len(requested) != len(set(requested)) or any(not isinstance(value, str) or not value for value in requested):
            raise ValueError("invalid requested features")
        expected = set(requested) | (set() if case["no_default_features"] else {"default"})
        if sorted(expected) != sorted(case["expected_features"]):
            raise ValueError("inconsistent default-feature expectation")
        prefix = "//crates/crucible/" + case["package"] + ":"
        if not case["target"].startswith(prefix):
            raise ValueError("feature case targets a different package")
        if set(case["required_dependencies"]) & set(case["forbidden_dependencies"]):
            raise ValueError("contradictory feature dependency policy")


def verify(build, contract):
    """Checks every selected case against analysis and retained compiler execution."""
    validate_contract(contract)
    inventory = json.loads((build / "inventory.json").read_text())
    if set(inventory["targets"]) != {case["target"] for case in contract["cases"]}:
        raise ValueError("compiled feature roots differ from the contract")
    records = [record for record in inventory["configured_targets"]
               if not record["external"] and record["kind"] == "rust_library"]
    actions = json.loads((build / "evidence/compiler-invocations.json").read_text())["actions"]
    events = execution_events(build)
    for record in records:
        action = unique(actions, record["label"], "target_label")
        if feature_options(action["arguments"]) != sorted(record["features"]):
            raise ValueError("dependency's compiled features differ: " + record["label"])
    return {"schema_version": 1, "cases": {
        case["name"]: validate_case(case, records, actions, events) for case in contract["cases"]
    }}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workspace", type=Path)
    options = parser.parse_args()
    if options.workspace is not None:
        if not (options.workspace / "MODULE.bazel").is_file():
            raise ValueError("feature workspace is absent or missing its module declaration")
        if any(path.name in {"Cargo.toml", "Cargo.lock"} for path in options.workspace.rglob("Cargo.*")):
            raise ValueError("selected feature workspace contains Cargo build metadata")
    report = verify(options.build, json.loads(options.contract.read_text()))
    options.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
