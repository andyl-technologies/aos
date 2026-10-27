"""Qualifies gate-to-test mapping against declared Bazel test compilations."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from verify_cache import execution_events, require_action
from verify_compiler_sources import compare
from verify_pilot import cases, verify
from verify_source_audits import executed_cases, oracle_binary


TARGET = "//crates/crucible/crucible-test-support:gate_target_mapping_controller"
CASE = "per_layer_gates_have_named_isolable_test_targets"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def invoke(binary, graph, root, case=None):
    environment = dict(os.environ)
    environment.pop("AOS_BAZEL_ARCHITECTURE", None)
    environment["AOS_SOURCE_CATALOG"] = "declared-source-catalog"
    environment["CARGO"] = "/absent-cargo-for-bazel-gate-mapping"
    if graph is not None:
        environment["AOS_BAZEL_ARCHITECTURE"] = str(graph)
    arguments = [str(binary), "--test-threads=1", "--nocapture"]
    if case:
        arguments += ["--exact", case]
    return subprocess.run(arguments, cwd=root, env=environment, capture_output=True, text=True, timeout=120)


def controls(binary, graph_path, source_root):
    """Reaches the real Rust feature, source, coverage, and execution assertions."""
    original = json.loads(graph_path.read_text())
    expected = cases(binary)
    actual = invoke(binary, graph_path, source_root)
    if actual.returncode or executed_cases(actual.stdout) != expected:
        raise ValueError("actual gate mapping backend did not execute both cases: " + actual.stdout + actual.stderr)
    candidates = [label for label, row in original["test_compilation_targets"].items()
                  if row["package"] == "crucible-engine" and row["crate_roots"] == ["tests/gate_abi_conformance.rs"]]
    if not candidates:
        raise ValueError("actual feature-required gate compilations are absent")
    label = candidates[0]
    wrappers = [name for name, row in original["test_execution_targets"].items() if row["binary"] in candidates]
    if not wrappers:
        raise ValueError("actual gate wrappers are absent")
    rejected = {}
    accepted = []
    with tempfile.TemporaryDirectory(prefix="controller-gate-targets-") as temporary:
        scratch = Path(temporary)

        def reject(name, diagnostic, graph, root=source_root):
            path = scratch / (name + ".json")
            path.write_text(json.dumps(graph))
            result = invoke(binary, path, root, CASE)
            if result.returncode == 0 or diagnostic not in result.stdout + result.stderr:
                raise ValueError("gate mapping mutation missed its policy assertion: " + name + "\n" + result.stdout + result.stderr)
            rejected[name] = {"exit_code": result.returncode, "diagnostic": diagnostic}

        graph = copy.deepcopy(original)
        compilation = graph["test_compilation_targets"][label]
        compilation["features"].remove("test-double")
        compilation["feature_selection"] = {"type": "STRING_LIST", "values": compilation["features"]}
        reject("missing-required-feature", "must guarantee required feature", graph)

        graph = copy.deepcopy(original)
        compilation = graph["test_compilation_targets"][label]
        compilation["feature_selection"] = {"type": "SELECTOR_LIST", "elements": [[
            {"condition": "//conditions:default", "values": [name for name in compilation["features"] if name != "test-double"]},
            {"condition": "//features:double", "values": compilation["features"]},
        ]]}
        reject("feature-union-is-not-guarantee", "must guarantee required feature", graph)

        graph = copy.deepcopy(original)
        graph["test_compilation_targets"][label]["crate_roots"].append("tests/unrelated.rs")
        reject("ambiguous-integration-root", "must pin its exact test source", graph)

        graph = copy.deepcopy(original)
        for name in candidates:
            graph["test_compilation_targets"][name]["crate_roots"] = ["tests/unrelated.rs"]
        reject("missing-declared-source", "missing declared integration compilation", graph)

        graph = copy.deepcopy(original)
        for name in wrappers:
            graph["test_execution_targets"].pop(name)
        graph["test_execution_count"] -= len(wrappers)
        reject("missing-wrappers", "missing unfiltered runnable test wrapper", graph)

        for name, selection in [
            ("filtered-wrappers", {"type": "STRING_LIST", "values": ["--exact", "absent_gate"]}),
            ("conditionally-filtered-wrappers", {"type": "SELECTOR_LIST", "elements": [[
                {"condition": "//conditions:default", "values": []},
                {"condition": "//features:filtered", "values": ["--exact", "absent_gate"]},
            ]]}),
        ]:
            graph = copy.deepcopy(original)
            for wrapper in wrappers:
                graph["test_execution_targets"][wrapper]["argument_selection"] = selection
            reject(name, "missing unfiltered runnable test wrapper", graph)

        graph = copy.deepcopy(original)
        foreign = next(name for name, row in graph["test_compilation_targets"].items() if row["package"] != "crucible-engine")
        graph["test_execution_targets"][wrappers[0]]["binary"] = foreign
        reject("foreign-wrapper-binary", "invalid test wrapper ownership", graph)

        graph = copy.deepcopy(original)
        graph["test_execution_targets"][wrappers[0]]["binary"] = "//crates/missing:binary"
        reject("missing-wrapper-binary", "test wrapper omitted its compilation", graph)

        graph = copy.deepcopy(original)
        graph["test_execution_targets"][wrappers[0]]["test_only"] = False
        reject("production-wrapper", "invalid test wrapper ownership", graph)

        graph = copy.deepcopy(original)
        graph["test_compilation_targets"][label]["test_only"] = False
        reject("production-test-compilation", "invalid test compilation ownership", graph)

        graph = copy.deepcopy(original)
        graph["test_compilation_targets"][label]["crate_targets"] = ["//crates/absent:lib"]
        reject("unowned-inherited-crate", "inherited test crate has no owned compilation", graph)

        graph = copy.deepcopy(original)
        graph["test_compilation_targets"].pop(label)
        graph["test_compilation_count"] -= 1
        reject("missing-compilation-coverage", "test compilation coverage disagrees", graph)

        graph = copy.deepcopy(original)
        graph["test_compilation_targets"].pop(label)
        reject("missing-record-count", "incomplete declared test target coverage", graph)

        graph = copy.deepcopy(original)
        graph["test_compilation_targets"] = {}
        graph["test_compilation_count"] = 0
        reject("empty-compilation-coverage", "incomplete declared test target coverage", graph)

        graph = copy.deepcopy(original)
        graph["test_compilation_targets"][label]["feature_selection"] = {"type": "SELECTOR_LIST", "elements": []}
        reject("empty-feature-selector", "test selector has no elements", graph)

        graph = copy.deepcopy(original)
        branch = {"condition": "//conditions:default", "values": graph["test_compilation_targets"][label]["features"]}
        graph["test_compilation_targets"][label]["feature_selection"] = {"type": "SELECTOR_LIST", "elements": [[branch, branch]]}
        reject("duplicate-feature-condition", "invalid or duplicate test selector condition", graph)

        graph = copy.deepcopy(original)
        graph["test_compilation_targets"][label]["features"].append("undeclared-feature")
        reject("inconsistent-feature-union", "invalid test compilation ownership or features", graph)

        graph = copy.deepcopy(original)
        graph["test_compilation_targets"][label]["crate_roots"] = ["../foreign.rs"]
        reject("escaping-source-root", "invalid test compilation ownership", graph)

        for field in ["test_target_selection", "test_compilation_count"]:
            graph = copy.deepcopy(original)
            graph.pop(field)
            reject("missing-" + field, "missing field", graph)

        for name, path, diagnostic in [("missing-graph", None, "omitted its declared architecture input"),
                                       ("missing-file", scratch / "absent.json", "No such file or directory")]:
            result = invoke(binary, path, source_root, CASE)
            if result.returncode == 0 or diagnostic not in result.stdout + result.stderr:
                raise ValueError("missing gate mapping input did not fail closed: " + name)
            rejected[name] = {"exit_code": result.returncode, "diagnostic": diagnostic}

        # Preserve all real gate source text while omitting one physical input.
        # Symlinks point into the immutable qualified source; mutations affect
        # only the fixture's directory entries, never the source snapshot.
        repository = scratch / "gate-sources"
        owners = {row["name"]: row["directory"] for row in original["packages"]}
        catalog = (source_root / "crates/crucible/crucible-test-support/src/gate_targets.rs").read_text()
        paths = {Path(owners[package]) / "tests" / (test + ".rs") for package, test in
                 re.findall(r'package: "([^"]+)",\s+test_target: "([^"]+)"', catalog)}
        if not paths:
            raise ValueError("gate source fixture omitted the actual target catalog")
        for path in paths:
            target = repository / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(source_root / path)
        missing = repository / owners["crucible-test-support"] / "tests/harness_lint.rs"
        missing.unlink()
        reject("missing-physical-source", "missing integration test target", original, repository)

        # A feature supplied by one concatenated element remains guaranteed even
        # when another element has alternatives. Keep this positive control so
        # selector validation cannot pass merely by rejecting all selectors.
        graph = copy.deepcopy(original)
        features = graph["test_compilation_targets"][label]["features"]
        graph["test_compilation_targets"][label]["feature_selection"] = {"type": "SELECTOR_LIST", "elements": [
            [{"condition": "//conditions:default", "values": []}, {"condition": "//features:other", "values": []}],
            [{"condition": "//conditions:default", "values": features}],
        ]}
        path = scratch / "guaranteed-concatenated-features.json"
        path.write_text(json.dumps(graph))
        result = invoke(binary, path, source_root, CASE)
        if result.returncode or executed_cases(result.stdout) != [CASE]:
            raise ValueError("valid concatenated feature guarantee did not pass: " + result.stdout + result.stderr)
        accepted.append("guaranteed-concatenated-features")
    if len(rejected) != 24:
        raise ValueError("gate mapping rejection coverage changed: " + str(len(rejected)))
    return {"actual_graph_cases": expected, "accepted": accepted, "rejected": rejected}


def qualify(options):
    if options.strict == options.conservative:
        raise ValueError("gate mapping parity requires independent strict and broad builds")
    binary = oracle_binary(options.oracle, "gate_target_mapping")
    expected = cases(binary)
    if len(expected) != 2 or cases(binary, ignored=True):
        raise ValueError("gate mapping case coverage changed")
    if executed_cases((options.oracle / "cargo-tests.log").read_text()) != expected:
        raise ValueError("independent Cargo oracle did not execute both gate mapping cases")
    evidence = {"schema_version": 1, "status": "PASS", "builds": {}}
    for name in ["strict", "conservative"]:
        build = getattr(options, name)
        source = getattr(options, name + "_root")
        inventory = json.loads((build / "inventory.json").read_text())
        sources = compare(inventory, source, options.cargo_root)
        if name == "strict" and any(Path(path).name in {"Cargo.toml", "Cargo.lock"} for path in inventory["source_files"]):
            raise ValueError("strict gate mapping selects first-party Cargo metadata")
        (options.output / (name + "-sources.json")).write_text(json.dumps(sources, indent=2, sort_keys=True) + "\n")
        parity = verify(build / "evidence/tests", {TARGET: binary})
        events = execution_events(build)
        actions = {}
        for mnemonic, target in [("Rustc", TARGET + "_binary"), ("TestRunner", TARGET)]:
            action = require_action(events, target, mnemonic, hit=False)
            if action["runner"] != "linux-sandbox":
                raise ValueError("gate mapping action did not use linux-sandbox")
            actions[target + ":" + mnemonic] = action
        event = next(row for row in events if row["targetLabel"] == TARGET and row["mnemonic"] == "TestRunner")
        selected = [row for row in event["inputs"] if "+aos_tools_repository+aos_architecture/" in row["path"]
                    and row["path"].endswith("/architecture.json")]
        if not selected or any(row["digest"]["hash"] != sha(options.graph) for row in selected):
            raise ValueError("gate mapping omitted or changed its declared graph")
        evidence["builds"][name] = {
            "output": str(build), "cases": parity, "actions": actions,
            "declared_graph_inputs": [row["path"] for row in selected],
            "selected_source_count": len(sources["sources_sha256"]),
            "execution_sha256": sha(build / "evidence/execution.json"),
        }
    evidence["backend_controls"] = controls(binary, options.graph, options.strict_root)
    evidence["oracle"] = str(options.oracle)
    evidence["graph"] = {"path": str(options.graph), "sha256": sha(options.graph)}
    evidence["limits"] = [
        "Gate target mapping only; campaign traceability, remaining lint consumers and production runtime gates require separate conversion and qualification.",
        "Cargo remains an independent oracle and is unavailable to actual graph-backend controls.",
    ]
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["strict", "conservative", "strict-root", "conservative-root", "oracle", "cargo-root", "graph", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=True)
    (options.output / "evidence.json").write_text(json.dumps(qualify(options), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
