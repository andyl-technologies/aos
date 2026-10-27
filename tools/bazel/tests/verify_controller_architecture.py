"""Qualifies controller structural audits against actual Bazel production edges."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from verify_cache import execution_events, require_action
from verify_compiler_sources import compare
from verify_pilot import cases, verify
from verify_source_audits import executed_cases, oracle_binary


TARGETS = {"control_plane_boundary": 7, "crate_layer_graph": 2}
PREFIX = "//crates/crucible/crucible-test-support:"


def invoke(binary, graph, case=None):
    """Selects the declared graph backend without relying on Cargo discovery."""
    environment = dict(os.environ)
    environment.pop("AOS_BAZEL_ARCHITECTURE", None)
    environment["AOS_SOURCE_CATALOG"] = "declared-source-catalog"
    if graph is not None:
        environment["AOS_BAZEL_ARCHITECTURE"] = str(graph)
    arguments = [str(binary), "--test-threads=1", "--nocapture"]
    if case:
        arguments += ["--exact", case]
    return subprocess.run(arguments, env=environment, capture_output=True, text=True, timeout=120)


def add_edge(graph, package_name, dependency):
    """Mutates both levels so policy controls cannot pass on malformed metadata."""
    package = next(row for row in graph["packages"] if row["name"] == package_name)
    package["production_dependencies"] = sorted(set(package["production_dependencies"]) | {dependency})
    target = package["production_targets"][0]
    graph["target_dependencies"][target].append({
        "attribute": "deps", "label": "//negative-control:" + dependency,
        "packages": [dependency],
    })


def negative_controls(binaries, graph_path):
    """Executes real audit assertions with valid and adversarial graph inputs."""
    original = json.loads(graph_path.read_text())
    expectations = {
        name: cases(binary) for name, binary in binaries.items()
    }
    for name, binary in binaries.items():
        result = invoke(binary, graph_path)
        if result.returncode or executed_cases(result.stdout) != expectations[name]:
            raise ValueError("actual graph backend did not execute all audit cases: " + name)

    rejected = {}
    specifications = [
        ("cli-direct-engine", "control_plane_boundary", "crucible-cli", "crucible-engine",
         "cli_uses_only_declared_host_composition_dependencies", "direct dependency"),
        ("runtime-test-support", "crate_layer_graph", "crucible-engine", "crucible-test-support",
         "crucible_runtime_dependencies_follow_layer_graph", "test-only `crucible-test-support`"),
        ("upward-edge", "crate_layer_graph", "crucible-determinism", "crucible-engine",
         "crucible_runtime_dependencies_follow_layer_graph", "upward dependency"),
        ("guest-outside-layer-one", "crate_layer_graph", "crucible-guest", "crucible-determinism",
         "crucible_runtime_dependencies_follow_layer_graph", "in-VM L2 crate"),
        ("cycle", "crate_layer_graph", "crucible-qemu-protocol", "crucible-device",
         "crucible_runtime_dependencies_follow_layer_graph", "dependency cycle"),
    ]
    with tempfile.TemporaryDirectory(prefix="controller-architecture-") as temporary:
        scratch = Path(temporary)
        for name, target, package, dependency, case, diagnostic in specifications:
            graph = copy.deepcopy(original)
            add_edge(graph, package, dependency)
            path = scratch / (name + ".json")
            path.write_text(json.dumps(graph))
            result = invoke(binaries[target], path, case)
            if result.returncode == 0 or diagnostic not in result.stdout + result.stderr:
                raise ValueError("graph mutation did not reach its existing policy assertion: " + name)
            rejected[name] = {"exit_code": result.returncode, "diagnostic": diagnostic}

        case = "cli_uses_only_declared_host_composition_dependencies"
        for name, graph, diagnostic in [
            ("missing-declaration", None, "Bazel audit omitted its declared architecture input"),
            ("missing-file", scratch / "absent.json", "No such file or directory"),
        ]:
            result = invoke(binaries["control_plane_boundary"], graph, case)
            if result.returncode == 0 or diagnostic not in result.stdout + result.stderr:
                raise ValueError("missing graph input did not fail closed: " + name)
            rejected[name] = {"exit_code": result.returncode, "diagnostic": diagnostic}
    return {"actual_graph_cases": expectations, "rejected": rejected}


def qualify(options):
    if options.strict == options.conservative:
        raise ValueError("architecture parity requires independent strict and conservative builds")
    binaries = {name: oracle_binary(options.oracle, name) for name in TARGETS}
    for name, count in TARGETS.items():
        if len(cases(binaries[name])) != count or cases(binaries[name], ignored=True):
            raise ValueError("architecture audit case coverage changed: " + name)
    expected = sorted(case for binary in binaries.values() for case in cases(binary))
    if executed_cases((options.oracle / "cargo-tests.log").read_text()) != expected:
        raise ValueError("independent Cargo oracle did not execute all architecture cases")

    evidence = {"schema_version": 1, "status": "PASS", "builds": {}}
    graph_digest = hashlib.sha256(options.graph.read_bytes()).hexdigest()
    oracles = {PREFIX + name + "_controller": binary for name, binary in binaries.items()}
    for name in ["strict", "conservative"]:
        build = getattr(options, name)
        source = getattr(options, name + "_root")
        inventory = json.loads((build / "inventory.json").read_text())
        sources = compare(inventory, source, options.cargo_root)
        if name == "strict" and any(Path(path).name in {"Cargo.toml", "Cargo.lock"} for path in inventory["source_files"]):
            raise ValueError("strict architecture audits select first-party Cargo metadata")
        (options.output / (name + "-sources.json")).write_text(json.dumps(sources, indent=2, sort_keys=True) + "\n")
        parity = verify(build / "evidence/tests", oracles)
        events = execution_events(build)
        actions = {}
        graph_inputs = {}
        for label in oracles:
            for mnemonic, target in [("Rustc", label + "_binary"), ("TestRunner", label)]:
                action = require_action(events, target, mnemonic, hit=False)
                if action["runner"] != "linux-sandbox":
                    raise ValueError("architecture audit action did not use linux-sandbox")
                actions[target + ":" + mnemonic] = action
                if mnemonic == "TestRunner":
                    event = next(row for row in events if row["targetLabel"] == target and row["mnemonic"] == mnemonic)
                    selected = [row for row in event["inputs"]
                                if "+aos_tools_repository+aos_architecture/" in row["path"]
                                and row["path"].endswith("/architecture.json")]
                    if not selected or any(row["digest"]["hash"] != graph_digest for row in selected):
                        raise ValueError("executed audit omitted or changed its declared production graph")
                    graph_inputs[target] = [row["path"] for row in selected]
        evidence["builds"][name] = {
            "output": str(build), "cases": parity, "actions": actions,
            "declared_graph_inputs": graph_inputs,
            "selected_source_count": len(sources["sources_sha256"]),
            "execution_sha256": hashlib.sha256((build / "evidence/execution.json").read_bytes()).hexdigest(),
        }
    evidence["graph_backend_controls"] = negative_controls(binaries, options.graph)
    evidence["graph_sha256"] = graph_digest
    evidence["oracle"] = str(options.oracle)
    evidence["limits"] = [
        "Two structural audit targets only; other controller runtime and acceptance gates remain separate.",
        "Cargo is an independent compilation/runtime oracle and is not called by the Bazel audits.",
        "Graph mutations execute the same Rust policy assertions through Cargo-compiled oracle binaries.",
    ]
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["strict", "conservative", "strict-root", "conservative-root", "oracle", "cargo-root", "graph", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=True)
    evidence = qualify(options)
    (options.output / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
