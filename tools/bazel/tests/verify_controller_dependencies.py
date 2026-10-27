"""Qualifies harness, standalone dependency, and scheduler audits on Bazel inputs."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from verify_cache import execution_events, require_action
from verify_compiler_sources import compare
from verify_controller_architecture import add_edge
from verify_pilot import cases, verify
from verify_source_audits import executed_cases, oracle_binary


TARGETS = {"harness_components": 4, "standalone_dependencies": 2, "single_scheduler_boundary": 3}
PREFIX = "//crates/crucible/crucible-test-support:"
HARNESS_CASE = "crucible_harness_is_dev_dependency_only"
STANDALONE_CASE = "crucible_crates_do_not_depend_on_ratchet_or_aos_nix"
SCHEDULER_CASE = "engine_owns_quantum_loop_and_only_l4_drivers_advance_it"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def invoke(binary, graph, root, case=None):
    environment = dict(os.environ)
    environment.pop("AOS_BAZEL_ARCHITECTURE", None)
    environment["AOS_SOURCE_CATALOG"] = "declared-source-catalog"
    environment["CARGO"] = "/absent-cargo-for-bazel-dependency-audit"
    if graph is not None:
        environment["AOS_BAZEL_ARCHITECTURE"] = str(graph)
    arguments = [str(binary), "--test-threads=1", "--nocapture"]
    if case:
        arguments += ["--exact", case]
    return subprocess.run(arguments, cwd=root, env=environment, capture_output=True, text=True, timeout=120)


def controls(binaries, graph_path, source_root):
    """Executes actual Rust policy assertions with valid and modified graph inputs."""
    original = json.loads(graph_path.read_text())
    expectations = {name: cases(binary) for name, binary in binaries.items()}
    for name, binary in binaries.items():
        result = invoke(binary, graph_path, source_root)
        if result.returncode or executed_cases(result.stdout) != expectations[name]:
            raise ValueError("declared dependency backend did not execute every case: " + name + "\n" + result.stdout + result.stderr)

    rejected = {}
    with tempfile.TemporaryDirectory(prefix="controller-dependencies-") as temporary:
        scratch = Path(temporary)

        def reject(name, target, case, diagnostic, graph, root=source_root):
            path = scratch / (name + ".json")
            path.write_text(json.dumps(graph))
            result = invoke(binaries[target], path, root, case)
            if result.returncode == 0 or diagnostic not in result.stdout + result.stderr:
                raise ValueError("dependency mutation missed its policy assertion: " + name + "\n" + result.stdout + result.stderr)
            rejected[name] = {"exit_code": result.returncode, "diagnostic": diagnostic}

        def production_edge(graph, package, dependency):
            add_edge(graph, package, dependency)
            owner = next(row for row in graph["packages"] if row["name"] == package)
            label = owner["production_targets"][0]
            graph["dependency_targets"][label]["dependencies"] = copy.deepcopy(graph["target_dependencies"][label])

        graph = copy.deepcopy(original)
        production_edge(graph, "crucible-engine", "crucible-test-support")
        reject("harness-production-edge", "harness_components", HARNESS_CASE,
               "must not enter release/runtime dependency graphs", graph)

        library = PREFIX + "lib"
        graph = copy.deepcopy(original)
        graph["dependency_targets"][library]["dependencies"].append({
            "attribute": "deps", "label": "//third_party/rust:core_serde", "packages": ["serde"],
        })
        reject("harness-library-dependencies", "harness_components", HARNESS_CASE,
               "must keep third-party crates as dev-dependencies only", graph)

        graph = copy.deepcopy(original)
        graph["compilation_targets"][library]["test_only"] = False
        graph["dependency_targets"][library]["test_only"] = False
        package = next(row for row in graph["packages"] if row["name"] == "crucible-test-support")
        package["production_targets"] = [library]
        package["production_dependencies"] = []
        graph["target_dependencies"][library] = []
        reject("harness-not-test-only", "harness_components", HARNESS_CASE,
               "test support must remain test-only", graph)

        graph = copy.deepcopy(original)
        production_edge(graph, "crucible-engine", "ratchet-store")
        reject("standalone-production-edge", "standalone_dependencies", STANDALONE_CASE,
               "forbidden dependency", graph)

        for name, kind in [("test", "rust_test"), ("doctest", "rust_doc_test"), ("clippy", "rust_clippy")]:
            graph = copy.deepcopy(original)
            label = next(label for label, row in graph["dependency_targets"].items()
                         if row["package"].startswith("crucible") and row["kind"] == kind)
            graph["dependency_targets"][label]["dependencies"].append({
                "attribute": "deps", "label": "//third_party/rust:renamed_dependency", "packages": ["aos-nix-graph"],
            })
            reject("standalone-" + name + "-edge", "standalone_dependencies", STANDALONE_CASE,
                   "aos-nix-graph", graph)

        # Crucible's current generators do not use a Cargo build-script bridge.
        # Reuse a real bridge's shape under declared Crucible ownership to check
        # that this rule class cannot bypass the standalone dependency policy.
        graph = copy.deepcopy(original)
        bridge = copy.deepcopy(next(row for row in graph["dependency_targets"].values() if row["kind"] == "cargo_build_script"))
        bridge.update(package="crucible-engine", dependencies=[{
            "attribute": "deps", "label": "//third_party/rust:renamed_build_dependency", "packages": ["ratchet-cache"],
        }])
        graph["dependency_targets"]["//crates/crucible/crucible-engine:negative_build_script"] = bridge
        graph["dependency_target_count"] += 1
        reject("standalone-build-script-edge", "standalone_dependencies", STANDALONE_CASE,
               "ratchet-cache", graph)

        graph = copy.deepcopy(original)
        label = next(label for label, row in graph["dependency_targets"].items()
                     if row["package"] == "crucible-engine" and row["kind"] == "rust_test")
        graph["dependency_targets"][label]["dependencies"].append({
            "attribute": "deps", "label": "//third_party/rust:ratchet-hidden", "packages": ["benign-package"],
        })
        reject("standalone-forbidden-alias", "standalone_dependencies", STANDALONE_CASE,
               "ratchet-hidden", graph)

        graph = copy.deepcopy(original)
        package = next(row for row in graph["packages"] if row["name"] == "crucible-session")
        for label in package["production_targets"]:
            edges = [edge for edge in graph["target_dependencies"][label] if "crucible-engine" not in edge["packages"]]
            graph["target_dependencies"][label] = edges
            graph["dependency_targets"][label]["dependencies"] = copy.deepcopy(edges)
        package["production_dependencies"] = sorted({name for label in package["production_targets"]
                                                       for edge in graph["target_dependencies"][label] for name in edge["packages"]})
        reject("scheduler-missing-engine-edge", "single_scheduler_boundary", SCHEDULER_CASE,
               "must depend on the L3 engine crate", graph)

        variants = []
        for field, diagnostic in [("dependency_target_selection", "omitted complete dependency selection"),
                                  ("dependency_target_count", "omitted complete dependency target count"),
                                  ("dependency_targets", "omitted complete dependency targets")]:
            graph = copy.deepcopy(original)
            graph.pop(field)
            variants.append(("missing-" + field, diagnostic, graph))
        graph = copy.deepcopy(original)
        graph["dependency_targets"] = {}
        variants.append(("empty-coverage", "dependency target coverage is empty", graph))
        graph = copy.deepcopy(original)
        graph["dependency_targets"][library]["package"] = "absent-owner"
        variants.append(("unowned-target", "has no source ownership", graph))
        graph = copy.deepcopy(original)
        graph["dependency_targets"].pop(library)
        graph["dependency_target_count"] -= 1
        variants.append(("missing-compilation", "omitted or changed a compilation", graph))
        graph = copy.deepcopy(original)
        test = next(label for label, row in graph["dependency_targets"].items() if row["kind"] == "rust_test")
        graph["dependency_targets"].pop(test)
        variants.append(("missing-test-record", "target count does not match its records", graph))
        label = next(label for label, row in original["dependency_targets"].items() if row["dependencies"])
        graph = copy.deepcopy(original)
        graph["dependency_targets"][label]["dependencies"].append(copy.deepcopy(graph["dependency_targets"][label]["dependencies"][0]))
        variants.append(("duplicate-edge", "invalid or duplicate complete dependency edge", graph))
        graph = copy.deepcopy(original)
        production = next(label for label, edges in graph["target_dependencies"].items() if edges)
        graph["dependency_targets"][production]["dependencies"][0]["packages"].append("unmatched-package")
        variants.append(("production-mismatch", "disagree with production records", graph))
        graph = copy.deepcopy(original)
        graph["dependency_targets"][label]["dependencies"][0]["attribute"] = "data"
        variants.append(("invalid-attribute", "invalid or duplicate complete dependency edge", graph))
        for name, diagnostic, graph in variants:
            reject("metadata-" + name, "standalone_dependencies", STANDALONE_CASE, diagnostic, graph)

        for name, path, diagnostic in [("missing-graph", None, "omitted its declared architecture input"),
                                       ("missing-file", scratch / "absent.json", "No such file or directory")]:
            result = invoke(binaries["standalone_dependencies"], path, source_root, STANDALONE_CASE)
            if result.returncode == 0 or diagnostic not in result.stdout + result.stderr:
                raise ValueError("missing dependency input did not fail closed: " + name)
            rejected[name] = {"exit_code": result.returncode, "diagnostic": diagnostic}

        # Keep the real contract-bearing source text. Other packages need only
        # their declared source directories for these targeted scanner controls.
        repository = scratch / "scheduler-source"
        for package in original["packages"]:
            (repository / package["directory"] / "src").mkdir(parents=True)
        for package, files, directories in [
            ("crucible-engine", ["lib.rs", "model.rs", "scheduler.rs"], ["model", "scheduler"]),
            ("crucible-session", ["lib.rs"], ["session"]),
        ]:
            directory = Path(next(row["directory"] for row in original["packages"] if row["name"] == package)) / "src"
            for filename in files:
                shutil.copy2(source_root / directory / filename, repository / directory / filename)
            for fragment in directories:
                shutil.copytree(source_root / directory / fragment, repository / directory / fragment)
        cli = repository / "crates/crucible/crucible-cli/src"
        bypass = cli / "production.rs"
        bypass.write_text("fn bypass(loop_: &mut dyn QuantumLoop) { loop_.drive_quantum(request); }\n")
        reject("scheduler-owned-source-bypass", "single_scheduler_boundary", SCHEDULER_CASE,
               "must not call `drive_quantum`", original, repository)
        bypass.unlink()
        cli.rmdir()
        reject("scheduler-missing-source", "single_scheduler_boundary", SCHEDULER_CASE,
               "declared scheduler audit source is absent", original, repository)
    if len(rejected) != 24:
        raise ValueError("dependency control coverage changed")
    return {"actual_graph_cases": expectations, "rejected": rejected}


def qualify(options):
    if options.strict == options.conservative:
        raise ValueError("dependency audit parity requires independent strict and broad builds")
    binaries = {name: oracle_binary(options.oracle, name) for name in TARGETS}
    for name, count in TARGETS.items():
        if len(cases(binaries[name])) != count or cases(binaries[name], ignored=True):
            raise ValueError("dependency audit case coverage changed: " + name)
    expected = sorted(case for binary in binaries.values() for case in cases(binary))
    if executed_cases((options.oracle / "cargo-tests.log").read_text()) != expected:
        raise ValueError("independent Cargo oracle did not execute every dependency audit case")

    evidence = {"schema_version": 1, "status": "PASS", "builds": {}}
    oracles = {PREFIX + name + "_controller": binary for name, binary in binaries.items()}
    for name in ["strict", "conservative"]:
        build = getattr(options, name)
        source = getattr(options, name + "_root")
        inventory = json.loads((build / "inventory.json").read_text())
        sources = compare(inventory, source, options.cargo_root)
        if name == "strict" and any(Path(path).name in {"Cargo.toml", "Cargo.lock"} for path in inventory["source_files"]):
            raise ValueError("strict dependency audits select first-party Cargo metadata")
        (options.output / (name + "-sources.json")).write_text(json.dumps(sources, indent=2, sort_keys=True) + "\n")
        parity = verify(build / "evidence/tests", oracles)
        events = execution_events(build)
        actions = {}
        graph_inputs = {}
        for label in oracles:
            for mnemonic, target in [("Rustc", label + "_binary"), ("TestRunner", label)]:
                action = require_action(events, target, mnemonic, hit=False)
                if action["runner"] != "linux-sandbox":
                    raise ValueError("dependency audit action did not use linux-sandbox")
                actions[target + ":" + mnemonic] = action
                if mnemonic == "TestRunner":
                    event = next(row for row in events if row["targetLabel"] == target and row["mnemonic"] == mnemonic)
                    selected = [row for row in event["inputs"] if "+aos_tools_repository+aos_architecture/" in row["path"]
                                and row["path"].endswith("/architecture.json")]
                    if not selected or any(row["digest"]["hash"] != sha(options.graph) for row in selected):
                        raise ValueError("executed dependency audit omitted or changed its declared graph")
                    graph_inputs[target] = [row["path"] for row in selected]
        evidence["builds"][name] = {
            "output": str(build), "cases": parity, "actions": actions,
            "declared_graph_inputs": graph_inputs, "selected_source_count": len(sources["sources_sha256"]),
            "execution_sha256": sha(build / "evidence/execution.json"),
        }
    evidence["backend_controls"] = controls(binaries, options.graph, options.strict_root)
    evidence["oracle"] = str(options.oracle)
    evidence["graph"] = {"path": str(options.graph), "sha256": sha(options.graph)}
    evidence["limits"] = [
        "Three dependency and scheduler source audits only; production runtime and remaining RFC gates require separate qualification.",
        "Cargo remains an independent oracle and is unavailable to actual graph-backend control executions.",
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
