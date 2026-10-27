"""Qualifies the license audit against declared graph and configured closures."""

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


TARGET = "//crates/crucible/crucible-test-support:gate_license_boundary_controller"
PLUGIN = "//crates/crucible/crucible-qemu-plugin:plugin"
PROTOCOL = "//crates/crucible/crucible-qemu-protocol:lib"
POLICY_INPUTS = [
    "AGENTS.md", "CONTRIBUTING.md", "README.md",
    "LICENSES/Apache-2.0.txt", "LICENSES/MIT.txt", "LICENSES/GPL-2.0-only.txt", "LICENSES/GPL-2.0-or-later.txt",
    "docs/legal/licensing.md", "docs/legal/external-contributor-license-agreement.md",
    "docs/maintainers/contributor-licensing.md", "docs/maintainers/README.md",
    "pkgs/emulation/crucible-qemu-plugin.nix", "pkgs/emulation/_crucible-qemu-bazel-installed.nix",
    "pkgs/tools/crucible/_debug-gateway.nix", "pkgs/emulation/qemu-patches/LICENSES.md",
    "crates/crucible/crucible-qemu-shmem/interface/crucible-shmem-abi.toml",
    "crates/crucible/crucible-qemu-shmem/include/crucible_shmem_abi.h",
    "crates/crucible/crucible-qemu-shmem/src/abi_version.in",
    "crates/crucible/crucible-qemu-shmem/tests/fixtures/shmem_abi_golden.fixture",
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runtime_data(inventory, source, oracle_source):
    """Requires the audit's selected policy and ABI fixtures to match Cargo."""
    names = set(inventory["source_files"])
    patches = sorted(name for name in names if name.startswith("pkgs/emulation/qemu-patches/") and name.endswith(".patch"))
    if not patches or not set(POLICY_INPUTS) <= names:
        raise ValueError("license audit omitted declared policy or ABI fixture inputs")
    result = {}
    for name in POLICY_INPUTS + patches:
        for root in [source, oracle_source]:
            if not (root / name).resolve().is_relative_to(root.resolve()):
                raise ValueError("license audit fixture escapes its source root: " + name)
        if (source / name).read_bytes() != (oracle_source / name).read_bytes():
            raise ValueError("Cargo/Bazel license fixture bytes differ: " + name)
        result[name] = sha(source / name)
    return dict(sorted(result.items()))


def invoke(binary, graph, closures, root, case=None):
    """Runs the Bazel backend with Cargo unavailable, including negative inputs."""
    environment = dict(os.environ)
    for name in ["AOS_BAZEL_ARCHITECTURE", "AOS_BAZEL_LICENSE_CLOSURES"]:
        environment.pop(name, None)
    environment["AOS_SOURCE_CATALOG"] = "declared-source-catalog"
    environment["CARGO"] = "/absent-cargo-for-bazel-license-audit"
    if graph is not None:
        environment["AOS_BAZEL_ARCHITECTURE"] = str(graph)
    if closures is not None:
        environment["AOS_BAZEL_LICENSE_CLOSURES"] = str(closures)
    arguments = [str(binary), "--test-threads=1", "--nocapture"]
    if case:
        arguments += ["--exact", case]
    return subprocess.run(arguments, cwd=root, env=environment, capture_output=True, text=True, timeout=120)


def controls(binary, graph_path, closures_path, source_root):
    """Reaches the existing Rust policy assertions through real graph mutations."""
    original_graph = json.loads(graph_path.read_text())
    original_closures = json.loads(closures_path.read_text())
    result = invoke(binary, graph_path, closures_path, source_root)
    if result.returncode or executed_cases(result.stdout) != cases(binary):
        raise ValueError("actual Bazel license backend did not execute all audit cases: " + result.stdout + result.stderr)

    rejected = {}
    with tempfile.TemporaryDirectory(prefix="controller-license-") as temporary:
        scratch = Path(temporary)

        def reject(name, case, diagnostic, graph=None, closures=None, root=source_root):
            graph = copy.deepcopy(original_graph) if graph is None else graph
            closures = copy.deepcopy(original_closures) if closures is None else closures
            graph_file = scratch / (name + "-graph.json")
            closure_file = scratch / (name + "-closures.json")
            graph_file.write_text(json.dumps(graph))
            closures["architecture_sha256"] = sha(graph_file)
            closure_file.write_text(json.dumps(closures))
            result = invoke(binary, graph_file, closure_file, root, case)
            if result.returncode == 0 or diagnostic not in result.stdout + result.stderr:
                raise ValueError("license mutation did not reach its policy assertion: " + name + "\n" + result.stdout + result.stderr)
            rejected[name] = {"exit_code": result.returncode, "diagnostic": diagnostic}

        graph = copy.deepcopy(original_graph)
        next(package for package in graph["packages"] if package["name"] == "crucible-engine")["license"] = "GPL-2.0-only"
        reject("component-license", "cargo_metadata_preserves_component_licenses", "declared Bazel component license drift", graph=graph)

        graph = copy.deepcopy(original_graph)
        add_edge(graph, "crucible-qemu-plugin", "crucible-engine")
        reject("gpl-host-edge", "gpl_side_internal_dependencies_are_only_permissive_boundary_crates", "crosses the GPL boundary", graph=graph)

        graph = copy.deepcopy(original_graph)
        add_edge(graph, "crucible-engine", "crucible-qemu-plugin")
        reject("apache-plugin-edge", "dependencies::non_gpl_crates_cannot_depend_on_qemu_side_implementation_crates", "forbidden QEMU-side package", graph=graph)

        graph = copy.deepcopy(original_graph)
        graph["compilation_targets"][PLUGIN]["kind"] = "rust_library"
        reject("plugin-artifact-kind", "boundary_artifacts_and_code_docs_remain_explicit", "declared Bazel library artifact", graph=graph)

        for name, target, license, case in [
            ("plugin-external-apache", PLUGIN, "Apache-2.0", "dependencies::plugin_distributed_dependency_graph_has_gpl2_compatible_license_choices"),
            ("boundary-external-gpl", PROTOCOL, "GPL-2.0-only", "dependencies::permissive_boundary_dependency_graphs_remain_implementation_neutral"),
        ]:
            closure = copy.deepcopy(original_closures)
            next(package for package in closure["closures"][target]["packages"] if package["source"] == "sdk")["license"] = license
            reject(name, case, "has no approved compatible choice", closures=closure)

        closure = copy.deepcopy(original_closures)
        owner = next(package for package in original_graph["packages"] if package["name"] == "aos-core")
        closure["closures"][PLUGIN]["packages"].append({
            **{field: owner[field] for field in ["name", "version", "license", "directory"]},
            "source": "local", "compilation_targets": owner["production_targets"],
        })
        plugin_case = "dependencies::plugin_distributed_dependency_graph_has_gpl2_compatible_license_choices"
        reject("plugin-local-apache", plugin_case, "not an approved boundary dependency", closures=closure)

        closure = copy.deepcopy(original_closures)
        next(package for package in closure["closures"][PLUGIN]["packages"] if package["source"] == "sdk")["sha256"] = "missing"
        reject("missing-sdk-source-hash", plugin_case, "no pinned source identity", closures=closure)

        for name, graph, closure, diagnostic in [
            ("missing-graph", None, closures_path, "Bazel audit omitted its declared architecture input"),
            ("missing-closures", graph_path, None, "Bazel license audit omitted its configured closure input"),
            ("missing-closure-file", graph_path, scratch / "absent.json", "No such file or directory"),
        ]:
            result = invoke(binary, graph, closure, source_root, plugin_case)
            if result.returncode == 0 or diagnostic not in result.stdout + result.stderr:
                raise ValueError("missing license input did not fail closed: " + name)
            rejected[name] = {"exit_code": result.returncode, "diagnostic": diagnostic}

        stale = copy.deepcopy(original_closures)
        stale["architecture_sha256"] = "0" * 64
        stale_file = scratch / "stale-closures.json"
        stale_file.write_text(json.dumps(stale))
        result = invoke(binary, graph_path, stale_file, source_root, plugin_case)
        if result.returncode == 0 or "invalid or stale configured license closure identity" not in result.stdout + result.stderr:
            raise ValueError("stale license closure binding did not fail closed")
        rejected["stale-architecture-binding"] = {"exit_code": result.returncode}

        # This fixture specifically exercises declared source ownership. The
        # historical Cargo scanner's directory heuristic remains in its oracle.
        repository = scratch / "source-fixture"
        evaluator = Path("crates/crucible/crucible-engine/src/trigger/guest_assertion_observation.rs")
        (repository / evaluator).parent.mkdir(parents=True)
        shutil.copy2(source_root / evaluator, repository / evaluator)
        plugin = repository / "crates/crucible/crucible-qemu-plugin/src/lib.rs"
        plugin.parent.mkdir(parents=True)
        plugin.write_text("// HostAssertionOutcome must remain host-side.\n")
        guest_case = "guest_assertions::guest_assertion_evaluation_stays_in_the_host"
        reject("guest-semantics-in-plugin", guest_case, "GPL-side observation code contains host assertion semantic", root=repository)
        plugin.unlink()
        plugin.parent.rmdir()
        reject("missing-plugin-source", guest_case, "declared Bazel plugin source input is absent", root=repository)
    return {"actual_graph_cases": cases(binary), "rejected": rejected}


def qualify(options):
    if options.strict == options.conservative:
        raise ValueError("license parity requires independent strict and conservative builds")
    binary = oracle_binary(options.oracle, "gate_license_boundary")
    expected = cases(binary)
    if len(expected) != 21 or cases(binary, ignored=True):
        raise ValueError("license audit case coverage changed")
    if executed_cases((options.oracle / "cargo-tests.log").read_text()) != expected:
        raise ValueError("independent Cargo oracle did not execute all license cases")

    evidence = {"schema_version": 1, "status": "PASS", "builds": {}}
    for name in ["strict", "conservative"]:
        build = getattr(options, name)
        source = getattr(options, name + "_root")
        inventory = json.loads((build / "inventory.json").read_text())
        sources = compare(inventory, source, options.cargo_root)
        fixtures = runtime_data(inventory, source, options.cargo_root)
        if name == "strict" and any(Path(path).name in {"Cargo.toml", "Cargo.lock"} for path in inventory["source_files"]):
            raise ValueError("strict license audit selected first-party Cargo metadata")
        (options.output / (name + "-sources.json")).write_text(json.dumps(sources, indent=2, sort_keys=True) + "\n")
        parity = verify(build / "evidence/tests", {TARGET: binary})
        events = execution_events(build)
        actions = {}
        for mnemonic, target in [("Rustc", TARGET + "_binary"), ("TestRunner", TARGET)]:
            action = require_action(events, target, mnemonic, hit=False)
            if action["runner"] != "linux-sandbox":
                raise ValueError("license audit action did not use linux-sandbox")
            actions[mnemonic] = action
        test = next(row for row in events if row["targetLabel"] == TARGET and row["mnemonic"] == "TestRunner")
        inputs = {}
        for filename, path in [("architecture.json", options.graph), ("license-closures.json", options.closures)]:
            selected = [row for row in test["inputs"] if "+aos_tools_repository+aos_architecture/" in row["path"]
                        and row["path"].endswith("/" + filename)]
            if not selected or any(row["digest"]["hash"] != sha(path) for row in selected):
                raise ValueError("executed license audit omitted or changed its declared input: " + filename)
            inputs[filename] = {"sha256": sha(path), "paths": [row["path"] for row in selected]}
        evidence["builds"][name] = {
            "output": str(build), "cases": parity, "actions": actions, "declared_inputs": inputs,
            "selected_source_count": len(sources["sources_sha256"]),
            "runtime_data_sha256": fixtures,
            "execution_sha256": sha(build / "evidence/execution.json"),
        }
    evidence["backend_controls"] = controls(binary, options.graph, options.closures, options.strict_root)
    evidence["oracle"] = str(options.oracle)
    evidence["graph"] = {"path": str(options.graph), "sha256": sha(options.graph)}
    evidence["closures"] = {"path": str(options.closures), "sha256": sha(options.closures)}
    evidence["limits"] = [
        "The static license audit only; ABI, native-library licensing, runtime, and publication gates remain separate.",
        "Cargo remains an independent oracle and is unavailable to graph-backend control executions.",
    ]
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["strict", "conservative", "strict-root", "conservative-root", "oracle", "cargo-root", "graph", "closures", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=True)
    (options.output / "evidence.json").write_text(json.dumps(qualify(options), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
