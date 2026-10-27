"""Qualifies campaign traceability against declared Bazel test targets."""

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


TARGET = "//crates/crucible/crucible-test-support:campaign_gate_traceability_controller"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def invoke(binary, graph, root, case=None):
    environment = dict(os.environ)
    environment.pop("AOS_BAZEL_ARCHITECTURE", None)
    environment["AOS_SOURCE_CATALOG"] = "declared-source-catalog"
    environment["CARGO"] = "/absent-cargo-for-bazel-campaign-traceability"
    if graph is not None:
        environment["AOS_BAZEL_ARCHITECTURE"] = str(graph)
    arguments = [str(binary), "--test-threads=1", "--nocapture"]
    if case:
        arguments += ["--exact", case]
    return subprocess.run(arguments, cwd=root, env=environment, capture_output=True, text=True, timeout=120)


def runtime_data(inventory, source, oracle_source):
    """Binds selected RFC, runner, contract, Nix and pinned QEMU fixture bytes."""
    exact = {
        "pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch",
        "pkgs/emulation/qemu-patches/_atomic-patch.nix",
    }
    names = set(inventory["source_files"])
    selected = sorted(name for name in names if name in exact or (
        Path(name).parent in {Path("tests/crucible"), Path("docs/rfcs/0020-crucible-campaigns")}
        and Path(name).suffix in {".nix", ".sh", ".toml", ".tsv", ".md"}
    ))
    required = exact | {
        "docs/rfcs/0020-crucible-campaigns/requirement-traceability.tsv",
        "docs/rfcs/0020-crucible-campaigns/schema-registry.tsv",
        "tests/crucible/default.nix",
        "tests/crucible/_e2e-determinism-native-runner.sh",
        "tests/crucible/_phase9-campaign-release-acceptance.sh",
        "tests/crucible/campaign-release-acceptance-contract.toml",
        "tests/crucible/campaign-gate-matrix-inventory.toml",
    }
    if not required <= set(selected):
        raise ValueError("campaign audit omitted runtime fixtures: " + str(sorted(required - set(selected))))
    result = {}
    for name in selected:
        for root in [source, oracle_source]:
            if not (root / name).resolve().is_relative_to(root.resolve()):
                raise ValueError("campaign fixture escapes its source root: " + name)
        if (source / name).read_bytes() != (oracle_source / name).read_bytes():
            raise ValueError("Cargo/Bazel campaign fixture bytes differ: " + name)
        result[name] = sha(source / name)
    return result


def controls(binary, graph_path, source_root):
    """Executes real target, selector and runner assertions with Cargo absent."""
    original = json.loads(graph_path.read_text())
    expected = cases(binary)
    actual = invoke(binary, graph_path, source_root)
    if actual.returncode or executed_cases(actual.stdout) != expected:
        raise ValueError("actual campaign backend did not execute all 25 cases: " + actual.stdout + actual.stderr)
    library_case = "registered_library_exact_targets_match_sources_and_nix"
    integration_case = "registered_integration_exact_targets_match_sources_and_nix"
    requirement_case = "every_rfc_requirement_has_an_executable_gate_contract"
    libraries = {name for name, row in original["compilation_targets"].items()
                 if row["package"] == "crucible-daemon" and row["kind"] == "rust_library"}
    units = {name for name, row in original["test_compilation_targets"].items()
             if row["package"] == "crucible-daemon" and set(row["crate_targets"]) & libraries}
    integrations = {name for name, row in original["test_compilation_targets"].items()
                    if row["package"] == "crucible-cli" and row["crate_roots"] == ["tests/campaign_store_process.rs"]}
    if not units or not integrations:
        raise ValueError("actual campaign library/integration declarations are absent")
    if not all(original["compilation_targets"][crate]["test_only"]
               for name in units for crate in original["test_compilation_targets"][name]["crate_targets"]):
        raise ValueError("expected actual daemon unit tests to use owned test-only library copies")
    rejected = {}
    with tempfile.TemporaryDirectory(prefix="controller-campaign-") as temporary:
        scratch = Path(temporary)

        def reject(name, case, diagnostic, graph, root=source_root):
            path = scratch / (name + ".json")
            path.write_text(json.dumps(graph))
            result = invoke(binary, path, root, case)
            if result.returncode == 0 or diagnostic not in result.stdout + result.stderr:
                raise ValueError("campaign mutation missed its policy assertion: " + name + "\n" + result.stdout + result.stderr)
            rejected[name] = {"exit_code": result.returncode, "diagnostic": diagnostic}

        graph = copy.deepcopy(original)
        for name in libraries:
            if not graph["compilation_targets"][name]["test_only"]:
                graph["compilation_targets"][name]["kind"] = "rust_binary"
                graph["dependency_targets"][name]["kind"] = "rust_binary"
        reject("missing-production-library", library_case, "missing declared library compilation", graph)

        graph = copy.deepcopy(original)
        for name in units:
            graph["test_compilation_targets"][name]["crate_targets"] = []
        reject("missing-library-unit-binding", library_case, "missing unfiltered runnable library unit test", graph)

        graph = copy.deepcopy(original)
        for row in graph["test_execution_targets"].values():
            if row["binary"] in units:
                row["argument_selection"] = {"type": "STRING_LIST", "values": ["--exact", "absent_selector"]}
        reject("filtered-library-wrappers", library_case, "missing unfiltered runnable library unit test", graph)

        graph = copy.deepcopy(original)
        for name in integrations:
            graph["test_compilation_targets"][name]["crate_roots"] = ["tests/unrelated.rs"]
        reject("missing-integration-binding", integration_case, "missing declared integration compilation", graph)

        graph = copy.deepcopy(original)
        wrappers = [name for name, row in graph["test_execution_targets"].items() if row["binary"] in integrations]
        for name in wrappers:
            graph["test_execution_targets"].pop(name)
        graph["test_execution_count"] -= len(wrappers)
        reject("missing-integration-wrappers", integration_case, "missing unfiltered runnable test wrapper", graph)

        graph = copy.deepcopy(original)
        for row in graph["test_execution_targets"].values():
            if row["binary"] in integrations:
                row["argument_selection"] = {"type": "STRING_LIST", "values": ["--exact", "absent_selector"]}
        reject("filtered-integration-wrappers", integration_case, "missing unfiltered runnable test wrapper", graph)

        graph = copy.deepcopy(original)
        feature_gate = next(row for row in graph["test_compilation_targets"].values()
                            if row["package"] == "crucible-store" and row["crate_roots"] == ["tests/gate_campaign_store_equivalence.rs"])
        feature_gate["feature_selection"] = {"type": "SELECTOR_LIST", "elements": [[
            {"condition": "//conditions:default", "values": [name for name in feature_gate["features"] if name != "test-support"]},
            {"condition": "//features:support", "values": feature_gate["features"]},
        ]]}
        reject("feature-union-is-not-guarantee", requirement_case, "must guarantee required feature", graph)

        for field in ["test_target_selection", "test_compilation_count"]:
            graph = copy.deepcopy(original)
            graph.pop(field)
            reject("missing-" + field, library_case, "missing field", graph)
        graph = copy.deepcopy(original)
        graph["test_compilation_targets"].pop(next(iter(integrations)))
        graph["test_compilation_count"] -= 1
        reject("missing-compilation-coverage", library_case, "test compilation coverage disagrees", graph)

        for name, path, diagnostic in [("missing-graph", None, "omitted its declared architecture input"),
                                       ("missing-file", scratch / "absent.json", "No such file or directory")]:
            result = invoke(binary, path, source_root, library_case)
            if result.returncode == 0 or diagnostic not in result.stdout + result.stderr:
                raise ValueError("missing campaign input did not fail closed: " + name)
            rejected[name] = {"exit_code": result.returncode, "diagnostic": diagnostic}

        def fixture(name, changes):
            # Only fixture directory entries are replaced. All untouched inputs
            # point to the immutable qualified source; no source is hardlinked.
            repository = scratch / name
            repository.mkdir()
            for child in source_root.iterdir():
                (repository / child.name).symlink_to(child)
            for relative, content in changes.items():
                path = Path(relative)
                prefix = Path()
                for part in path.parts[:-1]:
                    prefix /= part
                    destination = repository / prefix
                    if destination.is_symlink():
                        destination.unlink()
                        destination.mkdir()
                        for child in (source_root / prefix).iterdir():
                            (destination / child.name).symlink_to(child)
                destination = repository / path
                destination.unlink()
                if content is not None:
                    destination.write_bytes(content)
            return repository

        owners = {row["name"]: row["directory"] for row in original["packages"]}
        missing_library = owners["crucible-daemon"] + "/src/lib.rs"
        reject("missing-library-source", library_case, "declared library source is absent", original,
               fixture("library-source", {missing_library: None}))
        missing_integration = owners["crucible-cli"] + "/tests/campaign_store_process.rs"
        reject("missing-integration-source", integration_case, "integration target source", original,
               fixture("integration-source", {missing_integration: None}))

        native = "tests/crucible/phase7-qemu-hot-fork-atomic-world-vm.nix"
        source = (source_root / native).read_bytes()
        replacement = source.replace(b"--ignored --exact", b"--exact")
        if source == replacement:
            raise ValueError("native exact-selector control has no runner marker")
        reject("missing-native-exact-selection", library_case, "lacks --ignored --exact execution", original,
               fixture("native-selection", {native: replacement}))

        changes = {}
        for name in ["tests/crucible/phase4-packaged-campaign-choice-vm.nix", "tests/crucible/phase4-packaged-campaign-vm.nix"]:
            source = (source_root / name).read_bytes()
            replacement = source.replace(b"/bin/campaign-process-flight", b"/bin/absent-campaign-flight")
            if source != replacement:
                changes[name] = replacement
        if not changes:
            raise ValueError("packaged integration control has no runner marker")
        reject("missing-packaged-integration-runner", integration_case, "does not run campaign-process-flight", original,
               fixture("packaged-runner", changes))
    if len(rejected) != 16:
        raise ValueError("campaign control coverage changed: " + str(len(rejected)))
    return {"actual_graph_cases": expected, "accepted_actual_library_layout": "owned test-only copies with matching production source roots", "rejected": rejected}


def qualify(options):
    if options.strict == options.conservative:
        raise ValueError("campaign traceability parity requires independent strict and broad builds")
    binary = oracle_binary(options.oracle, "campaign_gate_traceability")
    expected = cases(binary)
    if len(expected) != 25 or cases(binary, ignored=True):
        raise ValueError("campaign traceability case coverage changed")
    if executed_cases((options.oracle / "cargo-tests.log").read_text()) != expected:
        raise ValueError("independent Cargo oracle did not execute all campaign traceability cases")
    evidence = {"schema_version": 1, "status": "PASS", "builds": {}}
    for name in ["strict", "conservative"]:
        build = getattr(options, name)
        source = getattr(options, name + "_root")
        inventory = json.loads((build / "inventory.json").read_text())
        sources = compare(inventory, source, options.cargo_root)
        if name == "strict" and any(Path(path).name in {"Cargo.toml", "Cargo.lock"} for path in inventory["source_files"]):
            raise ValueError("strict campaign traceability selects first-party Cargo metadata")
        (options.output / (name + "-sources.json")).write_text(json.dumps(sources, indent=2, sort_keys=True) + "\n")
        fixtures = runtime_data(inventory, source, options.cargo_root)
        parity = verify(build / "evidence/tests", {TARGET: binary})
        events = execution_events(build)
        actions = {}
        for mnemonic, target in [("Rustc", TARGET + "_binary"), ("TestRunner", TARGET)]:
            action = require_action(events, target, mnemonic, hit=False)
            if action["runner"] != "linux-sandbox":
                raise ValueError("campaign traceability action did not use linux-sandbox")
            actions[target + ":" + mnemonic] = action
        event = next(row for row in events if row["targetLabel"] == TARGET and row["mnemonic"] == "TestRunner")
        selected = [row for row in event["inputs"] if "+aos_tools_repository+aos_architecture/" in row["path"]
                    and row["path"].endswith("/architecture.json")]
        if not selected or any(row["digest"]["hash"] != sha(options.graph) for row in selected):
            raise ValueError("campaign traceability omitted or changed its declared graph")
        evidence["builds"][name] = {
            "output": str(build), "cases": parity, "actions": actions,
            "declared_graph_inputs": [row["path"] for row in selected],
            "selected_source_count": len(sources["sources_sha256"]),
            "execution_sha256": sha(build / "evidence/execution.json"),
            "runtime_data_sha256": fixtures,
        }
    evidence["backend_controls"] = controls(binary, options.graph, options.strict_root)
    evidence["oracle"] = str(options.oracle)
    evidence["graph"] = {"path": str(options.graph), "sha256": sha(options.graph)}
    evidence["limits"] = [
        "Campaign source/target traceability only; remaining lint consumers and actual production runtime flights require separate conversion and qualification.",
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
