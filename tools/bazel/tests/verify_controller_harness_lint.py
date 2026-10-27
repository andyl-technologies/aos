"""Qualifies the complete harness lint against declared Bazel policy inputs.

Legacy Nix gates still name thirteen real Cargo manifests as source evidence.
This checkpoint preserves those existence checks; it does not qualify their
removal or claim that the complete harness source closure is Cargo-free.
"""

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
from verify_controller_architecture import add_edge
from verify_pilot import cases, verify
from verify_source_audits import executed_cases, oracle_binary


TARGET = "//crates/crucible/crucible-test-support:harness_lint_controller"
CLIPPY_CASE = "clippy_tier_is_checked_in_and_wired"
ERROR_CASE = "production_sources_follow_error_and_logging_conventions"
BOUNDARY_CASE = "host_boundary_nondeterminism_is_confined_from_state"
CONFIG = "tools/bazel/rules/clippy.toml"
BUILDER = "tests/build/_bazel-crucible-controller-tests.nix"
LAUNCHER = "tools/bazel/launcher.py"
LEGACY_MANIFESTS = {
    "crates/Cargo.toml",
    *["crates/crucible/" + name + "/Cargo.toml" for name in [
        "crucible-cli", "crucible-control-api", "crucible-control-server",
        "crucible-daemon", "crucible-device", "crucible-engine", "crucible-guest",
        "crucible-qemu-host", "crucible-qemu-plugin", "crucible-qemu-protocol",
        "crucible-session", "crucible-store",
    ]],
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def invoke(binary, graph, root, case=None, configured=CONFIG):
    environment = dict(os.environ)
    environment.pop("AOS_BAZEL_ARCHITECTURE", None)
    environment.pop("AOS_BAZEL_CLIPPY_CONFIG", None)
    environment["AOS_SOURCE_CATALOG"] = "declared-source-catalog"
    environment["CARGO"] = "/absent-cargo-for-bazel-harness-lint"
    if graph is not None:
        environment["AOS_BAZEL_ARCHITECTURE"] = str(graph)
    if configured is not None:
        environment["AOS_BAZEL_CLIPPY_CONFIG"] = str(root / configured)
    arguments = [str(binary), "--test-threads=1", "--nocapture"]
    if case:
        arguments += ["--exact", case]
    return subprocess.run(arguments, cwd=root, env=environment, capture_output=True, text=True, timeout=120)


def controls(binary, graph_path, source_root):
    """Exercises actual Rust policy assertions, including selector weakening."""
    original = json.loads(graph_path.read_text())
    expected = cases(binary)
    actual = invoke(binary, graph_path, source_root)
    if len(expected) != 26 or actual.returncode or executed_cases(actual.stdout) != expected:
        raise ValueError("declared harness backend did not execute all original cases:\n" + actual.stdout + actual.stderr)
    rejected = {}
    accepted = {}
    with tempfile.TemporaryDirectory(prefix="controller-harness-lint-") as temporary:
        scratch = Path(temporary)

        def reject(name, diagnostic, graph, case=CLIPPY_CASE, root=source_root, configured=CONFIG):
            path = scratch / (name + ".json")
            path.write_text(json.dumps(graph))
            result = invoke(binary, path, root, case, configured)
            if result.returncode == 0 or diagnostic not in result.stdout + result.stderr:
                raise ValueError("harness mutation missed its policy assertion: " + name + "\n" + result.stdout + result.stderr)
            rejected[name] = {"exit_code": result.returncode, "diagnostic": diagnostic}

        def fixture(name, changes):
            root = scratch / name
            for relative in [CONFIG, BUILDER, LAUNCHER]:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                content = changes.get(relative, (source_root / relative).read_bytes())
                if content is not None:
                    destination.write_bytes(content)
            return root

        compilation = next(label for label, row in original["lint_bindings"].items()
                           if row["package"] == "crucible-engine" and row["kind"] == "rust_test")
        root_label = "//crates/crucible/crucible-engine:clippy_all"
        configuration = "//tools/bazel/rules:workspace_lints"
        for field in ["lint_target_selection", "lint_bindings", "lint_configurations", "alias_targets", "lint_data_groups"]:
            graph = copy.deepcopy(original)
            graph.pop(field)
            reject("missing-" + field, "missing field", graph)
        graph = copy.deepcopy(original)
        graph["lint_binding_count"] += 1
        reject("incorrect-count", "selection or counts disagree", graph)
        graph = copy.deepcopy(original)
        graph["lint_bindings"].pop(compilation)
        graph["lint_binding_count"] -= 1
        reject("missing-compilation-binding", "compilation coverage disagrees", graph)
        graph = copy.deepcopy(original)
        graph["lint_bindings"][compilation]["package"] = "crucible-cli"
        reject("incorrect-owner", "ownership disagrees", graph)
        graph = copy.deepcopy(original)
        graph["lint_bindings"][compilation]["configuration_selection"] = {"type": "LABEL", "values": []}
        reject("missing-explicit-inheritance", "missing explicit declared lint inheritance", graph)
        graph = copy.deepcopy(original)
        graph["lint_configurations"][configuration]["clippy"]["values"]["unwrap_used"] = "warn"
        reject("weakened-lint", "must guarantee deny `unwrap_used`", graph)
        for name, elements in [
            ("weak-selector-branch", [[
                {"condition": "//conditions:default", "values": {"unwrap_used": "deny"}},
                {"condition": "//features:weak", "values": {"unwrap_used": "warn"}},
            ]]),
            ("late-dictionary-override", [
                [{"condition": "//conditions:default", "values": {"unwrap_used": "deny"}}],
                [{"condition": "//conditions:default", "values": {"unwrap_used": "allow"}}],
            ]),
        ]:
            graph = copy.deepcopy(original)
            levels = copy.deepcopy(graph["lint_configurations"][configuration]["clippy"]["values"])
            # Other required levels remain guaranteed; isolate the overridden key.
            graph["lint_configurations"][configuration]["clippy"] = {
                "type": "SELECTOR_LIST", "elements": [[{"condition": "//conditions:default", "values": levels}]] + elements,
            }
            reject(name, "must guarantee deny `unwrap_used`", graph)
        graph = copy.deepcopy(original)
        levels = copy.deepcopy(graph["lint_configurations"][configuration]["clippy"]["values"])
        weak = dict(levels, unwrap_used="allow")
        graph["lint_configurations"][configuration]["clippy"] = {
            "type": "SELECTOR_LIST", "elements": [
                [{"condition": "//conditions:default", "values": weak}],
                [{"condition": "//conditions:default", "values": {"unwrap_used": "deny"}}],
            ],
        }
        path = scratch / "strengthening-override.json"
        path.write_text(json.dumps(graph))
        result = invoke(binary, path, source_root, CLIPPY_CASE)
        if result.returncode or executed_cases(result.stdout) != [CLIPPY_CASE]:
            raise ValueError("a final strict dictionary override was not accepted: " + result.stdout + result.stderr)
        accepted["ordered-strengthening-override"] = {"exit_code": result.returncode}
        graph = copy.deepcopy(original)
        graph["lint_bindings"][compilation]["configuration_selection"] = {"type": "LABEL", "values": ["//missing:configuration"]}
        reject("missing-configuration", "missing declared lint configuration", graph)
        graph = copy.deepcopy(original)
        alias = "//crates/crucible/crucible-engine:negative_lint_alias"
        graph["alias_targets"][alias] = {"type": "LABEL", "values": [alias]}
        graph["alias_target_count"] += 1
        graph["lint_bindings"][compilation]["configuration_selection"] = {"type": "LABEL", "values": [alias]}
        reject("cyclic-configuration-alias", "configuration alias cycle", graph)
        graph = copy.deepcopy(original)
        graph["clippy_targets"].pop(root_label)
        graph["clippy_target_count"] -= 1
        graph["dependency_targets"].pop(root_label)
        graph["dependency_target_count"] -= 1
        reject("missing-all-target-root", "missing declared all-target Clippy root", graph)
        graph = copy.deepcopy(original)
        values = graph["clippy_targets"][root_label]["target_selection"]["values"]
        graph["clippy_targets"][root_label]["target_selection"] = {"type": "SELECTOR_LIST", "elements": [[
            {"condition": "//conditions:default", "values": [label for label in values if label != compilation]},
            {"condition": "//features:complete", "values": values},
        ]]}
        reject("conditional-all-target-gap", "missing all-target Clippy coverage", graph)
        for tag in ["no-clippy", "NO_LINT", "nolint", "noclippy"]:
            graph = copy.deepcopy(original)
            graph["lint_bindings"][compilation]["tag_selection"] = {"type": "STRING_LIST", "values": [tag]}
            reject("skip-tag-" + tag, "flags or tags weaken the lint tier", graph)
        for flag in ["--cap-lints=warn", "-Aunwrap_used", "--warn=clippy::all"]:
            graph = copy.deepcopy(original)
            graph["lint_bindings"][compilation]["rustc_flag_selection"] = {"type": "STRING_LIST", "values": [flag]}
            reject("weak-flag-" + flag.split("=")[0], "flags or tags weaken the lint tier", graph)
        graph = copy.deepcopy(original)
        test = graph["dependency_targets"][compilation]
        test["dependencies"].append({"attribute": "deps", "label": "//third_party/rust:renamed_error", "packages": ["anyhow"]})
        reject("erased-error-development-alias", "banned erased error dependency `anyhow`", graph, ERROR_CASE)
        graph = copy.deepcopy(original)
        add_edge(graph, "crucible-store-s3", "crucible-engine")
        package = next(row for row in graph["packages"] if row["name"] == "crucible-store-s3")
        for target in package["production_targets"]:
            graph["dependency_targets"][target]["dependencies"] = copy.deepcopy(graph["target_dependencies"][target])
        reject("nondeterministic-engine-edge", "may not route host nondeterminism directly", graph, BOUNDARY_CASE)
        reject("missing-configured-file", "missing declared Clippy configuration input", original, configured=None)
        reject("unowned-configured-file", "has no declared file ownership", original, configured="absent-clippy.toml")
        for name, changes, diagnostic in [
            ("missing-method-policy", {CONFIG: b"disallowed-methods = []\ndisallowed-types = []\n"}, "missing disallowed method"),
            ("missing-config-file", {CONFIG: None}, "No such file or directory"),
            ("missing-lint-wiring", {BUILDER: b"{}\n"}, "declared Clippy gate wiring lacks"),
            ("missing-configured-setting", {LAUNCHER: b"# absent configured filegroup\n"}, "lacks the configured filegroup"),
        ]:
            reject(name, diagnostic, original, root=fixture(name, changes))
        repository = scratch / "source-evidence"
        for source in source_root.rglob("*"):
            if source.is_file():
                destination = repository / source.relative_to(source_root)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.symlink_to(source)
        manifest = repository / "crates/Cargo.toml"
        manifest.unlink()
        reject("missing-real-manifest-reference", "evidence source `crates/Cargo.toml` does not exist",
               original, "gate_evidence_references_are_integral", repository)
        manifest.symlink_to(source_root / "crates/Cargo.toml")
        reference = repository / "crates/crucible/crucible-engine/src/lib.rs"
        reference.unlink()
        reject("missing-real-source-reference", "evidence source `crates/crucible/crucible-engine/src/lib.rs` does not exist",
               original, "gate_evidence_references_are_integral", repository)
        for name, selected_graph in [("missing-graph", None), ("absent-graph-file", scratch / "absent.json")]:
            result = invoke(binary, selected_graph, source_root, CLIPPY_CASE)
            if result.returncode == 0:
                raise ValueError("harness graph selection did not fail closed: " + name)
            rejected[name] = {"exit_code": result.returncode}
    return {"actual_graph_cases": expected, "rejected": rejected, "accepted": accepted}


def runtime_data(inventory, source, oracle_source):
    """Binds recursive Nix sources, direct RFC task files and the baseline."""
    selected = set(inventory["source_files"])
    required = {
        "tests/crucible/harness-lint-baseline.txt", "tests/crucible/.validate-enumerate.nix",
        "docs/users/crucible/reference.md", CONFIG, BUILDER, LAUNCHER,
    }
    for directory, suffix, recursive in [
        ("tests/crucible", ".nix", True),
        ("docs/rfcs/0010-crucible", ".md", False),
        ("docs/rfcs/0014-signal-driven-fault-model", ".md", False),
    ]:
        # Match collect_nix_sources and rfc_task_states in the Rust reader:
        # task states inspect direct Markdown children, not design subtrees.
        scan = (oracle_source / directory).rglob if recursive else (oracle_source / directory).glob
        reference = {str(path.relative_to(oracle_source)) for path in scan("*" + suffix)}
        actual = {name for name in selected if name.startswith(directory + "/") and name.endswith(suffix)
                  and (recursive or str(Path(name).parent) == directory)}
        if not reference or reference != actual:
            raise ValueError("harness runtime scan differs from the independent oracle: " + directory)
        required.update(reference)
    legacy = {name for name in selected if Path(name).name in {"Cargo.toml", "Cargo.lock"}}
    if legacy != LEGACY_MANIFESTS:
        raise ValueError("unexpected remaining manifest evidence: " + str(sorted(legacy ^ LEGACY_MANIFESTS)))
    required.update(legacy)
    for relative in sorted(required):
        if not relative.startswith("tests/crucible/") or not relative.endswith(".nix"):
            continue
        for name in re.findall(r'failuresFor "([^"\n]+)"', (oracle_source / relative).read_text()):
            if (not any(token in name for token in ["*", " + ", " and "])
                    and "/" in name and Path(name).suffix in {".nix", ".rs", ".toml", ".md", ".patch", ".txt", ".json"}):
                required.add(name)
    evidence = {}
    for name in sorted(required):
        if name not in selected:
            raise ValueError("harness omitted runtime evidence: " + name)
        # Bazel-only wiring and configuration do not belong to the Cargo oracle.
        if name not in {CONFIG, BUILDER, LAUNCHER} and (source / name).read_bytes() != (oracle_source / name).read_bytes():
            raise ValueError("harness runtime source differs from its oracle: " + name)
        evidence[name] = sha(source / name)
    return evidence


def qualify(options):
    if options.strict == options.conservative:
        raise ValueError("harness lint parity requires independent strict and broad builds")
    binary = oracle_binary(options.oracle, "harness_lint")
    expected = cases(binary)
    if len(expected) != 26 or cases(binary, ignored=True):
        raise ValueError("harness lint original case coverage changed")
    if executed_cases((options.oracle / "cargo-tests.log").read_text()) != expected:
        raise ValueError("Cargo oracle did not execute all original harness lint cases")
    evidence = {"schema_version": 1, "status": "PASS", "builds": {}}
    for name in ["strict", "conservative"]:
        build, source = getattr(options, name), getattr(options, name + "_root")
        inventory = json.loads((build / "inventory.json").read_text())
        sources = compare(inventory, source, options.cargo_root)
        fixtures = runtime_data(inventory, source, options.cargo_root)
        (options.output / (name + "-sources.json")).write_text(json.dumps(sources, indent=2, sort_keys=True) + "\n")
        parity = verify(build / "evidence/tests", {TARGET: binary})
        events = execution_events(build)
        actions = {}
        for mnemonic, target in [("Rustc", TARGET + "_binary"), ("TestRunner", TARGET)]:
            action = require_action(events, target, mnemonic, hit=False)
            if action["runner"] != "linux-sandbox":
                raise ValueError("harness action did not use linux-sandbox")
            actions[mnemonic] = action
        event = next(row for row in events if row["targetLabel"] == TARGET and row["mnemonic"] == "TestRunner")
        selected = [row for row in event["inputs"] if "+aos_tools_repository+aos_architecture/" in row["path"]
                    and row["path"].endswith("/architecture.json")]
        if not selected or any(row["digest"]["hash"] != sha(options.graph) for row in selected):
            raise ValueError("harness executed without the retained declared graph")
        configured = [row for row in event["inputs"] if row["path"].endswith("/" + CONFIG)]
        if not configured or any(row["digest"]["hash"] != sha(source / CONFIG) for row in configured):
            raise ValueError("harness executed without the configured Clippy policy file")
        evidence["builds"][name] = {
            "output": str(build), "cases": parity, "actions": actions,
            "graph_inputs": [row["path"] for row in selected],
            "configured_clippy_inputs": [row["path"] for row in configured],
            "selected_source_count": len(sources["sources_sha256"]),
            "runtime_data_sha256": fixtures, "execution_sha256": sha(build / "evidence/execution.json"),
        }
    evidence["backend_controls"] = controls(binary, options.graph, options.strict_root)
    evidence["oracle"] = str(options.oracle)
    evidence["graph"] = {"path": str(options.graph), "sha256": sha(options.graph)}
    evidence["remaining_manifest_source_references"] = sorted(LEGACY_MANIFESTS)
    evidence["limits"] = [
        "Harness policy and source-reference checks only; actual Clippy execution has separate qualification.",
        "Thirteen real manifests remain evidence for unmigrated Nix source gates; manifest retirement is not qualified.",
        "Production runtime and all other outstanding RFC gates require their own qualification.",
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
