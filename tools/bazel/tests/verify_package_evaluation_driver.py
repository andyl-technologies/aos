"""Compares installed evaluation drivers and actual isolated-store workflows."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from installed_package import compare_installed, inventory, runtime_closures
from reconstruct_compiler_inputs import reconstruct
from verify_cache import execution_events
from verify_cli_package import openssl_imports, shared_openssl_linkage
from verify_compiler_options import compiler_options
from verify_protocol import compare_features


COMMAND = "package_deployment_check"
ACTIVATION_RESULT = "published, evaluated, activated, recovered, reconfigured, and pruned a package generation\n"
SOURCE_GC_RESULT = "native generation roots retained source evaluation; released sources were collected\n"


def workflow_parity(workflows):
    """Requires both builders to evaluate, activate and retain real fixture sources."""
    if set(workflows) != {"ordinary", "bazel"}:
        raise ValueError("evaluation workflow comparison needs both builders")
    records = {}
    artifacts = [
        ("read-only", "first.json"), ("read-only", "second.json"),
        ("read-only", "evaluation-input.json"), ("source-gc", "deployment.json"),
    ]
    for driver, modes in workflows.items():
        if set(modes) != {"read-only", "source-gc", "activation"}:
            raise ValueError("evaluation driver omitted a runtime mode")
        for path in modes.values():
            if (Path(path) / "result").read_text().strip() != "PASS":
                raise ValueError("evaluation driver runtime mode did not pass")
        if (Path(modes["activation"]) / "acceptance.log").read_text() != ACTIVATION_RESULT:
            raise ValueError("evaluation driver did not complete generation recovery and pruning")
        if SOURCE_GC_RESULT not in (Path(modes["source-gc"]) / "acceptance.log").read_text():
            raise ValueError("evaluation driver did not complete real source retention and collection")
        records[driver] = {}
        for mode, name in artifacts:
            data = (Path(modes[mode]) / name).read_bytes()
            if not isinstance(json.loads(data), dict):
                raise ValueError("evaluation workflow omitted its JSON document")
            records[driver][mode + "/" + name] = hashlib.sha256(data).hexdigest()
        if records[driver]["read-only/first.json"] != records[driver]["read-only/second.json"]:
            raise ValueError("evaluation driver changed its repeated read-only result")
    if records["ordinary"] != records["bazel"]:
        raise ValueError("evaluation or source-retention documents differ across builders")
    return {"outputs": workflows, "document_sha256": records, "activation_result": ACTIVATION_RESULT,
            "source_gc_result": SOURCE_GC_RESULT, "store_scope": "Each run uses a private local?root store and source-built Nix."}


def production_profiles(build, messages, package_paths):
    """Compares every first-party target and execution generator compiler profile."""
    cargo = {}
    for line in messages.read_text().splitlines():
        event = json.loads(line)
        if event.get("reason") != "compiler-artifact":
            continue
        package = Path(event["manifest_path"]).parent.name
        if package not in package_paths:
            continue
        role = "custom-build" if event["target"]["kind"] == ["custom-build"] else event["target"]["name"].replace("-", "_")
        key = package + "/" + role
        if key in cargo:
            raise ValueError("duplicate evaluation-driver Cargo compilation unit")
        cargo[key] = event["profile"]

    evidence = build / "evidence"
    actions = reconstruct(json.loads((evidence / "actions.json").read_text()), execution_events(build),
                          json.loads((evidence / "compiler-inputs.json").read_text()))["actions"]
    labels = {"//" + path: package for package, path in package_paths.items()}
    result = {}
    for action in actions:
        label = action["target_label"]
        package = labels.get(label.split(":", 1)[0])
        if package is None:
            continue
        arguments = action["arguments"]
        names = [arguments[index + 1] if value == "--crate-name" else value.split("=", 1)[1]
                 for index, value in enumerate(arguments)
                 if value == "--crate-name" or value.startswith("--crate-name=")]
        if len(names) != 1:
            raise ValueError("evaluation-driver compiler unit omitted its crate name")
        role = "custom-build" if label.endswith(":build_script_program") else names[0]
        key = package + "/" + role
        if key not in cargo or key in result:
            raise ValueError("evaluation-driver compiler unit is missing or ambiguous: " + key)
        before = cargo[key]
        after = compiler_options(arguments)["effective_scalar_codegen"]
        expected_optimization = "0" if role == "custom-build" else "3"
        if (before["opt_level"] != expected_optimization or before["debuginfo"]
                or before["debug_assertions"] or before["overflow_checks"]
                or after.get("opt-level") != expected_optimization or after.get("debuginfo", "0") != "0"
                or after.get("debug-assertions") not in {"no", "off", "false"}
                or after.get("overflow-checks") not in {"no", "off", "false"}):
            raise ValueError("evaluation-driver compiler profile differs: " + key)
        result[key] = {"label": label, "cargo": before, "bazel": after}
    if set(result) != set(cargo) or not result:
        raise ValueError("evaluation-driver profile comparison omitted a first-party unit")
    return result


def command_parity(packages):
    """Checks argument rejection before any fixture or store is opened."""
    records = []
    for arguments in [[], ["--help"], ["--evaluate-only"], ["--source-gc"], ["--source-gc", "relative"]]:
        results = [subprocess.run([str(Path(packages[driver]["out"]) / "bin" / COMMAND), *arguments],
                                  capture_output=True, timeout=30) for driver in ["ordinary", "bazel"]]
        before, after = [(result.returncode, result.stdout, result.stderr) for result in results]
        if before != after or before[0] != 1 or before[1] or not before[2].startswith(b"Error:"):
            raise ValueError("evaluation-driver argument rejection differs")
        records.append({"arguments": arguments, "status": before[0], "stderr_sha256": hashlib.sha256(before[2]).hexdigest()})
    return records


def verify(options):
    """Requires installed/runtime parity and all actual fixture-driver modes."""
    packages = json.loads(options.packages.read_text())
    if set(packages) != {"ordinary", "bazel"} or any(set(value) != {"out"} for value in packages.values()):
        raise ValueError("evaluation-driver qualification requires both installed packages")
    closures = runtime_closures(packages, json.loads(options.closure_attributes.read_text()))
    if closures["changes"] != {"out": {"added": [], "removed": []}}:
        raise ValueError("evaluation-driver runtime closure differs")
    installed = {driver: inventory(value, options.readelf, options.loader) for driver, value in packages.items()}
    search_changes = compare_installed(installed["ordinary"], installed["bazel"])
    events = execution_events(options.build)
    if not events or any(event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"] for event in events):
        raise ValueError("evaluation-driver proof requires fresh Linux sandbox execution")
    if any(path.name in {"Cargo.toml", "Cargo.lock"} for path in options.workspace.rglob("Cargo.*")):
        raise ValueError("evaluation-driver source selection retains first-party Cargo metadata")
    package_paths = json.loads(options.package_paths.read_text())
    messages = Path(packages["ordinary"]["out"]) / "nix-support/cargo-build-messages.jsonl"
    return {
        "schema_version": 1, "packages": packages, "installed": installed, "runtime_closures": closures,
        "library_search_changes": search_changes, "fresh_linux_sandbox_actions": len(events),
        "features": compare_features(options.build / "inventory.json", messages, package_paths, required_packages=package_paths),
        "production_profiles": production_profiles(options.build, messages, package_paths),
        "openssl_build_script_linkage": shared_openssl_linkage(options.build),
        "openssl_imports": openssl_imports(packages, installed, options.readelf),
        "cli_cases": command_parity(packages),
        "workflows": workflow_parity(json.loads(options.workflows.read_text())),
        "foreign_host_execution_qualified": False, "production_default_cutover": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["packages", "build", "workspace", "package-paths", "workflows", "readelf", "loader", "closure-attributes", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")
