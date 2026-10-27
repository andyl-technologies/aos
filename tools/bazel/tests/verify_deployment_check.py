"""Compares installed native validators, exact tests and real OCI producers."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess

from installed_package import compare_installed, inventory, runtime_closures
from verify_cache import execution_events
from verify_package_evaluation_driver import production_profiles
from verify_pilot import cases, verify as verify_tests
from verify_protocol import compare_features


COMMAND = "aos-deployment-check"
LABEL = "//crates/packages/aos-package-manager:bin_aos-deployment-check"
MAX_BYTES = 96 * 1024 * 1024


def fixture():
    """Mirrors the binary's declared native transaction contract."""
    return {
        "packages": {"system": "x86_64-linux", "artifacts": [], "modules": []},
        "transaction": {"schema": "aos.package.transaction", "system": "x86_64-linux",
                        "scope": ["profile", "main"], "inputs": [], "artifacts": [],
                        "packages": [], "retire": [],
                        "graph": {"schema": "aos.activation.graph", "nodes": {}, "order": []}},
        "documentation": {"schema": "aos.module.documentation", "system": "x86_64-linux",
                          "scope": ["profile", "main"], "packages": [], "options": [], "abilities": {}},
    }


def commands(packages):
    """Checks successful documents, validation failures and the exact byte bound."""
    encode = lambda value: json.dumps(value, separators=(",", ":")).encode()
    valid = fixture()
    valid_bytes = encode(valid)
    inputs = [(["--version"], b"", 0), (["--help"], b"", 1), (["extra"], b"", 1),
              ([], b"", 1), ([], b"{}", 1), ([], valid_bytes, 0),
              ([], encode({**valid, "documentation": None}), 0),
              ([], encode({key: value for key, value in valid.items() if key != "documentation"}), 0)]
    for key, field, value in [("transaction", "system", "aarch64-linux"),
                              ("documentation", "system", "aarch64-linux"),
                              ("documentation", "scope", ["profile", "other"]),
                              ("transaction", "schema", "unknown")]:
        changed = copy.deepcopy(valid)
        changed[key][field] = value
        inputs.append(([], encode(changed), 1))
    inputs += [([], encode({**valid, "execute": True}), 1), ([], valid_bytes + b"\n{}", 1),
               ([], valid_bytes + b" " * (MAX_BYTES - len(valid_bytes)), 0),
               ([], b"x" * (MAX_BYTES + 1), 1)]
    results = []
    for arguments, data, expected in inputs:
        executions = [subprocess.run([str(Path(packages[driver]["out"]) / "bin" / COMMAND), *arguments],
                                     input=data, capture_output=True, timeout=60)
                      for driver in ["ordinary", "bazel"]]
        before, after = [(item.returncode, item.stdout, item.stderr) for item in executions]
        if before != after or before[0] != expected:
            raise ValueError("deployment validator command behavior differs")
        if arguments == ["--version"]:
            if before[1:] != (b"aos-deployment-check 0.1.0\n", b""):
                raise ValueError("deployment validator version contract changed")
        elif expected == 0:
            if before[1:] != (b"", b""):
                raise ValueError("successful native validation must be silent")
        elif before[1] or not before[2].startswith(b"Error:"):
            raise ValueError("native validation failure omitted its diagnostic")
        if (len(data) > MAX_BYTES) != (b"native deployment check exceeds its byte limit" in before[2]):
            raise ValueError("native deployment validator changed its input byte boundary")
        results.append({"arguments": arguments, "stdin_bytes": len(data), "status": expected,
                        "stdin_sha256": hashlib.sha256(data).hexdigest(),
                        "stdout_sha256": hashlib.sha256(before[1]).hexdigest(),
                        "stderr_sha256": hashlib.sha256(before[2]).hexdigest()})
    return results


def producer_parity(producers):
    """Requires the real OCI constructor to retain identical artifact documents."""
    if set(producers) != {"ordinary", "bazel"}:
        raise ValueError("deployment producer comparison requires both validators")
    artifacts = {}
    for driver, output in producers.items():
        output = Path(output)
        artifacts[driver] = {name: hashlib.sha256((output / name).read_bytes()).hexdigest()
                             for name in ["deployment.json", "descriptor.json", "transaction.json", "packages.json"]}
        document = json.loads((output / "deployment.json").read_text())
        if document["schema"] != "aos.artifact.deployment/v1" or len(document["platforms"]) != 1:
            raise ValueError("OCI producer omitted its native platform document")
        graph = document["platforms"][0]["transaction"]["graph"]
        if not graph["nodes"] or not graph["order"]:
            raise ValueError("OCI producer comparison requires a nonempty activation graph")
    if artifacts["ordinary"] != artifacts["bazel"]:
        raise ValueError("OCI producer artifacts differ across validators")
    return {"outputs": producers, "document_sha256": artifacts,
            "scope": "The public mkOciTools.mkDeploymentArtifact constructor runs each installed validator."}


def verify(options):
    """Requires installed behavior, runtime, compilation and binary-test parity."""
    packages = json.loads(options.packages.read_text())
    if set(packages) != {"ordinary", "bazel"} or any(set(value) != {"out"} for value in packages.values()):
        raise ValueError("deployment validator requires both installed package roots")
    closures = runtime_closures(packages, json.loads(options.closure_attributes.read_text()))
    if closures["changes"] != {"out": {"added": [], "removed": []}}:
        raise ValueError("deployment validator runtime closure differs")
    installed = {driver: inventory(value, options.readelf, options.loader) for driver, value in packages.items()}
    search_changes = compare_installed(installed["ordinary"], installed["bazel"])
    events = {"production": execution_events(options.build), "tests": execution_events(options.tests)}
    for selected in events.values():
        if not selected or any(item["runner"] != "linux-sandbox" or item["cacheHit"] or item["exitCode"] for item in selected):
            raise ValueError("deployment validator requires fresh Linux sandbox execution")
    if any(path.name in {"Cargo.toml", "Cargo.lock"} for path in options.workspace.rglob("Cargo.*")):
        raise ValueError("deployment validator source slice retains Cargo metadata")
    messages = options.oracle / "cargo-messages.jsonl"
    tests = [json.loads(line) for line in messages.read_text().splitlines()]
    tests = [event for event in tests if event.get("reason") == "compiler-artifact"
             and event.get("profile", {}).get("test") and event.get("executable")]
    if len(tests) != 1 or tests[0]["target"]["name"] != COMMAND:
        raise ValueError("deployment validator Cargo oracle omitted its exact binary test")
    binary = Path(tests[0]["executable"])
    test_cases = cases(binary)
    if not test_cases or cases(binary, ignored=True):
        raise ValueError("deployment validator must execute its nonempty binary-test inventory")
    package_paths = json.loads(options.package_paths.read_text())
    production_messages = Path(packages["ordinary"]["out"]) / "nix-support/cargo-build-messages.jsonl"
    return {
        "schema_version": 1, "packages": packages, "installed": installed, "runtime_closures": closures,
        "library_search_changes": search_changes,
        "fresh_linux_sandbox_actions": {key: len(value) for key, value in events.items()},
        "production_features": compare_features(options.build / "inventory.json", production_messages, package_paths, required_packages=package_paths),
        "test_features": compare_features(options.tests / "inventory.json", messages, package_paths, required_packages=package_paths),
        "production_profiles": production_profiles(options.build, production_messages, package_paths),
        "test_profiles": production_profiles(options.tests, messages, package_paths),
        "test_cases": test_cases, "tests": verify_tests(options.tests / "evidence/tests", {LABEL: binary}),
        "cli_cases": commands(packages), "producers": producer_parity(json.loads(options.producers.read_text())),
        "foreign_host_execution_qualified": False, "production_default_cutover": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["packages", "build", "tests", "oracle", "workspace", "package-paths", "producers", "readelf", "loader", "closure-attributes", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")
