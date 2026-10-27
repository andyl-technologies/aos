"""Compares the embedded gateway's installed and runtime contracts."""

import argparse
import json
from pathlib import Path
import subprocess

from installed_package import compare_installed, inventory, runtime_closures
from verify_cache import execution_events
from verify_package_evaluation_driver import production_profiles
from verify_protocol import compare_features
from verify_qemu_gpl import artifact


PACKAGE_PATHS = {
    name: "crates/crucible/" + name
    for name in ["crucible-qemu-debug-gateway", "crucible-qemu-protocol"]
}


def checked_actions(build):
    """Requires fresh sandbox execution in the qualified build and test graphs."""
    actions = execution_events(build)
    if not actions or any(
        event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]
        for event in actions
    ):
        raise ValueError("gateway qualification requires fresh sandbox actions")
    return len(actions)


def verify(options):
    """Checks every installed file, runtime reference and first-party compiler unit."""
    packages = json.loads(options.packages.read_text())
    if set(packages) != {"ordinary", "bazel"} or any(set(value) != {"out"} for value in packages.values()):
        raise ValueError("gateway comparison requires both public package outputs")
    roots = {driver: Path(outputs["out"]) for driver, outputs in packages.items()}
    closures = runtime_closures(packages, json.loads(options.closure_attributes.read_text()))
    if closures["changes"] != {"out": {"added": [], "removed": []}}:
        raise ValueError("gateway runtime closure differs")
    installed = {driver: inventory(outputs, options.readelf, options.loader)
                 for driver, outputs in packages.items()}
    search_changes = compare_installed(installed["ordinary"], installed["bazel"])

    for root in roots.values():
        licenses = root / "share/licenses/crucible-debug-gateway"
        for name, source in [("GPL-2.0.txt", options.gpl), ("MIT.txt", options.mit)]:
            if (licenses / name).read_bytes() != source.read_bytes():
                raise ValueError("gateway changed a shipped license")
    cases = []
    for arguments in [[], ["--help"], ["--control-socket", "relative"],
                      ["--control-socket", "/unused-control", "--owner-gdb-socket", "relative"]]:
        results = [subprocess.run(
            ["crucible-debug-gateway", *arguments],
            executable=str(root / "bin/crucible-debug-gateway"),
            capture_output=True, text=True, timeout=10,
        ) for root in roots.values()]
        observed = [(result.returncode, result.stdout, result.stderr) for result in results]
        if observed[0] != observed[1] or observed[0][0] == 0:
            raise ValueError("gateway argument rejection differs from Cargo")
        cases.append({"arguments": arguments, "exit_code": observed[0][0],
                      "stdout": observed[0][1], "stderr": observed[0][2]})

    label = "//crates/crucible/crucible-qemu-debug-gateway:compiler_artifact"
    if set(json.loads((options.build / "packages/index.json").read_text())) != {label}:
        raise ValueError("gateway compilation includes another packaged component")
    artifact(options.build, "crucible-qemu-debug-gateway", "bin/crucible-debug-gateway")
    for workspace in [options.workspace, options.test_workspace, options.oracle_workspace]:
        if any(path.name in {"Cargo.toml", "Cargo.lock"} for path in workspace.rglob("Cargo.*")):
            raise ValueError("gateway compilation retains Cargo metadata")
    messages = roots["ordinary"] / "nix-support/cargo-build-messages.jsonl"
    return {
        "schema_version": 1, "status": "PASS", "packages": packages,
        "runtime_closures": closures, "installed": installed,
        "library_search_changes": search_changes, "argument_rejection": cases,
        "production_features": compare_features(
            options.build / "inventory.json", messages, PACKAGE_PATHS, required_packages=PACKAGE_PATHS,
        ),
        "production_profiles": production_profiles(options.build, messages, PACKAGE_PATHS),
        "fresh_linux_sandbox_actions": {
            "production": checked_actions(options.build),
            "release_tests": checked_actions(options.tests),
            "apache_oracle": checked_actions(options.oracle_build),
        },
        "production_default_cutover": False,
        "foreign_execution_qualified": False,
        "limits": ["Full suite, live debugger and corresponding-source release checks remain separate gates."],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in [
        "packages", "closure-attributes", "build", "tests", "oracle-build", "workspace",
        "test-workspace", "oracle-workspace", "gpl", "mit", "readelf", "loader", "output",
    ]:
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")
