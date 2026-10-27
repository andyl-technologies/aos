"""Compares installed release signers, exact tests and independent signature verification."""

import argparse
import json
from pathlib import Path

from installed_package import compare_installed, inventory, runtime_closures
from release_signer_protocol import qualify
from verify_cache import execution_events
from verify_package_evaluation_driver import production_profiles
from verify_pilot import cases, verify as verify_tests
from verify_protocol import compare_features


COMMAND = "aos-release-signer"
LABEL = "//crates/release/aos-release-signer:bin_aos-release-signer"


def verify(options):
    """Requires installed behavior, runtime, compilation and binary-test parity."""
    packages = json.loads(options.packages.read_text())
    if set(packages) != {"ordinary", "bazel"} or any(set(value) != {"out"} for value in packages.values()):
        raise ValueError("release signer requires both installed package roots")
    closures = runtime_closures(packages, json.loads(options.closure_attributes.read_text()))
    if closures["changes"] != {"out": {"added": [], "removed": []}}:
        raise ValueError("release signer runtime closure differs")
    installed = {driver: inventory(value, options.readelf, options.loader) for driver, value in packages.items()}
    search_changes = compare_installed(installed["ordinary"], installed["bazel"])
    events = {"production": execution_events(options.build), "tests": execution_events(options.tests)}
    for selected in events.values():
        if not selected or any(item["runner"] != "linux-sandbox" or item["cacheHit"] or item["exitCode"] for item in selected):
            raise ValueError("release signer requires fresh Linux sandbox execution")
    if any(path.name in {"Cargo.toml", "Cargo.lock"} for path in options.workspace.rglob("Cargo.*")):
        raise ValueError("release signer source slice retains Cargo metadata")
    messages = options.oracle / "cargo-messages.jsonl"
    tests = [json.loads(line) for line in messages.read_text().splitlines()]
    tests = [event for event in tests if event.get("reason") == "compiler-artifact"
             and event.get("profile", {}).get("test") and event.get("executable")]
    if len(tests) != 1 or tests[0]["target"]["name"] != COMMAND:
        raise ValueError("release signer Cargo oracle omitted its exact binary test")
    binary = Path(tests[0]["executable"])
    test_cases = cases(binary)
    if not test_cases or cases(binary, ignored=True):
        raise ValueError("release signer must execute its nonempty binary-test inventory")
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
        "signing_protocol": qualify(packages, options.openssl, options.ssh_keygen, options.sbsign,
                                    options.sbverify, options.clang, options.lld_link),
        "foreign_host_execution_qualified": False, "production_default_cutover": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["packages", "build", "tests", "oracle", "workspace", "package-paths", "openssl", "ssh-keygen", "sbsign", "sbverify", "clang", "lld-link", "readelf", "loader", "closure-attributes", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")
