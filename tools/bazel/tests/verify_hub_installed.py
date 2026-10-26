"""Compares native Hub packages and retains existing operator-fixture failures."""

import argparse
import hashlib
import json
from pathlib import Path

from installed_package import compare_installed, inventory, runtime_closures
from verify_cache import execution_events
from verify_package_evaluation_driver import production_profiles
from verify_protocol import compare_features
from egress_protocol import qualify as qualify_egress
from installed_commands import qualify as qualify_commands
from hub_native_runtime import qualify as qualify_native_runtime


def virtual_machines(outputs):
    """Retains the original operator fixture failure under both build drivers."""
    if set(outputs) != {"ordinary", "bazel"}:
        raise ValueError("native Hub qualification omitted one driver's observation")
    records = {}
    for driver, directory in outputs.items():
        output = Path(directory)
        if (output / "result").read_text().strip() != "PASS":
            raise ValueError("native Hub operator observation did not complete")
        serial = (output / "serial.log").read_bytes()
        log = serial.decode("utf-8", errors="strict")
        failure = "unexpected argument '--unit' found"
        if log.count("AOS_HUB_OPERATOR_OBSERVED_EXIT=1") != 1 or log.count(failure) != 1:
            raise ValueError("operator result differs from the existing Cargo fixture failure")
        if log.count("==> Exercise package credential authoring and render service boundaries") != 1:
            raise ValueError("operator observation omitted the failing fixture")
        if "==> Schema is inspectable before instance creation" in log:
            raise ValueError("operator observation unexpectedly passed the recorded failure")
        records[driver] = {
            "output": str(output), "test_exit_status": 1,
            "existing_failure": failure,
            "complete_operator_lifecycle_reached": False,
            "serial_log_sha256": hashlib.sha256(serial).hexdigest(),
        }
    return records


def verify(options):
    """Checks compilation, installation, authenticated egress and native operations."""
    packages = json.loads(options.packages.read_text())
    if (set(packages) != {"ordinary", "bazel"}
            or any(set(value) != {"out"} for value in packages.values())):
        raise ValueError("native Hub qualification requires both installed package roots")
    closures = runtime_closures(packages, json.loads(options.closure_attributes.read_text()))
    if closures["changes"] != {"out": {"added": [], "removed": []}}:
        raise ValueError("native Hub runtime closure differs")
    installed = {
        driver: inventory(outputs, options.readelf, options.loader)
        for driver, outputs in packages.items()
    }
    search_changes = compare_installed(installed["ordinary"], installed["bazel"])
    events = execution_events(options.build)
    if not events or any(
        event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]
        for event in events
    ):
        raise ValueError("native Hub requires fresh Linux sandbox compilation")
    if any(path.name in {"Cargo.toml", "Cargo.lock"} for path in options.workspace.rglob("Cargo.*")):
        raise ValueError("native Hub source slice retains Cargo metadata")
    paths = json.loads(options.package_paths.read_text())
    messages = Path(packages["ordinary"]["out"]) / "nix-support/cargo-build-messages.jsonl"
    return {
        "schema_version": 1,
        "packages": packages,
        "runtime_closures": closures,
        "installed": installed,
        "library_search_changes": search_changes,
        "fresh_linux_sandbox_actions": len(events),
        "production_features": compare_features(
            options.build / "inventory.json", messages, paths, required_packages=paths,
        ),
        "production_profiles": production_profiles(options.build, messages, paths),
        "installed_commands": qualify_commands(packages),
        "installed_egress_protocol": qualify_egress(packages),
        "operator_baseline_observations": virtual_machines(json.loads(options.vms.read_text())),
        "installed_native_runtime": qualify_native_runtime(packages),
        "browser_dom_execution_qualified": False,
        "foreign_host_execution_qualified": False,
        "production_default_cutover": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in [
        "packages", "build", "workspace", "package-paths", "vms", "readelf",
        "loader", "closure-attributes", "output",
    ]:
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")
