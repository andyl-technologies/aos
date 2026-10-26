"""Compares installed SQL drivers and explicitly records existing live failures."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from installed_package import compare_installed, inventory, runtime_closures
from verify_cache import execution_events
from verify_package_evaluation_driver import production_profiles
from verify_pilot import cases
from verify_protocol import compare_features


COMMAND = "aos-hub-dialect-contract"
CASES = ["mysql_contract", "postgres_contract", "sqlite_contract"]


def commands(packages):
    """Runs SQLite and requires absent live endpoints to fail rather than skip."""
    environment = {
        key: value for key, value in os.environ.items()
        if key not in {"AOS_HUB_TEST_PG_URL", "AOS_HUB_TEST_MYSQL_URL"}
    }
    records = {}
    for driver, outputs in packages.items():
        binaries = Path(outputs["out"]) / "bin"
        if sorted(path.name for path in binaries.iterdir()) != [COMMAND]:
            raise ValueError("SQL contract package changed its installed executable set")
        binary = binaries / COMMAND
        if cases(binary) != CASES or cases(binary, ignored=True):
            raise ValueError("installed SQL contract omitted a required database case")
        records[driver] = []
        for name in CASES:
            result = subprocess.run(
                [str(binary), "--exact", name, "--nocapture"],
                capture_output=True, text=True, timeout=120, env=environment,
            )
            expected = 0 if name == "sqlite_contract" else 101
            combined = result.stdout + result.stderr
            if result.returncode != expected or "SKIPPED" in combined:
                raise ValueError("SQL contract did not execute or fail closed: " + name)
            if expected == 0:
                if ("dialect contract: sqlite OK" not in combined
                        or "test result: ok. 1 passed; 0 failed; 0 ignored;" not in combined):
                    raise ValueError("installed SQL contract omitted the actual SQLite workload")
            else:
                variable = (
                    "AOS_HUB_TEST_PG_URL" if name == "postgres_contract"
                    else "AOS_HUB_TEST_MYSQL_URL"
                )
                if variable + " is required by the live dialect gate" not in combined:
                    raise ValueError("SQL contract failed for a reason other than its missing endpoint")
                if "test result: FAILED. 0 passed; 1 failed; 0 ignored;" not in combined:
                    raise ValueError("required live SQL case did not report a real failure")
            records[driver].append({
                "case": name,
                "status": result.returncode,
                "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
                "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest(),
            })

        result = subprocess.run(
            [str(binary), "--aos-invalid-option"],
            capture_output=True, timeout=30, env=environment,
        )
        if not result.returncode or result.stdout or b"Unrecognized option" not in result.stderr:
            raise ValueError("installed SQL contract did not reject an invalid harness option")
    return records


def virtual_machines(outputs):
    """Compares the existing MySQL failure without changing the public live gate."""
    if set(outputs) != {"ordinary", "bazel"}:
        raise ValueError("SQL qualification omitted one installed driver's VM")
    records = {}
    failure = (
        'Database(MySqlDatabaseError { code: Some("23000"), number: 4025, '
        'message: "CONSTRAINT `CONSTRAINT_1` failed for `hubtest`.`package_documentation`" })'
    )
    for driver, output in outputs.items():
        output = Path(output)
        if (output / "result").read_text().strip() != "PASS":
            raise ValueError("live SQL observation could not complete")
        serial = (output / "serial.log").read_bytes()
        log = serial.decode("utf-8", errors="strict")
        exits = re.findall(r"AOS_HUB_DIALECT_OBSERVED_EXIT=(\d+)", log)
        if exits == ["0"]:
            if len(re.findall(r"test result: ok\. 3 passed; 0 failed; 0 ignored;", log)) != 1:
                raise ValueError("live SQL success omitted a backend case")
            if log.count("mysql production baseline and crash/concurrency replay OK") != 1:
                raise ValueError("live SQL success omitted the full MySQL workload")
            failed = {}
        elif exits == ["101"]:
            if len(re.findall(r"test result: FAILED\. 2 passed; 1 failed; 0 ignored;", log)) != 1:
                raise ValueError("live SQL result differs from the existing Cargo baseline")
            if log.count(failure) != 1 or len(re.findall(r"panicked at", log)) != 1:
                raise ValueError("live SQL failure differs from the existing documentation fixture")
            if "mysql production baseline and crash/concurrency replay OK" in log:
                raise ValueError("live SQL observation misreported the failing workload")
            failed = {"mysql_contract": failure}
        else:
            raise ValueError("live SQL observation did not retain a recognized real exit status")
        if "SKIPPED" in log:
            raise ValueError("live SQL observation skipped a backend")
        for marker in [
            "dialect contract: sqlite OK",
            "dialect contract: postgres OK (postgresql://postgres@127.0.0.1:55432/hubtest)",
        ]:
            if log.count(marker) != 1:
                raise ValueError("live SQL observation omitted a passing backend workload")
        records[driver] = {
            "output": str(output), "cases": CASES,
            "test_exit_status": int(exits[0]),
            "passed_cases": [case for case in CASES if case not in failed],
            "existing_failed_cases": failed,
            "mysql_crash_and_concurrency_workload_reached": not failed,
            "serial_log_sha256": hashlib.sha256(serial).hexdigest(),
        }
    for field in ["test_exit_status", "passed_cases", "existing_failed_cases"]:
        if records["ordinary"][field] != records["bazel"][field]:
            raise ValueError("live SQL behavior differs between Cargo and Bazel: " + field)
    return records


def dialect_profiles(build, messages, paths):
    """Compares driver units and records Cargo's two uninstalled service binaries."""
    expected_binaries = {"aos-hub", "aos-hub-egress"}
    expected_profile = {
        "opt_level": "3", "debuginfo": 0, "debug_assertions": False,
        "overflow_checks": False, "test": False,
    }
    uninstalled = {}
    selected = []
    for line in messages.read_text().splitlines():
        event = json.loads(line)
        if (event.get("reason") == "compiler-artifact"
                and Path(event["manifest_path"]).parent.name == "aos-hub-native"
                and event["target"]["kind"] == ["bin"]):
            name = event["target"]["name"]
            if (name not in expected_binaries or name in uninstalled
                    or event["profile"] != expected_profile
                    or Path(event.get("executable") or "").name != name):
                raise ValueError("Cargo's additional SQL gate binary changed its contract")
            uninstalled[name] = event["profile"]
        else:
            selected.append(line)
    if set(uninstalled) != expected_binaries:
        raise ValueError("Cargo SQL gate omitted its integration setup binaries")

    # Cargo creates these service binaries for integration-test executable
    # discovery, but installs only dialect. Bazel builds the installed graph.
    with tempfile.TemporaryDirectory(prefix="hub-dialect-profiles-") as directory:
        filtered = Path(directory) / "driver-messages.jsonl"
        filtered.write_text("\n".join(selected) + "\n")
        matched = production_profiles(build, filtered, paths)
    return {"matched_units": matched, "uninstalled_cargo_binary_units": uninstalled}


def verify(options):
    """Requires runtime, compilation, installed behavior and actual database parity."""
    packages = json.loads(options.packages.read_text())
    if (set(packages) != {"ordinary", "bazel"}
            or any(set(value) != {"out"} for value in packages.values())):
        raise ValueError("SQL contract qualification requires both installed package roots")
    closures = runtime_closures(packages, json.loads(options.closure_attributes.read_text()))
    if closures["changes"] != {"out": {"added": [], "removed": []}}:
        raise ValueError("installed SQL contract runtime closure differs")
    installed = {
        driver: inventory(value, options.readelf, options.loader)
        for driver, value in packages.items()
    }
    search_changes = compare_installed(installed["ordinary"], installed["bazel"])
    events = execution_events(options.build)
    if not events or any(
        event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]
        for event in events
    ):
        raise ValueError("SQL contract requires fresh Linux sandbox compilation")
    if any(path.name in {"Cargo.toml", "Cargo.lock"} for path in options.workspace.rglob("Cargo.*")):
        raise ValueError("Bazel SQL contract source slice retains Cargo metadata")
    messages = Path(packages["ordinary"]["out"]) / "nix-support/cargo-build-messages.jsonl"
    paths = json.loads(options.package_paths.read_text())
    live = virtual_machines(json.loads(options.vms.read_text()))
    all_live_passed = all(not vm["existing_failed_cases"] for vm in live.values())
    return {
        "schema_version": 1,
        "packages": packages,
        "runtime_closures": closures,
        "installed": installed,
        "library_search_changes": search_changes,
        "fresh_linux_sandbox_actions": len(events),
        "features": compare_features(
            options.build / "inventory.json", messages, paths, required_packages=paths,
        ),
        "production_profiles": dialect_profiles(options.build, messages, paths),
        "installed_cases": commands(packages),
        "live_databases": live,
        "live_sql_all_cases_passed": all_live_passed,
        "existing_failure_parity_only": not all_live_passed,
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
