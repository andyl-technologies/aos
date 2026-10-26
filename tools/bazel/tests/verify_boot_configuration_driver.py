"""Qualifies the installed boot libtest and its source-built admission fixtures."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

from installed_package import compare_installed, inventory, runtime_closures
from reconstruct_compiler_inputs import reconstruct
from verify_cache import execution_events
from verify_compiler_options import compiler_options
from verify_pilot import cases, verify as verify_tests
from verify_protocol import compare_features


PACKAGE = "aos-package-manager"
PREFIX = "//crates/packages/aos-package-manager:"
FIXTURE_CASES = [
    "boot_configuration::integration::checked_metadata_adoption_recovers_and_preserves_operator_sources",
    "config_eval::provisioning_evaluator::tests::source_built_provisioning_results_match_declared_wire_contracts",
    "boot_configuration::integration::committed_dynamic_receipts_cross_stores_with_exact_authority",
]


def installed_binary(package):
    """Requires the consumer's wildcard to select exactly one executable."""
    binaries = sorted((Path(package) / "bin").glob("aos_package_manager-*"))
    if len(binaries) != 1 or not binaries[0].is_file():
        raise ValueError("boot driver must install exactly one package-manager libtest")
    return binaries[0]


def profiles(build, messages, package_paths):
    """Pairs release libtests, libraries and execution generators with Cargo."""
    cargo = {}
    for line in messages.read_text().splitlines():
        event = json.loads(line)
        if event.get("reason") != "compiler-artifact":
            continue
        package = Path(event["manifest_path"]).parent.name
        if package not in package_paths:
            continue
        role = "custom-build" if event["target"]["kind"] == ["custom-build"] else event["target"]["name"].replace("-", "_")
        key = package + "/" + role + ("/test" if event["profile"]["test"] else "")
        if key in cargo:
            raise ValueError("duplicate boot-driver Cargo compilation unit")
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
            raise ValueError("boot-driver Rust action omitted its crate name")
        role = "custom-build" if label.endswith(":build_script_program") else names[0]
        options = compiler_options(arguments)
        key = package + "/" + role + ("/test" if options["test"] else "")
        if key not in cargo or key in result:
            raise ValueError("boot-driver compiler unit is missing or ambiguous: " + key)
        before, after = cargo[key], options["effective_scalar_codegen"]
        expected = "0" if role == "custom-build" else "3"
        if (before["opt_level"] != expected or before["debuginfo"] or before["debug_assertions"]
                or before["overflow_checks"] or after.get("opt-level") != expected
                or after.get("debuginfo", "0") != "0"
                or after.get("debug-assertions") not in {"no", "off", "false"}
                or after.get("overflow-checks") not in {"no", "off", "false"}):
            raise ValueError("boot-driver compiler profile differs: " + key)
        result[key] = {"label": label, "cargo": before, "bazel": after}
    if set(result) != set(cargo) or PACKAGE + "/aos_package_manager/test" not in result:
        raise ValueError("boot-driver profile comparison omitted a compilation unit")
    return result


def fixture_results(workflows):
    """Requires all three ignored fixture cases to run once under both builders."""
    if set(workflows) != {"ordinary", "bazel"}:
        raise ValueError("boot fixtures need both installed builders")
    records = {}
    for driver, output in workflows.items():
        output = Path(output)
        if ((output / "result").read_text().strip() != "PASS"
                or (output / "cases.txt").read_text().splitlines() != FIXTURE_CASES):
            raise ValueError("boot fixture harness omitted an exact required case")
        records[driver] = {}
        for index, name in enumerate(FIXTURE_CASES, 1):
            log = (output / f"case-{index}.log").read_text()
            summaries = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", log)
            if summaries != [("1", "0", "0")]:
                raise ValueError("boot fixture did not execute exactly one successful case")
            records[driver][name] = {"executed": 1, "ignored": 0, "log_sha256": hashlib.sha256(log.encode()).hexdigest()}
    return {"outputs": workflows, "cases": records, "store_scope": "private local?root stores using source-built Nix"}


def verify(options):
    """Requires complete installed, test-inventory and boot-fixture parity."""
    packages = json.loads(options.packages.read_text())
    if set(packages) != {"ordinary", "bazel"} or any(set(outputs) != {"out"} for outputs in packages.values()):
        raise ValueError("boot driver requires exactly two installed package roots")
    binaries = {driver: installed_binary(outputs["out"]) for driver, outputs in packages.items()}
    closures = runtime_closures(packages, json.loads(options.closure_attributes.read_text()))
    if closures["changes"] != {"out": {"added": [], "removed": []}}:
        raise ValueError("boot-driver runtime closure differs")
    installed = {driver: inventory(outputs, options.readelf, options.loader) for driver, outputs in packages.items()}
    normalized = {}
    for driver, entries in installed.items():
        key = "out/bin/" + binaries[driver].name
        if key not in entries:
            raise ValueError("installed boot driver omitted its libtest artifact")
        normalized[driver] = dict(entries)
        normalized[driver]["out/bin/@package-manager-libtest@"] = normalized[driver].pop(key)
    search_changes = compare_installed(normalized["ordinary"], normalized["bazel"])
    all_cases = {driver: cases(binary) for driver, binary in binaries.items()}
    ignored = {driver: cases(binary, ignored=True) for driver, binary in binaries.items()}
    if (not all_cases["ordinary"] or all_cases["ordinary"] != all_cases["bazel"]
            or ignored["ordinary"] != ignored["bazel"] or not set(FIXTURE_CASES) <= set(ignored["ordinary"])):
        raise ValueError("installed boot-driver libtest or ignored inventories differ")
    tests = verify_tests(options.tests / "evidence/tests", {PREFIX + "unit": binaries["ordinary"]})
    expected = sorted(set(all_cases["ordinary"]) - set(ignored["ordinary"]))
    installed_tests = {"ordinary": options.ordinary_tests, "bazel": options.bazel_installed_tests}
    for driver, output in installed_tests.items():
        if (output / "result").read_text().strip() != "PASS":
            raise ValueError("installed libtest run did not pass: " + driver)
        xml = ET.parse(output / "unit.xml").findall("testcase")
        if sorted(case.attrib["name"] for case in xml) != expected or any(case.find("failure") is not None for case in xml):
            raise ValueError("installed libtest execution omitted or failed cases: " + driver)
    events = execution_events(options.build)
    test_events = execution_events(options.tests)
    for selected in [events, test_events]:
        if not selected or any(event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"] for event in selected):
            raise ValueError("boot-driver proof requires fresh Linux sandbox actions")
    if any(path.name in {"Cargo.toml", "Cargo.lock"} for path in options.workspace.rglob("Cargo.*")):
        raise ValueError("boot-driver source slice retains first-party Cargo metadata")
    paths = json.loads(options.package_paths.read_text())
    messages = Path(packages["ordinary"]["out"]) / "nix-support/cargo-build-messages.jsonl"
    return {
        "schema_version": 1, "packages": packages, "installed": installed,
        "libtest_names": {driver: binary.name for driver, binary in binaries.items()},
        "libtest_filename_contract": "one aos_package_manager-* executable; Cargo's hashed suffix becomes Bazel's stable unit suffix",
        "runtime_closures": closures, "library_search_changes": search_changes,
        "all_cases": all_cases["ordinary"], "ignored_cases": ignored["ordinary"], "ordinary_cases_executed": len(expected),
        "installed_test_outputs": {name: str(path) for name, path in installed_tests.items()},
        "bazel_tests": tests, "fresh_linux_sandbox_actions": len(events), "fresh_test_linux_sandbox_actions": len(test_events),
        "features": compare_features(options.build / "inventory.json", messages, paths, required_packages=paths),
        "compiler_profiles": profiles(options.build, messages, paths),
        "boot_fixtures": fixture_results(json.loads(options.workflows.read_text())),
        "foreign_host_execution_qualified": False, "production_default_cutover": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["packages", "build", "tests", "workspace", "package-paths", "ordinary-tests", "bazel-installed-tests", "workflows", "readelf", "loader", "closure-attributes", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")
