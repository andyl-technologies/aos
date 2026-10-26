"""Qualifies static Nix store handlers and their isolated, source-built Nix test."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

from installed_package import compare_installed, inventory, runtime_closures
from reconstruct_compiler_inputs import reconstruct
from verify_ability_package import static_contract
from verify_cache import execution_events
from verify_compiler_options import compiler_options
from verify_pilot import verify as verify_tests
from verify_protocol import compare_doctests, compare_features


COMMAND = "aos-nix-store-provider"
PACKAGE = "aos-activation-nix-store"
PREFIX = "//crates/activation/" + PACKAGE + ":"
REAL_NIX_CASE = "artifact::tests::source_built_nix_store_alias_adds_and_verifies_exact_content"
PACKAGE_PATHS = {
    PACKAGE: "crates/activation/" + PACKAGE,
    "aos-activation": "crates/activation/aos-activation",
    "aos-core": "crates/core/aos-core",
    "aos-module-format": "crates/modules/aos-module-format",
    "aos-artifact-evidence": "crates/artifacts/aos-artifact-evidence",
}
MAX_DOCUMENT_BYTES = 32 * 1024 * 1024


def cargo_tests(oracle):
    """Requires both independently compiled release test executables."""
    names = {PACKAGE.replace("-", "_"): PREFIX + "static_unit", COMMAND: PREFIX + "static_bin"}
    binaries = {}
    for line in (oracle / "cargo-messages.jsonl").read_text().splitlines():
        event = json.loads(line)
        name = event.get("target", {}).get("name")
        if (event.get("reason") != "compiler-artifact" or name not in names
                or not event.get("profile", {}).get("test") or not event.get("executable")):
            continue
        if names[name] in binaries:
            raise ValueError("duplicate Nix store Cargo test target")
        binaries[names[name]] = Path(event["executable"])
    if set(binaries) != set(names.values()) or any(not path.is_file() for path in binaries.values()):
        raise ValueError("Nix store Cargo oracle omitted a release test executable")
    return binaries


def production_profiles(build, messages):
    """Checks all first-party production compiler profiles against Cargo."""
    cargo = {}
    for line in messages.read_text().splitlines():
        event = json.loads(line)
        if (event.get("reason") == "compiler-artifact"
                and Path(event["manifest_path"]).parent.name in PACKAGE_PATHS):
            name = event["target"]["name"].replace("-", "_")
            if name in cargo:
                raise ValueError("duplicate Nix store production Cargo unit")
            cargo[name] = event["profile"]
    evidence = build / "evidence"
    actions = reconstruct(json.loads((evidence / "actions.json").read_text()), execution_events(build),
                          json.loads((evidence / "compiler-inputs.json").read_text()))["actions"]
    result = {}
    for action in actions:
        if not action["target_label"].startswith("//crates/"):
            continue
        arguments = action["arguments"]
        names = [arguments[index + 1] if value == "--crate-name" else value.split("=", 1)[1]
                 for index, value in enumerate(arguments)
                 if value == "--crate-name" or value.startswith("--crate-name=")]
        if len(names) != 1 or names[0] not in cargo or names[0] in result:
            raise ValueError("Nix store production unit is missing or ambiguous")
        before = cargo[names[0]]
        after = compiler_options(arguments)["effective_scalar_codegen"]
        if (before["opt_level"] != "3" or before["debuginfo"] or before["debug_assertions"]
                or before["overflow_checks"] or after.get("opt-level") != "3"
                or after.get("debuginfo", "0") != "0"
                or after.get("debug-assertions") not in {"no", "off", "false"}
                or after.get("overflow-checks") not in {"no", "off", "false"}):
            raise ValueError("Nix store production compiler profile differs")
        result[names[0]] = {"cargo": before, "bazel": after}
    if set(result) != set(cargo) or len(result) != len(PACKAGE_PATHS) + 1:
        raise ValueError("Nix store production profiles omitted a first-party unit")
    return result


def command_parity(packages):
    """Checks argument rejection and the inclusive invocation byte boundary."""
    cases = [([], b""), (["--help"], b""), (["invalid"], b""), (["observe", "extra"], b""),
             *[([operation], data) for operation in ["apply", "remove", "observe"] for data in [b"", b"{}"]],
             (["observe"], b"{}" + b" " * (MAX_DOCUMENT_BYTES - 2)),
             (["observe"], b"x" * (MAX_DOCUMENT_BYTES + 1))]
    records = []
    for arguments, data in cases:
        results = [subprocess.run([str(Path(packages[driver]["out"]) / "bin" / COMMAND), *arguments],
                                  input=data, capture_output=True, timeout=30)
                   for driver in ["ordinary", "bazel"]]
        before, after = [(item.returncode, item.stdout, item.stderr) for item in results]
        if before != after or before[0] != 1 or before[1] or not before[2].startswith(COMMAND.encode() + b":"):
            raise ValueError("Nix store argument or input rejection differs")
        if (len(data) > MAX_DOCUMENT_BYTES) != (b"invocation exceeds the canonical ability document bound" in before[2]):
            raise ValueError("Nix store invocation boundary differs")
        records.append({"arguments": arguments, "stdin_bytes": len(data), "status": before[0],
                        "stdin_sha256": hashlib.sha256(data).hexdigest(), "stderr_sha256": hashlib.sha256(before[2]).hexdigest()})
    return records


def real_nix_test(tests, binary, nix_store, nix_tools):
    """Runs the retained Cargo case and requires the exact Bazel ignored case."""
    root = tests / "evidence/tests"
    results = json.loads((root / "index.json").read_text())["results"]
    selected = [result for result in results if result["identity"]["label"] == PREFIX + "static_real_nix"]
    if len(selected) != 1 or selected[0]["status"] != "PASSED":
        raise ValueError("source-built Nix Bazel test did not pass exactly once")
    cases = ET.parse(root / selected[0]["outputs"]["test.xml"]).findall("testcase")
    if (len(cases) != 1 or cases[0].attrib["name"] != REAL_NIX_CASE
            or any(child.tag != "system-out" for child in cases[0])):
        raise ValueError("source-built Nix Bazel test ran a different case or skipped it")
    bazel_stdout = cases[0].findtext("system-out", "")
    if "1 passed; 0 failed; 0 ignored" not in bazel_stdout or REAL_NIX_CASE not in bazel_stdout:
        raise ValueError("source-built Nix Bazel case did not retain its executed result")
    completed = subprocess.run([str(binary), "--exact", REAL_NIX_CASE, "--ignored", "--nocapture"],
                               env={**os.environ, "AOS_TEST_NIX_STORE": str(nix_store)},
                               capture_output=True, text=True, timeout=120, check=True)
    if "1 passed; 0 failed; 0 ignored" not in completed.stdout or REAL_NIX_CASE not in completed.stdout:
        raise ValueError("source-built Nix Cargo oracle did not execute the required case")
    events = [event for event in execution_events(tests)
              if event["targetLabel"] == PREFIX + "static_real_nix" and event["mnemonic"] == "TestRunner"]
    if len(events) != 1:
        raise ValueError("source-built Nix case has no unique test action")
    inputs = {}
    for name, path in {"bin/nix-store": nix_store, "closure.json": nix_tools / "closure.json"}.items():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        matching = [entry for entry in events[0]["inputs"]
                    if entry["path"].endswith("+aos_nix_test_tools/" + name)
                    and entry.get("digest", {}).get("hash") == digest]
        if len(matching) != 1:
            raise ValueError("Nix test omitted the exact executable or closure identity: " + name)
        inputs[name] = matching[0]
    return {"case": REAL_NIX_CASE, "bazel_stdout": bazel_stdout,
            "cargo_stdout": completed.stdout, "cargo_stderr": completed.stderr,
            "declared_action_inputs": inputs,
            "nix_store": str(nix_store), "scope": "Exact bytes, fixed-output path, validity, references and NAR dump in a private local?root store."}


def verify(options):
    """Requires installed, runtime, compiler, test and bounded-command parity."""
    packages = json.loads(options.packages.read_text())
    if set(packages) != {"ordinary", "bazel"} or any(set(value) != {"out"} for value in packages.values()):
        raise ValueError("Nix store qualification requires both installed packages")
    closures = runtime_closures(packages, json.loads(options.closure_attributes.read_text()))
    if closures["changes"] != {"out": {"added": [], "removed": []}}:
        raise ValueError("Nix store runtime closure differs")
    installed = {driver: inventory(value, options.readelf, None, elf_inspector=static_contract)
                 for driver, value in packages.items()}
    compare_installed(installed["ordinary"], installed["bazel"])
    for value in packages.values():
        companion = Path(value["out"]) / "libexec/nix-store"
        if not companion.is_symlink() or companion.readlink() != options.nix_store:
            raise ValueError("installed Nix store companion alias differs")
    actions = {}
    for role, build in [("production", options.build), ("release_tests", options.tests)]:
        events = execution_events(build)
        if not events or any(event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"] for event in events):
            raise ValueError("Nix store proof requires fresh Linux sandbox execution")
        actions[role] = len(events)
    if any(path.name in {"Cargo.toml", "Cargo.lock"} for path in options.workspace.rglob("Cargo.*")):
        raise ValueError("Nix store source selection retains first-party Cargo metadata")
    binaries = cargo_tests(options.oracle)
    messages = Path(packages["ordinary"]["out"]) / "nix-support/cargo-build-messages.jsonl"
    return {
        "schema_version": 1, "packages": packages, "installed": installed, "runtime_closures": closures,
        "fresh_linux_sandbox_actions": actions,
        "features": {
            "production": compare_features(options.build / "inventory.json", messages, PACKAGE_PATHS, required_packages=PACKAGE_PATHS),
            "release_tests": compare_features(options.tests / "inventory.json", options.oracle / "cargo-messages.jsonl", PACKAGE_PATHS, required_packages=PACKAGE_PATHS),
        },
        "production_profiles": production_profiles(options.build, messages),
        "test_parity": verify_tests(options.tests / "evidence/tests", binaries, allow_empty=[PREFIX + "static_bin"]),
        "real_nix_test": real_nix_test(options.tests, binaries[PREFIX + "static_unit"], options.nix_store, options.nix_tools),
        "doctest_parity": compare_doctests(options.tests / "evidence/tests", options.oracle / "cargo-tests.log",
                                           {PACKAGE: PACKAGE_PATHS[PACKAGE]}, target_suffix="_static"),
        "cli_cases": command_parity(packages), "live_system_activation_qualified": False,
        "production_default_cutover": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["packages", "build", "tests", "oracle", "workspace", "readelf", "nix-store", "nix-tools", "closure-attributes", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")
