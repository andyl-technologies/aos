"""Qualifies the six installed systemd commands against its Cargo package."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess

from installed_package import compare_installed, inventory, runtime_closures
from verify_cache import execution_events
from verify_compiler_options import compiler_options
from verify_pilot import verify as verify_tests
from verify_protocol import compare_doctests, compare_features
from verify_static_runtime import expanded_command


SERVICE = "//crates/activation/aos-activation-systemd:"
BOOT = "//crates/boot/aos-boot-runtime:"
SERVICE_COMMANDS = ["aos-systemd-native-resource-provider", "aos-systemd-credential-encrypt"]
BOOT_COMMANDS = ["aos-systemd-boot-platform", "aos-systemd-image-stage",
                 "aos-systemd-image-evidence", "aos-systemd-initrd-store"]
COMMANDS = SERVICE_COMMANDS + BOOT_COMMANDS
PACKAGE_PATHS = {
    "aos-activation": "crates/activation/aos-activation",
    "aos-activation-systemd": "crates/activation/aos-activation-systemd",
    "aos-artifact-evidence": "crates/artifacts/aos-artifact-evidence",
    "aos-boot-identity": "crates/boot/aos-boot-identity",
    "aos-boot-runtime": "crates/boot/aos-boot-runtime",
    "aos-core": "crates/core/aos-core",
    "aos-module-format": "crates/modules/aos-module-format",
    "aos-nar": "crates/artifacts/aos-nar",
    "aos-nix": "crates/nix/aos-nix",
    "aos-oci-types": "crates/artifacts/aos-oci-types",
    "aos-registry-format": "crates/registry/aos-registry-format",
    "aos-release-format": "crates/release/aos-release-format",
    "aos-systemd-client": "crates/linux/aos-systemd-client"
}
TEST_NAMES = {"aos_boot_runtime": BOOT + "unit"}
TEST_NAMES.update({command: SERVICE + "bin_" + command for command in SERVICE_COMMANDS})
TEST_NAMES.update({command: BOOT + "bin_" + command
                   for command in BOOT_COMMANDS + ["aos-boot-preparation-provider"]})


def cargo_tests(oracle):
    """Requires all eight independently compiled release test executables."""
    binaries = {}
    for line in (oracle / "cargo-messages.jsonl").read_text().splitlines():
        event = json.loads(line)
        name = event.get("target", {}).get("name")
        if (event.get("reason") != "compiler-artifact" or name not in TEST_NAMES
                or not event.get("profile", {}).get("test") or not event.get("executable")):
            continue
        label = TEST_NAMES[name]
        if label in binaries:
            raise ValueError("duplicate Cargo systemd test target: " + name)
        binaries[label] = Path(event["executable"])
    if set(binaries) != set(TEST_NAMES.values()) or any(not binary.is_file() for binary in binaries.values()):
        raise ValueError("Cargo oracle omits a systemd test executable")
    return binaries


def command_parity(packages, command):
    """Compares installed argument and malformed invocation rejection paths."""
    cases = [([], b""), (["--help"], b""), (["invalid"], b""),
             (["apply"], b""), (["remove"], b""), (["observe"], b"{}")]
    document_bound = 256 * 1024
    if command == SERVICE_COMMANDS[0]:
        cases.extend([
            (["observe"], b"{}" + b" " * (document_bound - 2)),
            (["observe"], b"x" * (document_bound + 1)),
        ])
    compared = []
    for arguments, data in cases:
        results = [
            subprocess.run([str(Path(packages[driver]["out"]) / "bin" / command), *arguments],
                           input=data, capture_output=True, timeout=30)
            for driver in ["ordinary", "bazel"]
        ]
        before, after = [(result.returncode, result.stdout, result.stderr) for result in results]
        if (before != after or before[0] != 1 or before[1]
                or not before[2].startswith((b"native systemd resource:" if command == SERVICE_COMMANDS[0]
                                             else command.encode() + b":"))):
            raise ValueError("installed systemd rejection behavior differs: " + repr(arguments))
        if command == SERVICE_COMMANDS[0]:
            bounded = b"invocation exceeds 256 KiB" in before[2]
            if (len(data) > document_bound) != bounded:
                raise ValueError("native systemd invocation bound changed")
        compared.append({
            "arguments": arguments, "status": before[0], "stdin_size": len(data),
            "stdin_sha256": hashlib.sha256(data).hexdigest(),
            "stderr_sha256": hashlib.sha256(before[2]).hexdigest(),
        })
    return compared


def production_profiles(build, messages):
    """Checks all eighteen first-party production compiler targets and profiles."""
    targets = {
        package + ":" + package.replace("-", "_"): "//" + path + ":lib"
        for package, path in PACKAGE_PATHS.items() if package != "aos-activation-systemd"
    }
    targets.update({"aos-activation-systemd:" + name: SERVICE + name for name in SERVICE_COMMANDS})
    targets.update({"aos-boot-runtime:" + name: BOOT + name for name in BOOT_COMMANDS})
    cargo = {}
    for line in messages.read_text().splitlines():
        event = json.loads(line)
        if event.get("reason") != "compiler-artifact":
            continue
        package = Path(event["manifest_path"]).parent.name
        if package not in PACKAGE_PATHS:
            continue
        profile = event["profile"]
        if (profile["opt_level"] != "3" or profile["debug_assertions"]
                or profile["overflow_checks"] or profile["debuginfo"]):
            raise ValueError("ordinary systemd compiler profile changed")
        key = package + ":" + event["target"]["name"]
        if key in cargo or key not in targets:
            raise ValueError("unexpected or duplicate Cargo systemd compiler target: " + key)
        cargo[key] = profile
    if set(cargo) != set(targets):
        raise ValueError("ordinary systemd profile proof omits a compiler target")

    graph = json.loads((build / "evidence/actions.json").read_text())
    bazel = {}
    for event in execution_events(build):
        label = event["targetLabel"]
        if event["mnemonic"] != "Rustc" or not label.startswith("//crates/"):
            continue
        options = compiler_options(expanded_command(graph, event))["effective_scalar_codegen"]
        if (options.get("opt-level") != "3" or options.get("debuginfo") != "0"
                or options.get("debug-assertions") not in {"no", "off", "false"}
                or options.get("overflow-checks") not in {"no", "off", "false"}):
            raise ValueError("Bazel systemd production compiler profile differs: " + label)
        if label in bazel:
            raise ValueError("duplicate Bazel systemd production compiler target")
        bazel[label] = options
    if set(bazel) != set(targets.values()) or len(targets) != 18:
        raise ValueError("systemd production compiler targets differ")
    return {"targets": targets, "cargo": cargo, "bazel": bazel}


def test_setup(options, events=None):
    """Binds boot unit execution to the exact source-built Nix setup and wrapper."""
    if events is None:
        events = execution_events(options.tests)
    if not events or any(event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]
                         for event in events):
        raise ValueError("systemd release tests require fresh Linux sandbox execution")
    selected = [event for event in events
                if event["mnemonic"] == "TestRunner" and event["targetLabel"] == BOOT + "unit"]
    if len(selected) != 1:
        raise ValueError("systemd proof omits boot unit execution")
    event = selected[0]
    inputs = event["inputs"]
    setup = [entry for entry in inputs if entry["path"].endswith("/test-setup")]
    if len(setup) != 1 or ".runfiles/" not in setup[0]["path"]:
        raise ValueError("boot unit execution omits its declared setup")
    setup_bytes = (options.test_tools / "test-setup").read_bytes()
    setup_digest = hashlib.sha256(setup_bytes).hexdigest()
    if setup[0].get("digest", {}).get("hash") != setup_digest:
        raise ValueError("boot unit execution setup differs from its source-built declaration")

    environment = {entry["name"]: entry["value"] for entry in event["environmentVariables"]}
    workspace = environment["TEST_WORKSPACE"]
    package = workspace + "/crates/boot/aos-boot-runtime/"

    def runfile(name):
        return '"${TEST_SRCDIR:?}/"' + "'" + name + "'"

    script = ("#!" + str(options.bash) + "\nset -euo pipefail\nexec "
              + runfile(setup[0]["path"].split(".runfiles/", 1)[1])
              + " '" + str(options.python) + "' " + runfile(workspace + "/tools/bazel/testing/runner.py")
              + " --binary " + runfile(package + "unit_binary")
              + " --policy " + runfile(workspace + "/tools/bazel/testing/policy.json")
              + " --package 'aos-boot-runtime' --jobs 4 \"$@\"\n")
    digest = hashlib.sha256(script.encode()).hexdigest()
    wrappers = [entry for entry in inputs if entry["path"].endswith(".runfiles/" + package + "unit")]
    if len(wrappers) != 1 or wrappers[0].get("digest", {}).get("hash") != digest:
        raise ValueError("boot unit execution did not consume the wrapper selecting its setup")
    return {"setup": str(options.test_tools), "setup_sha256": setup_digest,
            "actual_setup_input": setup[0], "wrapper_sha256": digest,
            "sandboxed_cache_miss_actions": len(events),
            "native_closure": json.loads((options.test_tools / "closure.json").read_text())}


def test_setup_negative_controls(options):
    """Rejects altered setup inputs, wrapper inputs and execution provenance."""
    events = [event for event in execution_events(options.tests)
              if event["mnemonic"] == "TestRunner" and event["targetLabel"] == BOOT + "unit"]
    if len(events) != 1:
        raise ValueError("negative controls require the actual boot test execution")
    rejections = {}
    for kind in ["setup_digest", "wrapper_digest", "cache_hit", "runner"]:
        event = copy.deepcopy(events[0])
        if kind in {"setup_digest", "wrapper_digest"}:
            suffix = "/test-setup" if kind == "setup_digest" else "/crates/boot/aos-boot-runtime/unit"
            inputs = [entry for entry in event["inputs"] if entry["path"].endswith(suffix)]
            if len(inputs) != 1:
                raise ValueError("negative control lacks its actual execution input")
            inputs[0]["digest"]["hash"] = "00" * 32
        elif kind == "cache_hit":
            event["cacheHit"] = True
        else:
            event["runner"] = "local"
        try:
            test_setup(options, [event])
        except ValueError as error:
            rejections[kind] = str(error)
        else:
            raise ValueError("systemd test proof accepted negative control: " + kind)
    return {"status": "PASS", "rejections": rejections}


def verify(options):
    packages = json.loads(options.packages.read_text())
    if (set(packages) != {"ordinary", "bazel"}
            or any(set(outputs) != {"out"} for outputs in packages.values())):
        raise ValueError("systemd parity requires both installed production packages")
    closures = runtime_closures(packages, json.loads(options.closure_attributes.read_text()))
    installed = {
        driver: inventory(outputs, options.readelf, options.loader)
        for driver, outputs in packages.items()
    }
    if closures["changes"] != {"out": {"added": [], "removed": []}}:
        raise ValueError("installed systemd package changed its required runtime closure")
    search_changes = compare_installed(installed["ordinary"], installed["bazel"])

    events = execution_events(options.build)
    if not events or any(event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]
                         for event in events):
        raise ValueError("systemd proof requires fresh Linux sandbox actions")
    links = [event for event in events if event["mnemonic"] == "Rustc"
             and event["targetLabel"] in (
                 {SERVICE + command for command in SERVICE_COMMANDS}
                 | {BOOT + command for command in BOOT_COMMANDS})]
    if len(links) != len(COMMANDS):
        raise ValueError("systemd proof omits the installed program compilation")

    features = {
        "production": compare_features(
            options.build / "inventory.json",
            Path(packages["ordinary"]["out"]) / "nix-support/cargo-build-messages.jsonl",
            PACKAGE_PATHS, required_packages=PACKAGE_PATHS,
        ),
        "release_tests": compare_features(
            options.tests / "inventory.json", options.oracle / "cargo-messages.jsonl",
            PACKAGE_PATHS, required_packages=PACKAGE_PATHS,
        ),
    }
    tests = verify_tests(options.tests / "evidence/tests", cargo_tests(options.oracle),
                         allow_empty=[BOOT + "bin_" + command
                                      for command in BOOT_COMMANDS + ["aos-boot-preparation-provider"]])
    docs = compare_doctests(
        options.tests / "evidence/tests", options.oracle / "cargo-tests.log",
        {"aos-boot-runtime": PACKAGE_PATHS["aos-boot-runtime"]},
    )
    manifests = sorted(str(path.relative_to(options.workspace))
                       for path in (options.workspace / "crates").rglob("Cargo.*")
                       if path.name in {"Cargo.toml", "Cargo.lock"})
    if manifests:
        raise ValueError("systemd source selection retains first-party Cargo metadata")

    return {
        "schema_version": 1,
        "packages": packages,
        "installed": installed,
        "runtime_closures": closures,
        "features": features,
        "production_profiles": production_profiles(
            options.build, Path(packages["ordinary"]["out"]) / "nix-support/cargo-build-messages.jsonl",
        ),
        "test_parity": tests,
        "test_setup": test_setup(options),
        "test_setup_negative_controls": test_setup_negative_controls(options),
        "doctest_parity": docs,
        "cli_parity": {command: command_parity(packages, command) for command in COMMANDS},
        "library_search_changes": search_changes,
        "sandboxed_cache_miss_actions": len(events),
        "first_party_rust_compilations": sum(
            event["mnemonic"] == "Rustc" and event["targetLabel"].startswith("//crates/")
            for event in events
        ),
        "source_selection": {"workspace": str(options.workspace), "first_party_cargo_files": []},
        "limits": [
            "Native dynamic installation, exact compiler features, release-profile tests and bounded input rejection only.",
            "Live systemd DBus effects, credential encryption with a TPM, foreign hosts, numeric performance budgets and default cutover remain separate gates.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["packages", "build", "tests", "oracle", "workspace", "readelf", "loader",
                 "closure-attributes", "test-tools", "bash", "python", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
