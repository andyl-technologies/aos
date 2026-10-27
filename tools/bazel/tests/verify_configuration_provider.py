"""Qualifies the installed dynamic configuration provider against its Cargo package."""

import argparse
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


PREFIX = "//crates/activation/aos-activation-config-files:"
COMMAND = "aos-configuration-provider"
MAX_DOCUMENT_BYTES = 256 * 1024
PACKAGE_PATHS = {
    "aos-activation-config-files": "crates/activation/aos-activation-config-files",
}


def cargo_tests(oracle):
    """Requires the independently compiled release test executables."""
    names = {
        "aos_activation_config_files": PREFIX + "unit",
        COMMAND: PREFIX + "bin_aos-configuration-provider",
    }
    binaries = {}
    for line in (oracle / "cargo-messages.jsonl").read_text().splitlines():
        event = json.loads(line)
        name = event.get("target", {}).get("name")
        if (event.get("reason") != "compiler-artifact" or name not in names
                or not event.get("profile", {}).get("test") or not event.get("executable")):
            continue
        label = names[name]
        if label in binaries:
            raise ValueError("duplicate Cargo configuration test target: " + name)
        binaries[label] = Path(event["executable"])
    if set(binaries) != set(names.values()) or any(not binary.is_file() for binary in binaries.values()):
        raise ValueError("Cargo oracle omits a configuration test executable")
    return binaries


def command_parity(packages):
    """Compares argument, malformed-envelope and input-bound rejection paths."""
    cases = [
        ([], b""),
        (["--state-directory"], b""),
        (["apply", "remove"], b""),
        (["invalid"], b""),
        (["apply"], b""),
        (["remove"], b""),
        (["observe"], b""),
        (["apply"], b"{}"),
        (["observe"], b"{}" + b" " * (MAX_DOCUMENT_BYTES - 2)),
        (["observe"], b"x" * (MAX_DOCUMENT_BYTES + 1)),
    ]
    compared = []
    for arguments, data in cases:
        results = [
            subprocess.run([str(Path(packages[driver]["out"]) / "bin" / COMMAND), *arguments],
                           input=data, capture_output=True, timeout=30)
            for driver in ["ordinary", "bazel"]
        ]
        before, after = [(result.returncode, result.stdout, result.stderr) for result in results]
        if (before != after or before[0] != 1 or before[1]
                or not before[2].startswith(b"native configuration handler:")):
            raise ValueError("installed configuration rejection behavior differs: " + repr(arguments))
        if (len(data) > MAX_DOCUMENT_BYTES
                and b"native invocation exceeds limit" not in before[2]):
            raise ValueError("installed configuration command did not enforce its document bound")
        if (len(data) == MAX_DOCUMENT_BYTES
                and b"native invocation exceeds limit" in before[2]):
            raise ValueError("installed configuration command rejected its permitted document size")
        compared.append({
            "arguments": arguments,
            "status": before[0],
            "stdin_size": len(data),
            "stdin_sha256": hashlib.sha256(data).hexdigest(),
            "stderr_sha256": hashlib.sha256(before[2]).hexdigest(),
        })
    for arguments in [["--help"], ["-h"]]:
        results = [subprocess.run([str(Path(packages[driver]["out"]) / "bin" / COMMAND), *arguments],
                                  capture_output=True, timeout=30)
                   for driver in ["ordinary", "bazel"]]
        before, after = [(result.returncode, result.stdout, result.stderr) for result in results]
        if before != after or before[0] or before[2] or not before[1].startswith(b"usage: aos-configuration-provider "):
            raise ValueError("installed configuration help behavior differs")
        compared.append({"arguments": arguments, "status": 0,
                         "stdout_sha256": hashlib.sha256(before[1]).hexdigest()})
    return compared


def production_profiles(build, messages):
    """Checks actual production compiler settings against the original package."""
    cargo = {}
    for line in messages.read_text().splitlines():
        event = json.loads(line)
        if event.get("reason") != "compiler-artifact":
            continue
        name = Path(event["manifest_path"]).parent.name
        if name not in PACKAGE_PATHS:
            continue
        profile = event["profile"]
        if (profile["opt_level"] != "3" or profile["debug_assertions"]
                or profile["overflow_checks"] or profile["debuginfo"]):
            raise ValueError("ordinary configuration production compiler profile changed")
        cargo[event["target"]["name"]] = profile
    if len(cargo) != len(PACKAGE_PATHS) + 1:
        raise ValueError("ordinary configuration production profile proof omits a compiler target")

    graph = json.loads((build / "evidence/actions.json").read_text())
    bazel = {}
    for event in execution_events(build):
        if event["mnemonic"] != "Rustc" or not event["targetLabel"].startswith("//crates/"):
            continue
        options = compiler_options(expanded_command(graph, event))["effective_scalar_codegen"]
        if (options.get("opt-level") != "3" or options.get("debuginfo") != "0"
                or options.get("debug-assertions") not in {"no", "off", "false"}
                or options.get("overflow-checks") not in {"no", "off", "false"}):
            raise ValueError("Bazel configuration production compiler profile differs")
        bazel[event["targetLabel"]] = options
    if len(bazel) != len(cargo):
        raise ValueError("configuration production compiler target count differs")
    return {"cargo": cargo, "bazel": bazel}


def native_helper(options):
    """Requires actual C source and compiler options, plus the declared NSS test pin."""
    source = options.workspace / "pkgs/system/_aos-configuration-provider/account-lookup.c"
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    records = {}
    for name, build in [("production", options.build), ("release_tests", options.tests)]:
        events = execution_events(build)
        if not events or any(event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]
                             for event in events):
            raise ValueError("configuration proof requires fresh Linux sandbox actions")
        graph = json.loads((build / "evidence/actions.json").read_text())
        selected = [event for event in events if event["targetLabel"] == PREFIX + "aos-account-lookup"
                    and event["mnemonic"] == "CppCompile"]
        links = [event for event in events if event["targetLabel"] == PREFIX + "aos-account-lookup"
                 and event["mnemonic"] == "CppLink"]
        if len(selected) != 1 or len(links) != 1:
            raise ValueError("configuration proof omits the native companion compilation or link")
        compile_event = selected[0]
        command = expanded_command(graph, compile_event)
        required = {"-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"}
        if not required.issubset(command):
            raise ValueError("native account helper compiler policy differs")
        if not any(entry["path"].endswith("/account-lookup.c")
                   and entry.get("digest", {}).get("hash") == digest for entry in compile_event["inputs"]):
            raise ValueError("native account helper did not compile the exact declared source")
        records[name] = {"source_sha256": digest, "compile_command": command,
                         "link_command": expanded_command(graph, links[0]),
                         "sandboxed_cache_miss_actions": len(events)}

    traces = [json.loads(line) for line in (options.oracle / "compiler-arguments.jsonl").read_text().splitlines()]
    pins = {entry["environment"].get("AOS_ACCOUNT_LOOKUP") for entry in traces
            if "--test" in entry["arguments"] and "aos_activation_config_files" in entry["arguments"]}
    if len(pins) != 1 or None in pins or any(not Path(pin).is_absolute() or not Path(pin).is_file() for pin in pins):
        raise ValueError("Cargo NSS unit test omits its declared source-built native helper")
    records["cargo_test_helper"] = sorted(pins)
    events = [event for event in execution_events(options.tests)
              if event["mnemonic"] == "TestRunner" and event["targetLabel"] == PREFIX + "unit"]
    if len(events) != 1:
        raise ValueError("NSS proof omits the actual unit-test execution")
    event = events[0]
    environment = {entry["name"]: entry["value"] for entry in event["environmentVariables"]}
    workspace = environment["TEST_WORKSPACE"]
    package = "crates/activation/aos-activation-config-files/"

    def runfile(path):
        return '"${TEST_SRCDIR:?}/"' + "'" + workspace + "/" + path + "'"

    # Bind the declared environment to the wrapper bytes consumed by TestRunner;
    # otherwise an early-returning NSS test could appear to pass without a pin.
    script = ("#!" + str(options.bash) + "\nset -euo pipefail\n"
              + "export AOS_TEST_ACCOUNT_LOOKUP=" + runfile(package + "aos-account-lookup") + "\n"
              + "exec '" + str(options.python) + "' " + runfile("tools/bazel/testing/runner.py")
              + " --binary " + runfile(package + "unit_binary")
              + " --policy " + runfile("tools/bazel/testing/policy.json")
              + " --package 'aos-activation-config-files' --jobs 4 \"$@\"\n")
    digest = hashlib.sha256(script.encode()).hexdigest()
    wrappers = [entry for entry in event["inputs"]
                if entry["path"].endswith(".runfiles/" + workspace + "/" + package + "unit")]
    helpers = [entry for entry in event["inputs"]
               if entry["path"].endswith(".runfiles/" + workspace + "/" + package + "aos-account-lookup")]
    if len(wrappers) != 1 or wrappers[0].get("digest", {}).get("hash") != digest or len(helpers) != 1:
        raise ValueError("actual NSS test wrapper or native-helper input differs from its declaration")
    records["bazel_test_helper"] = {"wrapper_sha256": digest, "helper_input": helpers[0]}
    return records


def verify(options):
    packages = json.loads(options.packages.read_text())
    if (set(packages) != {"ordinary", "bazel"}
            or any(set(outputs) != {"out"} for outputs in packages.values())):
        raise ValueError("configuration parity requires both installed production packages")
    closures = runtime_closures(packages, json.loads(options.closure_attributes.read_text()))
    installed = {
        driver: inventory(outputs, options.readelf, options.loader)
        for driver, outputs in packages.items()
    }
    if closures["changes"] != {"out": {"added": [], "removed": []}}:
        raise ValueError("installed configuration package changed its required runtime closure")
    search_changes = compare_installed(installed["ordinary"], installed["bazel"])

    events = execution_events(options.build)
    if not events or any(event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]
                         for event in events):
        raise ValueError("configuration proof requires fresh Linux sandbox actions")
    links = [event for event in events if event["mnemonic"] == "Rustc"
             and event["targetLabel"] == PREFIX + COMMAND]
    if len(links) != 1:
        raise ValueError("configuration proof omits the installed program compilation")

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
                         allow_empty=[PREFIX + "bin_aos-configuration-provider"])
    docs = compare_doctests(
        options.tests / "evidence/tests", options.oracle / "cargo-tests.log",
        {"aos-activation-config-files": PACKAGE_PATHS["aos-activation-config-files"]},
    )
    manifests = sorted(str(path.relative_to(options.workspace))
                       for path in (options.workspace / "crates").rglob("Cargo.*")
                       if path.name in {"Cargo.toml", "Cargo.lock"})
    if manifests:
        raise ValueError("configuration source selection retains first-party Cargo metadata")

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
        "doctest_parity": docs,
        "cli_parity": command_parity(packages),
        "library_search_changes": search_changes,
        "sandboxed_cache_miss_actions": len(events),
        "first_party_rust_compilations": sum(
            event["mnemonic"] == "Rustc" and event["targetLabel"].startswith("//crates/")
            for event in events
        ),
        "native_helper": native_helper(options),
        "source_selection": {"workspace": str(options.workspace), "first_party_cargo_files": []},
        "limits": [
            "Native dynamic installation, exact compiler features, release-profile tests and bounded input rejection only.",
            "Privileged production-root configuration effects, foreign hosts, numeric performance budgets and default cutover remain separate gates.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["packages", "build", "tests", "oracle", "workspace", "readelf", "loader",
                 "closure-attributes", "bash", "python", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
