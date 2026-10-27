"""Qualifies the installed dynamic metadata provider against its Cargo package."""

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


PREFIX = "//crates/boot/aos-platform-metadata:"
COMMANDS = ["aos-metadata-acquisition-provider", "aos-metadata-policy-provider"]
MAX_DOCUMENT_BYTES = 32 * 1024 * 1024
PACKAGE_PATHS = {
    "aos-platform-metadata": "crates/boot/aos-platform-metadata",
    "aos-activation": "crates/activation/aos-activation",
    "aos-artifact-evidence": "crates/artifacts/aos-artifact-evidence",
    "aos-core": "crates/core/aos-core",
    "aos-module-format": "crates/modules/aos-module-format",
    "aos-nar": "crates/artifacts/aos-nar",
    "aos-nix": "crates/nix/aos-nix",
    "aos-storage-layout": "crates/boot/aos-storage-layout",
    "aos-transfer": "crates/transfer/aos-transfer",
    "libssh2-sys": "crates/bindings/libssh2-sys",
}


def cargo_tests(oracle):
    """Requires the independently compiled release test executables."""
    names = {"aos_platform_metadata": PREFIX + "unit"}
    names.update({command: PREFIX + "bin_" + command for command in COMMANDS})
    binaries = {}
    for line in (oracle / "cargo-messages.jsonl").read_text().splitlines():
        event = json.loads(line)
        name = event.get("target", {}).get("name")
        if (event.get("reason") != "compiler-artifact" or name not in names
                or not event.get("profile", {}).get("test") or not event.get("executable")):
            continue
        label = names[name]
        if label in binaries:
            raise ValueError("duplicate Cargo metadata test target: " + name)
        binaries[label] = Path(event["executable"])
    if set(binaries) != set(names.values()) or any(not binary.is_file() for binary in binaries.values()):
        raise ValueError("Cargo oracle omits a metadata test executable")
    return binaries


def command_parity(packages, command):
    """Compares argument, malformed-envelope and input-bound rejection paths."""
    cases = [
        ([], b""),
        (["--help"], b""),
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
            subprocess.run([str(Path(packages[driver]["out"]) / "bin" / command), *arguments],
                           input=data, capture_output=True, timeout=30)
            for driver in ["ordinary", "bazel"]
        ]
        before, after = [(result.returncode, result.stdout, result.stderr) for result in results]
        if (before != after or before[0] != 1 or before[1]
                or not before[2].startswith(command.encode() + b":")):
            raise ValueError("installed metadata rejection behavior differs: " + repr(arguments))
        if (len(data) > MAX_DOCUMENT_BYTES
                and b"metadata invocation exceeds bound" not in before[2]):
            raise ValueError("installed metadata command did not enforce its document bound")
        if (len(data) == MAX_DOCUMENT_BYTES
                and b"metadata invocation exceeds bound" in before[2]):
            raise ValueError("installed metadata command rejected its permitted document size")
        compared.append({
            "arguments": arguments,
            "status": before[0],
            "stdin_size": len(data),
            "stdin_sha256": hashlib.sha256(data).hexdigest(),
            "stderr_sha256": hashlib.sha256(before[2]).hexdigest(),
        })
    return compared


def production_profiles(build, messages):
    """Compares target profiles and the libssh2 execution build script separately."""
    cargo = {}
    for line in messages.read_text().splitlines():
        event = json.loads(line)
        if event.get("reason") != "compiler-artifact":
            continue
        package = Path(event["manifest_path"]).parent.name
        if package not in PACKAGE_PATHS:
            continue
        execution = event["target"]["kind"] == ["custom-build"]
        profile = event["profile"]
        if (profile["opt_level"] != ("0" if execution else "3")
                or profile["debug_assertions"] or profile["overflow_checks"] or profile["debuginfo"]):
            raise ValueError("ordinary metadata compiler profile changed")
        key = package + ":" + event["target"]["name"]
        if key in cargo:
            raise ValueError("duplicate Cargo metadata production compiler target")
        cargo[key] = {"role": "execution" if execution else "target", "profile": profile}
    if len(cargo) != len(PACKAGE_PATHS) + len(COMMANDS) + 1:
        raise ValueError("ordinary metadata profile proof omits a compiler target")

    graph = json.loads((build / "evidence/actions.json").read_text())
    bazel = {}
    for event in execution_events(build):
        label = event["targetLabel"]
        if event["mnemonic"] != "Rustc" or not label.startswith("//crates/"):
            continue
        execution = label == "//crates/bindings/libssh2-sys:build_script_program"
        options = compiler_options(expanded_command(graph, event))["effective_scalar_codegen"]
        if (options.get("opt-level") != ("0" if execution else "3") or options.get("debuginfo") != "0"
                or options.get("debug-assertions") not in {"no", "off", "false"}
                or options.get("overflow-checks") not in {"no", "off", "false"}):
            raise ValueError("Bazel metadata production compiler profile differs: " + label)
        if label in bazel:
            raise ValueError("duplicate Bazel metadata production compiler target")
        bazel[label] = {"role": "execution" if execution else "target", "compiler_options": options}
    if (len(bazel) != len(cargo)
            or sum(value["role"] == "execution" for value in cargo.values()) != 1
            or sum(value["role"] == "execution" for value in bazel.values()) != 1):
        raise ValueError("metadata compiler target or execution build-script count differs")
    return {"cargo": cargo, "bazel": bazel}


def verify(options):
    packages = json.loads(options.packages.read_text())
    if (set(packages) != {"ordinary", "bazel"}
            or any(set(outputs) != {"out"} for outputs in packages.values())):
        raise ValueError("metadata parity requires both installed production packages")
    closures = runtime_closures(packages, json.loads(options.closure_attributes.read_text()))
    installed = {
        driver: inventory(outputs, options.readelf, options.loader)
        for driver, outputs in packages.items()
    }
    if closures["changes"] != {"out": {"added": [], "removed": []}}:
        raise ValueError("installed metadata package changed its required runtime closure")
    search_changes = compare_installed(installed["ordinary"], installed["bazel"])

    events = execution_events(options.build)
    if not events or any(event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]
                         for event in events):
        raise ValueError("metadata proof requires fresh Linux sandbox actions")
    links = [event for event in events if event["mnemonic"] == "Rustc"
             and event["targetLabel"] in {PREFIX + command for command in COMMANDS}]
    if len(links) != len(COMMANDS):
        raise ValueError("metadata proof omits the installed program compilation")

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
                         allow_empty=[PREFIX + "bin_" + command for command in COMMANDS])
    docs = compare_doctests(
        options.tests / "evidence/tests", options.oracle / "cargo-tests.log",
        {"aos-platform-metadata": PACKAGE_PATHS["aos-platform-metadata"]},
    )
    manifests = sorted(str(path.relative_to(options.workspace))
                       for path in (options.workspace / "crates").rglob("Cargo.*")
                       if path.name in {"Cargo.toml", "Cargo.lock"})
    if manifests:
        raise ValueError("metadata source selection retains first-party Cargo metadata")

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
            "Cloud acquisition, ignored native transaction contract, foreign hosts, numeric performance budgets and default cutover remain separate gates.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["packages", "build", "tests", "oracle", "workspace", "readelf", "loader",
                 "closure-attributes", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
