"""Qualifies the installed static preparation provider against its Cargo package."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from installed_package import compare_installed, inventory, runtime_closures
from verify_ability_package import static_contract
from verify_cache import execution_events
from verify_pilot import verify as verify_tests
from verify_protocol import compare_doctests, compare_features
from verify_static_runtime import expanded_command


PREFIX = "//crates/boot/aos-boot-runtime:"
COMMAND = "aos-boot-preparation-provider"
PACKAGE_PATHS = {
    "aos-boot-runtime": "crates/boot/aos-boot-runtime",
    "aos-activation": "crates/activation/aos-activation",
    "aos-core": "crates/core/aos-core",
    "aos-module-format": "crates/modules/aos-module-format",
    "aos-artifact-evidence": "crates/artifacts/aos-artifact-evidence",
}


def cargo_tests(oracle):
    """Requires the independently compiled no-default-features test executables."""
    names = {
        "aos_boot_runtime": PREFIX + "preparation_unit",
        COMMAND: PREFIX + "preparation_bin",
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
            raise ValueError("duplicate Cargo preparation test target: " + name)
        binaries[label] = Path(event["executable"])
    if set(binaries) != set(names.values()) or any(not binary.is_file() for binary in binaries.values()):
        raise ValueError("Cargo oracle omits a preparation test executable")
    return binaries


def command_parity(packages):
    """Compares argument, malformed-envelope and input-bound rejection paths."""
    cases = [
        ([], b""),
        (["--help"], b""),
        (["invalid"], b""),
        (["apply"], b""),
        (["remove"], b""),
        (["observe"], b""),
        (["apply"], b"{}"),
        (["observe"], b"x" * (256 * 1024 + 1)),
    ]
    compared = []
    for arguments, data in cases:
        results = [
            subprocess.run([str(Path(packages[driver]["out"]) / "bin" / COMMAND), *arguments],
                           input=data, capture_output=True, timeout=30)
            for driver in ["ordinary", "bazel"]
        ]
        before, after = [(result.returncode, result.stdout, result.stderr) for result in results]
        if before != after or before[0] != 1 or before[1] or not before[2].startswith(COMMAND.encode() + b":"):
            raise ValueError("installed preparation rejection behavior differs: " + repr(arguments))
        compared.append({
            "arguments": arguments,
            "status": before[0],
            "stdin_size": len(data),
            "stdin_sha256": hashlib.sha256(data).hexdigest(),
            "stderr_sha256": hashlib.sha256(before[2]).hexdigest(),
        })
    return compared


def verify(options):
    packages = json.loads(options.packages.read_text())
    if set(packages) != {"ordinary", "bazel"} or any(set(outputs) != {"out"} for outputs in packages.values()):
        raise ValueError("preparation parity requires both installed production packages")
    closures = runtime_closures(packages, json.loads(options.closure_attributes.read_text()))
    installed = {
        driver: inventory(outputs, options.readelf, None, elf_inspector=static_contract)
        for driver, outputs in packages.items()
    }
    if compare_installed(installed["ordinary"], installed["bazel"]):
        raise ValueError("static preparation package changed library search paths")

    events = execution_events(options.build)
    if not events or any(event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]
                         for event in events):
        raise ValueError("preparation proof requires fresh Linux sandbox actions")
    links = [event for event in events if event["mnemonic"] == "Rustc"
             and event["targetLabel"] == PREFIX + "static_preparation_provider"]
    if len(links) != 1:
        raise ValueError("preparation proof omits the actual static link")
    event = links[0]
    hashes = {
        name: hashlib.sha256((options.libraries / name).read_bytes()).hexdigest()
        for name in ["static/lib/libc.a", "static/lib/libm.a", "static/lib/libgcc_eh.a", "static/closure.json"]
    }
    for name, digest in hashes.items():
        if not any(entry["path"].endswith("/" + name) and entry.get("digest", {}).get("hash") == digest
                   for entry in event["inputs"]):
            raise ValueError("preparation link omitted exact static input: " + name)
    arguments = expanded_command(json.loads((options.build / "evidence/actions.json").read_text()), event)
    for flag in ["target-feature=+crt-static", "relocation-model=static"]:
        if not any(flag in argument for argument in arguments):
            raise ValueError("preparation link omitted " + flag)

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
                         allow_empty=[PREFIX + "preparation_bin"])
    docs = compare_doctests(
        options.tests / "evidence/tests", options.oracle / "cargo-tests.log",
        {"aos-boot-runtime": PACKAGE_PATHS["aos-boot-runtime"]}, target_suffix="_preparation",
    )
    manifests = sorted(str(path.relative_to(options.workspace))
                       for path in (options.workspace / "crates").rglob("Cargo.*")
                       if path.name in {"Cargo.toml", "Cargo.lock"})
    if manifests:
        raise ValueError("preparation source selection retains first-party Cargo metadata")

    return {
        "schema_version": 1,
        "packages": packages,
        "installed": installed,
        "runtime_closures": closures,
        "features": features,
        "test_parity": tests,
        "doctest_parity": docs,
        "cli_parity": command_parity(packages),
        "static_inputs_sha256": hashes,
        "link_arguments": arguments,
        "sandboxed_cache_miss_actions": len(events),
        "first_party_rust_compilations": sum(event["mnemonic"] == "Rustc" and event["targetLabel"].startswith("//crates/")
                                              for event in events),
        "source_selection": {"workspace": str(options.workspace), "first_party_cargo_files": []},
        "limits": ["Native static installation, exact native features, release tests and bounded input rejection only. Live boot transactions, foreign hosts, numeric performance budgets and default cutover remain separate gates."],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["packages", "build", "tests", "oracle", "workspace", "libraries", "readelf",
                 "closure-attributes", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
