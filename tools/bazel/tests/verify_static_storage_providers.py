"""Qualifies both installed static storage commands against their Cargo packages."""

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
from verify_transaction_storage_provider import PACKAGE_PATHS, PREFIX


COMMANDS = {
    "cryptsetup": "aos-cryptsetup-provider",
    "storage_format": "aos-storage-format-provider",
}


def cargo_tests(oracle):
    """Requires the library and both independently compiled command test targets."""
    names = {"aos_activation_storage": PREFIX + "boot_transaction_unit"}
    names.update({command: PREFIX + "static_" + tag + "_bin" for tag, command in COMMANDS.items()})
    binaries = {}
    for line in (oracle / "cargo-messages.jsonl").read_text().splitlines():
        event = json.loads(line)
        name = event.get("target", {}).get("name")
        if (event.get("reason") != "compiler-artifact" or name not in names
                or not event.get("profile", {}).get("test") or not event.get("executable")):
            continue
        label = names[name]
        if label in binaries:
            raise ValueError("duplicate Cargo storage test target: " + name)
        binaries[label] = Path(event["executable"])
    if set(binaries) != set(names.values()) or any(not binary.is_file() for binary in binaries.values()):
        raise ValueError("Cargo oracle omits a static storage test executable")
    return binaries


def rejections(packages, command):
    """Compares installed argument, malformed invocation and document-bound errors."""
    cases = [
        ([], b""),
        (["--help"], b""),
        (["invalid"], b""),
        (["apply"], b""),
        (["remove"], b""),
        (["observe"], b""),
        (["apply"], b"{}"),
        (["observe"], b"x" * (32 * 1024 * 1024 + 1)),
    ]
    compared = []
    for arguments, data in cases:
        results = [
            subprocess.run([str(Path(packages[driver]["out"]) / "bin" / command), *arguments],
                           input=data, capture_output=True, timeout=30)
            for driver in ["ordinary", "bazel"]
        ]
        before, after = [(result.returncode, result.stdout, result.stderr) for result in results]
        if before != after or before[0] != 1 or before[1] or not before[2].startswith(command.encode() + b":"):
            raise ValueError("installed storage rejection behavior differs: " + command + repr(arguments))
        if len(data) > 32 * 1024 * 1024 and b"invocation exceeds the canonical document bound" not in before[2]:
            raise ValueError("installed storage command did not enforce its document bound")
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
    if set(packages) != set(COMMANDS):
        raise ValueError("static storage qualification requires both command packages")
    events = execution_events(options.build)
    if not events or any(event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]
                         for event in events):
        raise ValueError("static storage proof requires fresh Linux sandbox actions")
    graph = json.loads((options.build / "evidence/actions.json").read_text())
    hashes = {
        name: hashlib.sha256((options.libraries / name).read_bytes()).hexdigest()
        for name in ["static/lib/libc.a", "static/lib/libm.a", "static/lib/libgcc_eh.a", "static/closure.json"]
    }
    attributes = json.loads(options.closure_attributes.read_text())
    compared = {}
    for tag, command in COMMANDS.items():
        pair = packages[tag]
        if set(pair) != {"ordinary", "bazel"} or any(set(outputs) != {"out"} for outputs in pair.values()):
            raise ValueError("static storage parity requires both installed package outputs: " + tag)
        pair_attributes = {driver + "_out": attributes[tag + "_" + driver + "_out"] for driver in pair}
        closures = runtime_closures(pair, pair_attributes)
        installed = {
            driver: inventory(outputs, options.readelf, None, elf_inspector=static_contract)
            for driver, outputs in pair.items()
        }
        if compare_installed(installed["ordinary"], installed["bazel"]):
            raise ValueError("static storage package changed library search paths: " + tag)

        links = [event for event in events if event["mnemonic"] == "Rustc"
                 and event["targetLabel"] == PREFIX + "static_" + tag]
        if len(links) != 1:
            raise ValueError("static storage proof omits an actual link: " + tag)
        event = links[0]
        for name, digest in hashes.items():
            if not any(entry["path"].endswith("/" + name) and entry.get("digest", {}).get("hash") == digest
                       for entry in event["inputs"]):
                raise ValueError("static storage link omitted exact input: " + tag + ":" + name)
        arguments = expanded_command(graph, event)
        for flag in ["target-feature=+crt-static", "relocation-model=static"]:
            if not any(flag in argument for argument in arguments):
                raise ValueError("static storage link omitted " + flag + ":" + tag)
        compared[tag] = {
            "packages": pair,
            "installed": installed,
            "runtime_closures": closures,
            "production_features": compare_features(
                options.build / "inventory.json",
                Path(pair["ordinary"]["out"]) / "nix-support/cargo-build-messages.jsonl",
                PACKAGE_PATHS, required_packages=PACKAGE_PATHS,
            ),
            "cli_parity": rejections(pair, command),
            "link_arguments": arguments,
        }

    features = compare_features(
        options.tests / "inventory.json", options.oracle / "cargo-messages.jsonl",
        PACKAGE_PATHS, required_packages=PACKAGE_PATHS,
    )
    tests = verify_tests(
        options.tests / "evidence/tests", cargo_tests(options.oracle),
        allow_empty=[PREFIX + "static_" + tag + "_bin" for tag in COMMANDS],
    )
    docs = compare_doctests(
        options.tests / "evidence/tests", options.oracle / "cargo-tests.log",
        {"aos-activation-storage": PACKAGE_PATHS["aos-activation-storage"]}, target_suffix="_boot_transaction",
    )
    manifests = sorted(str(path.relative_to(options.workspace))
                       for path in (options.workspace / "crates").rglob("Cargo.*")
                       if path.name in {"Cargo.toml", "Cargo.lock"})
    if manifests:
        raise ValueError("static storage source selection retains first-party Cargo metadata")
    return {
        "schema_version": 1,
        "packages": compared,
        "test_features": features,
        "test_parity": tests,
        "doctest_parity": docs,
        "static_inputs_sha256": hashes,
        "sandboxed_cache_miss_actions": len(events),
        "first_party_rust_compilations": sum(event["mnemonic"] == "Rustc" and event["targetLabel"].startswith("//crates/")
                                              for event in events),
        "source_selection": {"workspace": str(options.workspace), "first_party_cargo_files": []},
        "limits": ["Native static installation, exact native features, release tests and bounded input rejection only. Real encrypted mappings, swap formatting, foreign hosts, numeric performance budgets and default cutover remain separate gates."],
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
