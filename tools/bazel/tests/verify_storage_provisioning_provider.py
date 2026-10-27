"""Qualifies static provisioning commands, installed helpers and required libraries."""

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
from verify_static_storage_providers import rejections
from verify_transaction_storage_provider import PACKAGE_PATHS, PREFIX


COMMANDS = {
    "provisioning": "aos-storage-provisioning-provider",
    "provisioning_marker": "aos-storage-provisioning-marker-observer",
}


def cargo_tests(oracle):
    """Requires both libraries and both independently compiled command tests."""
    names = {
        "aos_activation_storage": PREFIX + "boot_transaction_unit",
        "aos_storage_layout": "//crates/boot/aos-storage-layout:static_provisioning_unit",
    }
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
            raise ValueError("duplicate Cargo storage provisioning test target: " + name)
        binaries[label] = Path(event["executable"])
    if set(binaries) != set(names.values()) or any(not binary.is_file() for binary in binaries.values()):
        raise ValueError("Cargo oracle omits a storage provisioning test executable")
    return binaries


def marker_parity(packages):
    """Checks marker dispatch responses which perform no native device inspection."""
    command = COMMANDS["provisioning_marker"]
    compared = []
    for operation, action, expected in [
        ("observe", "apply", {"status": "retry-safe"}),
        ("observe", "remove", {"status": "absent"}),
        ("remove", "remove", {}),
    ]:
        # Observe and remove validate the invocation but never dispatch lsblk.
        # Nonexistent locators ensure these cases need no native device access.
        invocation = {
            "id": "marker", "revision": "first", "action": action, "previous": None,
            "input": {"root_device": "/nonexistent-root-device", "lsblk": "/nonexistent-lsblk"},
            "effect": {
                "owner": "storage", "identity": ["provisioning", "marker"], "input": {}, "inputs": {},
                "input_type": {"kind": "submodule", "open": False, "fields": {}}, "after": [],
                "results": {}, "dependencies": [], "revision": "first",
                "lifetime": "instance", "timeout_ms": 1000,
                "handler": {
                    "kind": "process",
                    "artifact": "/nix/store/00000000000000000000000000000000-handler",
                    "executable": "/nix/store/00000000000000000000000000000000-handler/bin/handler",
                },
            },
        }
        results = [
            subprocess.run([str(Path(packages[driver]["out"]) / "bin" / command), operation],
                           input=json.dumps(invocation).encode(), capture_output=True, timeout=30)
            for driver in ["ordinary", "bazel"]
        ]
        before, after = [(result.returncode, result.stdout, result.stderr) for result in results]
        if before != after or before[0] or before[2] or json.loads(before[1]) != expected:
            raise ValueError("installed provisioning marker dispatch differs: " + operation + ":" + action)
        compared.append({"operation": operation, "action": action, "response": expected})
    return compared


def storage_layout_link(options, hashes):
    """Checks the required layout test's actual static archive inputs and flags."""
    label = "//crates/boot/aos-storage-layout:static_provisioning_unit_binary"
    selected = [event for event in execution_events(options.tests)
                if event["mnemonic"] == "Rustc" and event["targetLabel"] == label]
    if len(selected) != 1:
        raise ValueError("storage-layout proof omits its actual test link")
    event = selected[0]
    if event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]:
        raise ValueError("storage-layout proof requires a fresh Linux test compilation")
    for name, digest in hashes.items():
        if not any(entry["path"].endswith("/" + name) and entry.get("digest", {}).get("hash") == digest
                   for entry in event["inputs"]):
            raise ValueError("storage-layout test omitted an exact static input: " + name)
    graph = json.loads((options.tests / "evidence/actions.json").read_text())
    arguments = expanded_command(graph, event)
    for flag in ["target-feature=+crt-static", "relocation-model=static"]:
        if not any(flag in argument for argument in arguments):
            raise ValueError("storage-layout test omitted " + flag)
    return {"target": label, "link_arguments": arguments, "static_inputs_sha256": hashes}


def verify(options):
    packages = json.loads(options.packages.read_text())
    if set(packages) != {"ordinary", "bazel"} or any(set(outputs) != {"out"} for outputs in packages.values()):
        raise ValueError("storage provisioning parity requires both installed production packages")
    closures = runtime_closures(packages, json.loads(options.closure_attributes.read_text()))
    installed = {
        driver: inventory(outputs, options.readelf, None, elf_inspector=static_contract)
        for driver, outputs in packages.items()
    }
    if compare_installed(installed["ordinary"], installed["bazel"]):
        raise ValueError("static storage provisioning package changed library search paths")
    events = execution_events(options.build)
    if not events or any(event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]
                         for event in events):
        raise ValueError("storage provisioning proof requires fresh Linux sandbox actions")
    graph = json.loads((options.build / "evidence/actions.json").read_text())
    hashes = {
        name: hashlib.sha256((options.libraries / name).read_bytes()).hexdigest()
        for name in ["static/lib/libc.a", "static/lib/libm.a", "static/lib/libgcc_eh.a", "static/closure.json"]
    }
    links = {}
    for tag in COMMANDS:
        selected = [event for event in events if event["mnemonic"] == "Rustc"
                    and event["targetLabel"] == PREFIX + "static_" + tag]
        if len(selected) != 1:
            raise ValueError("storage provisioning proof omits an actual static link: " + tag)
        event = selected[0]
        for name, digest in hashes.items():
            if not any(entry["path"].endswith("/" + name) and entry.get("digest", {}).get("hash") == digest
                       for entry in event["inputs"]):
                raise ValueError("storage provisioning link omitted exact input: " + tag + ":" + name)
        arguments = expanded_command(graph, event)
        for flag in ["target-feature=+crt-static", "relocation-model=static"]:
            if not any(flag in argument for argument in arguments):
                raise ValueError("storage provisioning link omitted " + flag + ":" + tag)
        links[tag] = arguments
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
    tests = verify_tests(
        options.tests / "evidence/tests", cargo_tests(options.oracle),
        allow_empty=[PREFIX + "static_" + tag + "_bin" for tag in COMMANDS],
    )
    docs = compare_doctests(
        options.tests / "evidence/tests", options.oracle / "cargo-tests.log",
        {name: PACKAGE_PATHS[name] for name in ["aos-activation-storage", "aos-storage-layout"]},
        package_target_suffixes={"aos-activation-storage": "_boot_transaction"},
    )
    manifests = sorted(str(path.relative_to(options.workspace))
                       for path in (options.workspace / "crates").rglob("Cargo.*")
                       if path.name in {"Cargo.toml", "Cargo.lock"})
    if manifests:
        raise ValueError("storage provisioning source selection retains first-party Cargo metadata")
    return {
        "schema_version": 1, "packages": packages, "installed": installed, "runtime_closures": closures,
        "features": features, "test_parity": tests, "doctest_parity": docs,
        "cli_parity": {command: rejections(packages, command) for command in COMMANDS.values()},
        "marker_dispatch_parity": marker_parity(packages),
        "storage_layout_test_link": storage_layout_link(options, hashes),
        "static_inputs_sha256": hashes, "link_arguments": links,
        "sandboxed_cache_miss_actions": len(events),
        "first_party_rust_compilations": sum(event["mnemonic"] == "Rustc" and event["targetLabel"].startswith("//crates/")
                                              for event in events),
        "source_selection": {"workspace": str(options.workspace), "first_party_cargo_files": []},
        "limits": ["Native static installation, exact native features, both required library test suites, installed helpers and admission errors only. Real block devices, MD arrays, VM boot, foreign hosts, numeric performance budgets and default cutover remain separate gates."],
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
