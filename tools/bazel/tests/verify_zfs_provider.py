"""Qualifies installed static OpenZFS commands and their compiled version input."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from installed_package import compare_installed, inventory, runtime_closures
from reconstruct_compiler_inputs import reconstruct
from verify_ability_package import static_contract
from verify_cache import execution_events
from verify_pilot import verify as verify_tests
from verify_protocol import compare_doctests, compare_features
from verify_static_runtime import expanded_command
from verify_static_storage_providers import rejections
from verify_transaction_storage_provider import PACKAGE_PATHS, PREFIX


COMMANDS = {
    "zfs_pool": "aos-zfs-pool-provider",
    "zfs_dataset": "aos-zfs-dataset-provider",
    "zfs_memory_policy": "aos-zfs-memory-policy",
    "zfs_maintenance": "aos-zfs-maintenance",
}


def cargo_tests(oracle):
    """Requires the library and all four independently compiled command tests."""
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
            raise ValueError("duplicate Cargo OpenZFS test target: " + name)
        binaries[label] = Path(event["executable"])
    if set(binaries) != set(names.values()) or any(not binary.is_file() for binary in binaries.values()):
        raise ValueError("Cargo oracle omits an OpenZFS test executable")
    return binaries


def command_parity(packages):
    """Checks admission errors without loading modules, querying pools or writing sysfs."""
    compared = {command: rejections(packages, command) for tag, command in COMMANDS.items()
                if tag in {"zfs_pool", "zfs_dataset"}}
    cases = {
        "aos-zfs-memory-policy": [[], ["--help"], ["invalid"], ["apply"],
                                  ["apply", *(["not-a-number"] * 8)],
                                  ["verify", *(["not-a-number"] * 8)]],
        "aos-zfs-maintenance": [[], ["--help"], ["invalid"], ["health"], ["metrics"], ["report-undeclared"]],
    }
    for command, arguments_list in cases.items():
        compared[command] = []
        for arguments in arguments_list:
            results = [
                subprocess.run([str(Path(packages[driver]["out"]) / "bin" / command), *arguments],
                               capture_output=True, timeout=30)
                for driver in ["ordinary", "bazel"]
            ]
            before, after = [(result.returncode, result.stdout, result.stderr) for result in results]
            if before != after or before[0] != 1 or before[1] or not before[2].startswith(command.encode() + b":"):
                raise ValueError("installed OpenZFS admission behavior differs: " + command + repr(arguments))
            compared[command].append({"arguments": arguments, "status": before[0],
                                      "stderr_sha256": hashlib.sha256(before[2]).hexdigest()})
    return compared


def compiled_version(options):
    """Reconstructs the version environment consumed by actual compiler executions."""
    expected = ("AOS_ZFS_VERSION=" + options.zfs_version + "\n").encode()
    version_file = options.runtime / "version.env"
    if version_file.read_bytes() != expected:
        raise ValueError("OpenZFS compiler version repository differs from its runtime package")
    digest = hashlib.sha256(expected).hexdigest()
    compiled = {}
    for role, build, labels in [
        ("production", options.build, {PREFIX + "static_zfs_memory_policy"}),
        ("release_tests", options.tests,
         {PREFIX + "static_zfs_memory_policy", PREFIX + "static_zfs_memory_policy_bin_binary"}),
    ]:
        evidence = build / "evidence"
        events = execution_events(build)
        actions = reconstruct(
            json.loads((evidence / "actions.json").read_text()), events,
            json.loads((evidence / "compiler-inputs.json").read_text()),
        )["actions"]
        selected = [action for action in actions if action["target_label"] in labels]
        if {action["target_label"] for action in selected} != labels or len(selected) != len(labels):
            raise ValueError("OpenZFS version proof omits a compiler execution: " + role)
        for action in selected:
            if action["environment"].get("AOS_ZFS_VERSION") != options.zfs_version:
                raise ValueError("executed OpenZFS compiler environment lost the packaged version")
            matches = [event for event in events if event["mnemonic"] == "Rustc"
                       and event["targetLabel"] == action["target_label"]]
            if len(matches) != 1:
                raise ValueError("OpenZFS version proof has ambiguous execution evidence")
            event = matches[0]
            if event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]:
                raise ValueError("OpenZFS version proof requires a fresh Linux compiler execution")
            if not any(entry["path"].endswith("/version.env") and entry.get("digest", {}).get("hash") == digest
                       for entry in event["inputs"]):
                raise ValueError("OpenZFS version file was not an exact executed compiler input")
        compiled[role] = sorted(action["target_label"] for action in selected)

    cargo = []
    for line in (options.oracle / "compiler-arguments.jsonl").read_text().splitlines():
        invocation = json.loads(line)
        arguments = invocation["arguments"]
        if ("--test" in arguments and "--crate-name" in arguments
                and arguments[arguments.index("--crate-name") + 1] == "aos_zfs_memory_policy"):
            if invocation["environment"].get("AOS_ZFS_VERSION") != options.zfs_version:
                raise ValueError("actual Cargo memory-policy compiler lost its packaged version")
            cargo.append(invocation)
    if len(cargo) != 1:
        raise ValueError("OpenZFS version proof omits the actual Cargo memory-policy test compilation")
    return {"version": options.zfs_version, "version_file_sha256": digest,
            "executed_compiler_targets": compiled, "cargo_memory_policy_test_compilers": len(cargo),
            "cargo_trace_sha256": hashlib.sha256((options.oracle / "compiler-arguments.jsonl").read_bytes()).hexdigest()}


def verify(options):
    packages = json.loads(options.packages.read_text())
    if set(packages) != {"ordinary", "bazel"} or any(set(outputs) != {"out"} for outputs in packages.values()):
        raise ValueError("OpenZFS parity requires both installed production packages")
    closures = runtime_closures(packages, json.loads(options.closure_attributes.read_text()))
    installed = {
        driver: inventory(outputs, options.readelf, None, elf_inspector=static_contract)
        for driver, outputs in packages.items()
    }
    if compare_installed(installed["ordinary"], installed["bazel"]):
        raise ValueError("static OpenZFS package changed library search paths")
    events = execution_events(options.build)
    if not events or any(event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]
                         for event in events):
        raise ValueError("OpenZFS proof requires fresh Linux sandbox actions")
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
            raise ValueError("OpenZFS proof omits an actual static link: " + tag)
        event = selected[0]
        for name, digest in hashes.items():
            if not any(entry["path"].endswith("/" + name) and entry.get("digest", {}).get("hash") == digest
                       for entry in event["inputs"]):
                raise ValueError("OpenZFS link omitted exact input: " + tag + ":" + name)
        arguments = expanded_command(graph, event)
        for flag in ["target-feature=+crt-static", "relocation-model=static"]:
            if not any(flag in argument for argument in arguments):
                raise ValueError("OpenZFS link omitted " + flag + ":" + tag)
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
        {"aos-activation-storage": PACKAGE_PATHS["aos-activation-storage"]}, target_suffix="_boot_transaction",
    )
    manifests = sorted(str(path.relative_to(options.workspace))
                       for path in (options.workspace / "crates").rglob("Cargo.*")
                       if path.name in {"Cargo.toml", "Cargo.lock"})
    if manifests:
        raise ValueError("OpenZFS source selection retains first-party Cargo metadata")
    return {
        "schema_version": 1, "packages": packages, "installed": installed, "runtime_closures": closures,
        "features": features, "test_parity": tests, "doctest_parity": docs,
        "cli_parity": command_parity(packages), "compiled_version": compiled_version(options),
        "static_inputs_sha256": hashes, "link_arguments": links,
        "sandboxed_cache_miss_actions": len(events),
        "first_party_rust_compilations": sum(event["mnemonic"] == "Rustc" and event["targetLabel"].startswith("//crates/")
                                              for event in events),
        "source_selection": {"workspace": str(options.workspace), "first_party_cargo_files": []},
        "limits": ["Native static installation, exact native features and compiled version, release tests and admission errors only. Real pools, module loading, sysfs writes, foreign hosts, numeric performance budgets and default cutover remain separate gates."],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["packages", "build", "tests", "oracle", "workspace", "libraries", "runtime", "readelf",
                 "closure-attributes", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--zfs-version", required=True)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
