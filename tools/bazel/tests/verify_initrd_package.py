"""Qualifies installed initrd orchestration without executing boot-time mutations."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from installed_package import compare_installed, inventory, runtime_closures
from verify_cache import execution_events
from verify_pilot import verify as verify_tests


def verify(options):
    source_inventory = options.source_inventory.read_bytes()
    if json.loads(source_inventory) != json.loads((options.build / "inventory.json").read_text()):
        raise ValueError("compiled initrd inventory differs from the checked source inventory")
    first_party = options.workspace / "crates"
    rust_sources = sorted(str(path.relative_to(options.workspace)) for path in first_party.rglob("*.rs"))
    if rust_sources != ["crates/boot/aos-boot-runtime/standalone/initrd_preparation.rs"]:
        raise ValueError("standalone initrd source slice contains unrelated Rust sources")
    if any(path.name in {"Cargo.toml", "Cargo.lock"} for path in first_party.rglob("Cargo.*")):
        raise ValueError("standalone initrd source slice contains first-party Cargo metadata")

    packages = json.loads(options.packages.read_text())
    if set(packages) != {"ordinary", "bazel"} or any(set(value) != {"out"} for value in packages.values()):
        raise ValueError("initrd package comparison requires both production outputs")
    closures = runtime_closures(packages, json.loads(options.closure_attributes.read_text()))
    records = {name: inventory(outputs, options.readelf, options.loader) for name, outputs in packages.items()}
    search_changes = compare_installed(records["ordinary"], records["bazel"])
    tests = verify_tests(
        options.build / "evidence/tests",
        {"//crates/boot/aos-boot-runtime:standalone_unit": options.oracle},
    )

    commands = [
        [],
        ["--help"],
        ["apply-deployment"],
        ["unknown"],
        ["apply-deployment", "--input", "/tmp/untrusted-deployment", "--state-directory",
         "/run/journal", "--nix-store", "/nix/store/tool/bin/nix-store"],
    ]
    behavior = []
    embedded_commands = [
        os.environ[name]
        for name in ["AOS_PACKAGE_RUNTIME", "AOS_BOOT_CONFIGURATION", "AOS_CONFIGURATION_BOOT"]
    ]
    executables = {
        driver: Path(outputs["out"]) / "bin/aos-boot-preparations"
        for driver, outputs in packages.items()
    }
    for driver, executable in executables.items():
        data = executable.read_bytes()
        if any(command.encode() not in data for command in embedded_commands):
            raise ValueError("initrd program lost an exact embedded command: " + driver)

    for arguments in commands:
        results = {}
        for driver, executable in executables.items():
            result = subprocess.run([str(executable), *arguments], capture_output=True, timeout=30)
            if result.returncode != 1 or result.stdout or b"aos-boot-preparations:" not in result.stderr:
                raise ValueError("initrd program accepted invalid invocation: " + repr(arguments))
            results[driver] = (result.returncode, result.stdout, result.stderr)
        if results["ordinary"] != results["bazel"]:
            raise ValueError("installed initrd command behavior differs: " + repr(arguments))
        behavior.append({
            "arguments": arguments,
            "exit_code": 1,
            "stderr_sha256": hashlib.sha256(results["bazel"][2]).hexdigest(),
        })

    executions = execution_events(options.build)
    if not executions or any(event["runner"] != "linux-sandbox" or event["cacheHit"]
                             or event["exitCode"] != 0 for event in executions):
        raise ValueError("initrd production qualification requires fresh sandboxed execution")
    rust = [event for event in executions if event["mnemonic"] == "Rustc"
            and event["targetLabel"].startswith("//crates/boot/aos-boot-runtime:")]
    if {event["targetLabel"] for event in rust} != {
        "//crates/boot/aos-boot-runtime:standalone", "//crates/boot/aos-boot-runtime:standalone_unit_binary",
    } or len(rust) != 2:
        raise ValueError("missing standalone initrd program or unit compilation")
    return {
        "schema_version": 1,
        "packages": packages,
        "source_selection": {
            "workspace": str(options.workspace),
            "checked_inventory_sha256": hashlib.sha256(source_inventory).hexdigest(),
            "compiled_inventory_matches": True,
            "first_party_cargo_files": [],
            "rust_sources": rust_sources,
        },
        "installed": records,
        "library_search_changes": search_changes,
        "runtime_closures": closures,
        "test_parity": tests,
        "rejected_invocations": behavior,
        "embedded_commands": embedded_commands,
        "sandboxed_cache_miss_actions": len(executions),
        "first_party_rust_compilations": len(rust),
        "limits": [
            "Native Linux installed-package and unit-test qualification only; successful boot-time "
            "transactions require their existing VM and authenticated image gates.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["packages", "build", "oracle", "workspace", "source-inventory", "readelf", "loader",
                 "closure-attributes", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
