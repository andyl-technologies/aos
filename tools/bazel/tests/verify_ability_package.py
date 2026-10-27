"""Qualifies the installed static ability adapter against its production package."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from installed_package import compare_installed, inventory, runtime_closures
from verify_activation_crucible import verify as verify_runtime
from verify_cache import execution_events
from verify_pilot import verify as verify_tests
from verify_protocol import compare_doctests


PREFIX = "//crates/activation/aos-activation-crucible:"


def static_contract(binary, readelf, _loader):
    """Requires the actual installed ELF to remain a classic static executable."""
    header, program, dynamic = [
        subprocess.check_output([str(readelf), flag, str(binary)], text=True)
        for flag in ["-h", "-l", "-d"]
    ]
    if (not re.search(r"Type:\s+EXEC\b", header) or "INTERP" in program
            or any(marker in dynamic for marker in ["(NEEDED)", "(RPATH)", "(RUNPATH)"])):
        raise ValueError("installed ability adapter is not a classic static executable")
    return {
        "class": re.search(r"Class:\s+(\S+)", header)[1],
        "machine": re.search(r"Machine:\s+(.+)", header)[1],
        "type": "EXEC",
        "needed": [],
        "interpreter": [],
        "rpath_directories": [],
        "resolved_libraries": [],
    }


def cargo_tests(oracle):
    """Requires retained Cargo library and command test executables."""
    names = {"aos_activation_crucible": PREFIX + "unit",
             "aos-ability-crucible": PREFIX + "bin_aos-ability-crucible"}
    binaries = {}
    for line in (oracle / "cargo-messages.jsonl").read_text().splitlines():
        message = json.loads(line)
        target = message.get("target", {}).get("name")
        if (message.get("reason") == "compiler-artifact" and target in names
                and message.get("profile", {}).get("test") and message.get("executable")):
            label = names[target]
            if label in binaries:
                raise ValueError("Cargo oracle repeats an ability test target")
            binaries[label] = Path(message["executable"])
    if set(binaries) != set(names.values()) or any(not binary.is_file() for binary in binaries.values()):
        raise ValueError("Cargo oracle omits an ability test executable")
    return binaries


def verify(options):
    packages = json.loads(options.packages.read_text())
    if set(packages) != {"ordinary", "bazel"} or any(set(outputs) != {"out"} for outputs in packages.values()):
        raise ValueError("ability comparison requires both installed production outputs")
    attributes = json.loads(options.closure_attributes.read_text())
    closures = runtime_closures(packages, attributes)
    installed = {driver: inventory(outputs, options.readelf, None, elf_inspector=static_contract)
                 for driver, outputs in packages.items()}
    search_changes = compare_installed(installed["ordinary"], installed["bazel"])
    if search_changes:
        raise ValueError("static ability package changed library search paths")

    runtime = verify_runtime(options.build, Path(packages["bazel"]["out"]), options.libraries,
                             Path(packages["ordinary"]["out"]), options.readelf)
    parity = verify_tests(options.tests / "evidence/tests", cargo_tests(options.oracle),
                          allow_empty=[PREFIX + "bin_aos-ability-crucible"])
    docs = compare_doctests(
        options.tests / "evidence/tests", options.oracle / "cargo-tests.log",
        {"aos-activation-crucible": "crates/activation/aos-activation-crucible"},
    )

    manifests = sorted(str(path.relative_to(options.workspace))
                       for path in (options.workspace / "crates").rglob("Cargo.*")
                       if path.name in {"Cargo.toml", "Cargo.lock"})
    if manifests:
        raise ValueError("production ability source selection retains first-party Cargo metadata")
    events = execution_events(options.build)
    if not events or any(event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]
                         for event in events):
        raise ValueError("ability production proof requires fresh Linux sandbox execution")
    rust = [event for event in events if event["mnemonic"] == "Rustc"
            and event["targetLabel"].startswith("//crates/")]
    if not any(event["targetLabel"] == PREFIX + "aos-ability-crucible" for event in rust):
        raise ValueError("production ability program was not compiled")

    return {
        "schema_version": 1,
        "packages": packages,
        "installed": installed,
        "runtime_closures": closures,
        "static_runtime_and_cli": runtime,
        "test_parity": parity,
        "doctest_parity": docs,
        "source_selection": {"workspace": str(options.workspace), "first_party_cargo_files": []},
        "sandboxed_cache_miss_actions": len(events),
        "first_party_rust_compilations": len(rust),
        "binary_sha256": {driver: hashlib.sha256(
            (Path(outputs["out"]) / "bin/aos-ability-crucible").read_bytes()).hexdigest()
            for driver, outputs in packages.items()},
        "limits": [
            "Native Linux package, static-link, release-test and invalid-command parity only.",
            "Live guest instrumentation, supported foreign hosts, performance budgets and default cutover remain separate gates.",
        ],
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
