"""Checks installed static configuration programs against their Cargo package."""

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


PREFIX = "//crates/boot/aos-configuration-image:"
COMMANDS = ["aos-certificate-bundle", "aos-configuration-boot",
            "aos-configuration-lower", "aos-configuration-mount"]
PACKAGE_PATHS = {
    "aos-configuration-image": "crates/boot/aos-configuration-image",
    "aos-activation": "crates/activation/aos-activation",
    "aos-core": "crates/core/aos-core",
    "aos-module-format": "crates/modules/aos-module-format",
    "aos-artifact-evidence": "crates/artifacts/aos-artifact-evidence",
}
EMBEDDED_TOOLS = {
    "aos-certificate-bundle": [],
    "aos-configuration-boot": ["AOS_MKFS_EROFS", "AOS_FSCK_EROFS", "AOS_MOUNT", "AOS_PACKAGE_RUNTIME"],
    "aos-configuration-lower": ["AOS_MKFS_EROFS", "AOS_FSCK_EROFS"],
    "aos-configuration-mount": ["AOS_MKFS_EROFS", "AOS_FSCK_EROFS", "AOS_MOUNT", "AOS_UMOUNT"],
}


def cargo_tests(oracle):
    """Requires all five independently compiled native test executables."""
    names = {"aos_configuration_image": PREFIX + "static_unit"}
    names.update({name: PREFIX + "static_bin_" + name for name in COMMANDS})
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
    """Compares startup errors and successful certificate serialization."""
    compared = []

    def compare(name, arguments, data, expected_status, expected_output=None):
        results = [subprocess.run([str(Path(packages[driver]["out"]) / "bin" / name), *arguments],
                                  input=data, capture_output=True, timeout=30)
                   for driver in ["ordinary", "bazel"]]
        before, after = [(result.returncode, result.stdout, result.stderr) for result in results]
        if before != after or before[0] != expected_status:
            raise ValueError("installed configuration command differs: " + repr((name, arguments, before, after)))
        if expected_output is not None and (before[1] != expected_output or before[2]):
            raise ValueError("certificate command changed validated PEM output")
        compared.append({"command": name, "arguments": arguments, "status": before[0],
                         "stdin_sha256": hashlib.sha256(data).hexdigest(),
                         "stdout_sha256": hashlib.sha256(before[1]).hexdigest(),
                         "stderr_sha256": hashlib.sha256(before[2]).hexdigest()})

    for name in COMMANDS:
        for arguments in [[], ["--help"], ["invalid", "extra"]]:
            compare(name, arguments, b"", 1)

    certificate = "-----BEGIN CERTIFICATE-----\nMAcwADAAAwEA\n-----END CERTIFICATE-----\n"
    sources = [{"kind": "text", "text": certificate}, {"kind": "text", "text": "\n" + certificate}]
    compare("aos-certificate-bundle", [], json.dumps(sources).encode(), 0,
            (certificate + "\n" + certificate).encode())
    compare("aos-certificate-bundle", [], b'[{"kind":"text","text":"invalid PEM"}]', 1)
    return compared


def verify(options):
    packages = json.loads(options.packages.read_text())
    if set(packages) != {"ordinary", "bazel"} or any(set(outputs) != {"out"} for outputs in packages.values()):
        raise ValueError("configuration parity requires both installed production packages")
    attributes = json.loads(options.closure_attributes.read_text())
    closures = runtime_closures(packages, attributes)
    installed = {driver: inventory(outputs, options.readelf, None, elf_inspector=static_contract)
                 for driver, outputs in packages.items()}
    if compare_installed(installed["ordinary"], installed["bazel"]):
        raise ValueError("static configuration commands changed library search paths")

    environment = dict(line.split("=", 1) for line in (options.tools / "configuration.env").read_text().splitlines())
    if set(environment) != {name for names in EMBEDDED_TOOLS.values() for name in names}:
        raise ValueError("configuration tools omit an immutable command")
    for path in environment.values():
        if not path.startswith("/nix/store/") or not Path(path).is_file():
            raise ValueError("configuration command is not a realized store input")
    for driver, outputs in packages.items():
        for command, names in EMBEDDED_TOOLS.items():
            binary = (Path(outputs["out"]) / "bin" / command).read_bytes()
            if any(environment[name].encode() not in binary for name in names):
                raise ValueError("installed configuration command lost an immutable tool: " + driver + "/" + command)

    events = execution_events(options.build)
    if not events or any(event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]
                         for event in events):
        raise ValueError("configuration proof requires fresh Linux sandbox actions")
    graph = json.loads((options.build / "evidence/actions.json").read_text())
    hashes = {name: hashlib.sha256((options.libraries / name).read_bytes()).hexdigest()
              for name in ["static/lib/libc.a", "static/lib/libm.a", "static/lib/libgcc_eh.a", "static/closure.json"]}
    links = {}
    for command in COMMANDS:
        matching = [event for event in events if event["mnemonic"] == "Rustc"
                    and event["targetLabel"] == PREFIX + "static_" + command]
        if len(matching) != 1:
            raise ValueError("missing actual configuration link: " + command)
        event = matching[0]
        for name, digest in hashes.items():
            if not any(entry["path"].endswith("/" + name) and entry.get("digest", {}).get("hash") == digest
                       for entry in event["inputs"]):
                raise ValueError("configuration link omitted exact static input: " + name)
        arguments = expanded_command(graph, event)
        for flag in ["target-feature=+crt-static", "relocation-model=static"]:
            if not any(flag in argument for argument in arguments):
                raise ValueError("configuration link omitted " + flag)
        links[command] = arguments

    parity = verify_tests(options.tests / "evidence/tests", cargo_tests(options.oracle),
                          allow_empty=[PREFIX + "static_bin_" + name for name in COMMANDS])
    production_features = compare_features(
        options.build / "inventory.json",
        Path(packages["ordinary"]["out"]) / "nix-support/cargo-build-messages.jsonl",
        PACKAGE_PATHS, required_packages=PACKAGE_PATHS,
    )
    test_features = compare_features(options.tests / "inventory.json",
                                     options.oracle / "cargo-messages.jsonl",
                                     PACKAGE_PATHS, required_packages=PACKAGE_PATHS)
    docs = compare_doctests(options.tests / "evidence/tests", options.oracle / "cargo-tests.log",
                            {"aos-configuration-image": "crates/boot/aos-configuration-image"},
                            target_suffix="_static")
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
        "embedded_tools": environment,
        "cli_parity": command_parity(packages),
        "test_parity": parity,
        "production_features": production_features,
        "test_features": test_features,
        "doctest_parity": docs,
        "static_inputs_sha256": hashes,
        "link_commands": links,
        "source_selection": {"workspace": str(options.workspace), "first_party_cargo_files": []},
        "sandboxed_cache_miss_actions": len(events),
        "first_party_rust_compilations": sum(event["mnemonic"] == "Rustc" and event["targetLabel"].startswith("//crates/")
                                              for event in events),
        "limits": ["Native Linux static installation, release tests and bounded CLI parity only; privileged mounting, verified boot, foreign hosts and numeric performance acceptance remain separate gates."],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["packages", "build", "tests", "oracle", "workspace", "libraries", "tools",
                 "readelf", "closure-attributes", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
