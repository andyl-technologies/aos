"""Qualifies the installed static network-ruleset provider against its Cargo package."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from reconstruct_compiler_inputs import reconstruct
from installed_package import compare_installed, inventory, runtime_closures
from verify_ability_package import static_contract
from verify_cache import execution_events
from verify_pilot import verify as verify_tests
from verify_protocol import compare_doctests, compare_features
from verify_static_runtime import expanded_command


PREFIX = "//crates/activation/aos-activation-nftables:"
COMMAND = "aos-network-ruleset-provider"
PACKAGE_PATHS = {
    "aos-activation-nftables": "crates/activation/aos-activation-nftables",
    "aos-activation": "crates/activation/aos-activation",
    "aos-module-format": "crates/modules/aos-module-format",
    "aos-artifact-evidence": "crates/artifacts/aos-artifact-evidence",
    "aos-core": "crates/core/aos-core",
}


def cargo_tests(oracle):
    """Requires the independently compiled release test executables."""
    names = {
        "aos_activation_nftables": PREFIX + "static_unit",
        COMMAND: PREFIX + "static_bin",
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
            raise ValueError("duplicate Cargo network-ruleset test target: " + name)
        binaries[label] = Path(event["executable"])
    if set(binaries) != set(names.values()) or any(not binary.is_file() for binary in binaries.values()):
        raise ValueError("Cargo oracle omits a network-ruleset test executable")
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
        (["observe"], b"x" * (16 * 1024 * 1024 + 1)),
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
                or not before[2].startswith(COMMAND.encode() + b":")):
            raise ValueError("installed network-ruleset rejection behavior differs: " + repr(arguments))
        if (len(data) > 16 * 1024 * 1024
                and b"invocation exceeds bound" not in before[2]):
            raise ValueError("installed network-ruleset command did not enforce its document bound")
        compared.append({
            "arguments": arguments,
            "status": before[0],
            "stdin_size": len(data),
            "stdin_sha256": hashlib.sha256(data).hexdigest(),
            "stderr_sha256": hashlib.sha256(before[2]).hexdigest(),
        })
    return compared


def version_parity(packages, version):
    """Requires the unchanged version command without dispatching a firewall action."""
    results = [
        subprocess.run([str(Path(packages[driver]["out"]) / "bin" / COMMAND), "--version"],
                       input=b"", capture_output=True, timeout=30)
        for driver in ["ordinary", "bazel"]
    ]
    expected = (COMMAND + " " + version + "\n").encode()
    if any(result.returncode or result.stdout != expected or result.stderr for result in results):
        raise ValueError("installed network-ruleset version command differs")
    return {"version": version, "stdout_sha256": hashlib.sha256(expected).hexdigest()}


def compiled_nft(options):
    """Requires the packaged nft path in each actual provider library compilation."""
    expected = ("AOS_NFT_EXECUTABLE=" + options.nft_executable + "\n").encode()
    environment_file = options.runtime / "executable.env"
    if environment_file.read_bytes() != expected:
        raise ValueError("nft compiler repository differs from the packaged runtime path")
    if not Path(options.nft_executable).is_file():
        raise ValueError("packaged nft runtime executable is missing")
    digest = hashlib.sha256(expected).hexdigest()
    compiled = {}
    for role, build, labels in [
        ("production", options.build, {PREFIX + "static_lib"}),
        ("release_tests", options.tests, {PREFIX + "static_lib", PREFIX + "static_unit_binary"}),
    ]:
        evidence = build / "evidence"
        events = execution_events(build)
        actions = reconstruct(
            json.loads((evidence / "actions.json").read_text()), events,
            json.loads((evidence / "compiler-inputs.json").read_text()),
        )["actions"]
        selected = [action for action in actions if action["target_label"] in labels]
        if {action["target_label"] for action in selected} != labels or len(selected) != len(labels):
            raise ValueError("nft path proof omits an actual compiler execution: " + role)
        for action in selected:
            if action["environment"].get("AOS_NFT_EXECUTABLE") != options.nft_executable:
                raise ValueError("executed compiler omitted the packaged nft path")
            matches = [event for event in events if event["mnemonic"] == "Rustc"
                       and event["targetLabel"] == action["target_label"]]
            if len(matches) != 1:
                raise ValueError("nft path proof has ambiguous compiler execution evidence")
            event = matches[0]
            if event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]:
                raise ValueError("nft path proof requires fresh Linux compiler execution")
            if not any(entry["path"].endswith("/executable.env")
                       and entry.get("digest", {}).get("hash") == digest for entry in event["inputs"]):
                raise ValueError("nft path was not an exact executed compiler input")
        compiled[role] = sorted(labels)

    cargo_actions = {}
    for line in (options.oracle / "compiler-arguments.jsonl").read_text().splitlines():
        invocation = json.loads(line)
        arguments = invocation["arguments"]
        if ("--crate-name" not in arguments
                or arguments[arguments.index("--crate-name") + 1] != "aos_activation_nftables"):
            continue
        role = "test" if "--test" in arguments else "library"
        if role in cargo_actions:
            raise ValueError("duplicate Cargo nft library compilation: " + role)
        if invocation["environment"].get("AOS_NFT_EXECUTABLE") != options.nft_executable:
            raise ValueError("actual Cargo compiler omitted the packaged nft path")
        cargo_actions[role] = invocation
    if set(cargo_actions) != {"library", "test"}:
        raise ValueError("nft path proof omits an actual Cargo library compilation")
    return {
        "executable": options.nft_executable,
        "environment_file_sha256": digest,
        "executed_compiler_targets": compiled,
        "cargo_library_compilers": len(cargo_actions),
        "cargo_trace_sha256": hashlib.sha256((options.oracle / "compiler-arguments.jsonl").read_bytes()).hexdigest(),
    }


def verify(options):
    packages = json.loads(options.packages.read_text())
    if (set(packages) != {"ordinary", "bazel"}
            or any(set(outputs) != {"out"} for outputs in packages.values())):
        raise ValueError("network-ruleset parity requires both installed production packages")
    closures = runtime_closures(packages, json.loads(options.closure_attributes.read_text()))
    if closures["changes"] != {"out": {"added": [], "removed": []}}:
        raise ValueError("installed network-ruleset package changed its required runtime closure")
    for outputs in packages.values():
        binary = Path(outputs["out"]) / "bin" / COMMAND
        if options.nft_executable.encode() not in binary.read_bytes():
            raise ValueError("installed network-ruleset command lost its packaged nft path")
    installed = {
        driver: inventory(outputs, options.readelf, None, elf_inspector=static_contract)
        for driver, outputs in packages.items()
    }
    if compare_installed(installed["ordinary"], installed["bazel"]):
        raise ValueError("static network-ruleset package changed library search paths")

    events = execution_events(options.build)
    if not events or any(event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]
                         for event in events):
        raise ValueError("network-ruleset proof requires fresh Linux sandbox actions")
    links = [event for event in events if event["mnemonic"] == "Rustc"
             and event["targetLabel"] == PREFIX + "static_provider"]
    if len(links) != 1:
        raise ValueError("network-ruleset proof omits the actual static link")
    event = links[0]
    hashes = {
        name: hashlib.sha256((options.libraries / name).read_bytes()).hexdigest()
        for name in ["static/lib/libc.a", "static/lib/libm.a", "static/lib/libgcc_eh.a", "static/closure.json"]
    }
    for name, digest in hashes.items():
        if not any(entry["path"].endswith("/" + name) and entry.get("digest", {}).get("hash") == digest
                   for entry in event["inputs"]):
            raise ValueError("network-ruleset link omitted exact static input: " + name)
    arguments = expanded_command(json.loads((options.build / "evidence/actions.json").read_text()), event)
    for flag in ["target-feature=+crt-static", "relocation-model=static"]:
        if not any(flag in argument for argument in arguments):
            raise ValueError("network-ruleset link omitted " + flag)

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
                         allow_empty=[PREFIX + "static_bin"])
    docs = compare_doctests(
        options.tests / "evidence/tests", options.oracle / "cargo-tests.log",
        {"aos-activation-nftables": PACKAGE_PATHS["aos-activation-nftables"]}, target_suffix="_static",
    )
    manifests = sorted(str(path.relative_to(options.workspace))
                       for path in (options.workspace / "crates").rglob("Cargo.*")
                       if path.name in {"Cargo.toml", "Cargo.lock"})
    if manifests:
        raise ValueError("network-ruleset source selection retains first-party Cargo metadata")

    return {
        "schema_version": 1,
        "packages": packages,
        "installed": installed,
        "runtime_closures": closures,
        "features": features,
        "test_parity": tests,
        "doctest_parity": docs,
        "cli_parity": command_parity(packages),
        "version_parity": version_parity(packages, options.package_version),
        "compiled_nft": compiled_nft(options),
        "static_inputs_sha256": hashes,
        "link_arguments": arguments,
        "sandboxed_cache_miss_actions": len(events),
        "first_party_rust_compilations": sum(
            event["mnemonic"] == "Rustc" and event["targetLabel"].startswith("//crates/")
            for event in events
        ),
        "source_selection": {"workspace": str(options.workspace), "first_party_cargo_files": []},
        "limits": [
            "Native static installation, exact native features, release tests and bounded input rejection only.",
            "Live firewall transactions, foreign hosts, numeric performance budgets and default cutover remain separate gates.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["packages", "build", "tests", "oracle", "workspace", "libraries", "readelf",
                 "closure-attributes", "runtime", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--nft-executable", required=True)
    parser.add_argument("--package-version", required=True)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
