"""Compares complete static BPF provider installations and release tests."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from bpf_object import object_contract
from installed_package import compare_installed, elf_contract, inventory, runtime_closures
from reconstruct_compiler_inputs import reconstruct
from verify_ability_package import static_contract
from verify_bpf_native import actions as native_actions, command_parity as loader_parity
from verify_cache import execution_events
from verify_compiler_options import compiler_options
from verify_pilot import verify as verify_tests
from verify_protocol import compare_doctests, compare_features
from verify_static_runtime import expanded_command


FAMILIES = {
    "lsm": {"package": "aos-activation-bpf-lsm", "command": "aos-ebpf-lsm-provider",
            "loader": "aos-ebpf-lsm-loader", "object": "aos-ebpf-lsm-task-audit.bpf.o"},
    "net": {"package": "aos-activation-bpf-network", "command": "aos-ebpf-net-policy-provider",
            "loader": "aos-ebpf-net-policy-loader", "object": "aos-ebpf-net-policy.bpf.o"},
}
PACKAGE_PATHS = {
    "aos-activation": "crates/activation/aos-activation",
    "aos-module-format": "crates/modules/aos-module-format",
    "aos-artifact-evidence": "crates/artifacts/aos-artifact-evidence",
    "aos-core": "crates/core/aos-core",
    **{value["package"]: "crates/activation/" + value["package"] for value in FAMILIES.values()},
}
MAX_DOCUMENT_BYTES = 32 * 1024 * 1024


def cargo_tests(oracle):
    """Requires both independent library libtests and both command libtests."""
    names = {}
    for family in FAMILIES.values():
        prefix = "//" + PACKAGE_PATHS[family["package"]] + ":"
        names[family["package"].replace("-", "_")] = prefix + "static_unit"
        names[family["command"]] = prefix + "static_bin"
    binaries = {}
    for line in (oracle / "cargo-messages.jsonl").read_text().splitlines():
        event = json.loads(line)
        name = event.get("target", {}).get("name")
        if (event.get("reason") != "compiler-artifact" or name not in names
                or not event.get("profile", {}).get("test") or not event.get("executable")):
            continue
        label = names[name]
        if label in binaries:
            raise ValueError("duplicate Cargo BPF test target: " + name)
        binaries[label] = Path(event["executable"])
    if set(binaries) != set(names.values()) or any(not path.is_file() for path in binaries.values()):
        raise ValueError("Cargo oracle omitted a BPF test executable")
    return binaries


def command_parity(packages):
    """Requires exact bounded-input and argument rejection behavior."""
    cases = [([], b""), (["--help"], b""), (["invalid"], b""),
             (["apply"], b""), (["remove"], b""), (["observe"], b""),
             (["apply"], b"{}"), (["remove"], b"{}"), (["observe"], b"{}"),
             (["observe"], b"{}" + b" " * (MAX_DOCUMENT_BYTES - 2)),
             (["observe"], b"x" * (MAX_DOCUMENT_BYTES + 1))]
    records = []
    for name, family in FAMILIES.items():
        for arguments, data in cases:
            results = [subprocess.run([str(Path(packages[name][driver]["out"]) / "bin" / family["command"]), *arguments],
                                      input=data, capture_output=True, timeout=30)
                       for driver in ["ordinary", "bazel"]]
            before, after = [(item.returncode, item.stdout, item.stderr) for item in results]
            if before != after or before[0] != 1 or before[1] or not before[2].startswith(family["command"].encode() + b":"):
                raise ValueError("installed BPF provider rejection differs: " + name + ": " + repr(arguments))
            oversized = b"invocation exceeds the canonical ability document bound" in before[2]
            if (len(data) > MAX_DOCUMENT_BYTES) != oversized:
                raise ValueError("BPF provider changed its document size boundary")
            records.append({"family": name, "arguments": arguments, "status": before[0],
                            "stdin_bytes": len(data), "stdin_sha256": hashlib.sha256(data).hexdigest(),
                            "stderr_sha256": hashlib.sha256(before[2]).hexdigest()})
    return records


def production_profiles(build, messages):
    """Compares all eight production Rust units with original Cargo profiles."""
    cargo = {}
    source = messages.read_text()
    for line in source.splitlines():
        event = json.loads(line)
        if event.get("reason") != "compiler-artifact":
            continue
        name = event["target"]["name"].replace("-", "_")
        if any(name == package.replace("-", "_") for package in PACKAGE_PATHS) or name in {
                family["command"].replace("-", "_") for family in FAMILIES.values()}:
            profile = event["profile"]
            if name in cargo and cargo[name] != profile:
                raise ValueError("ambiguous production Cargo BPF profile: " + name)
            cargo[name] = profile
    evidence = build / "evidence"
    execution = execution_events(build)
    actual = reconstruct(json.loads((evidence / "actions.json").read_text()), execution,
                         json.loads((evidence / "compiler-inputs.json").read_text()))["actions"]
    selected = [action for action in actual if action["target_label"].startswith("//crates/")]
    if len(selected) != 8 or len(cargo) != 8:
        raise ValueError("production BPF profile inventory omitted a first-party unit")
    result = {}
    for action in selected:
        arguments = action["arguments"]
        names = [arguments[index + 1] if argument == "--crate-name" else argument.split("=", 1)[1]
                 for index, argument in enumerate(arguments)
                 if argument == "--crate-name" or argument.startswith("--crate-name=")]
        if len(names) != 1:
            raise ValueError("production BPF compiler omitted an unambiguous crate name")
        name = names[0]
        if name not in cargo or name in result:
            raise ValueError("production BPF profile selected an unexpected compiler unit")
        profile = compiler_options(arguments)["effective_scalar_codegen"]
        if (cargo[name]["opt_level"] != "3" or cargo[name]["debuginfo"] != 0
                or cargo[name]["debug_assertions"] or cargo[name]["overflow_checks"]
                or profile.get("opt-level") != "3" or profile.get("debuginfo", "0") != "0"
                or profile.get("debug-assertions") not in {"no", "off", "false"}
                or profile.get("overflow-checks") not in {"no", "off", "false"}):
            raise ValueError("production BPF compiler profile differs: " + name)
        result[name] = {"cargo": cargo[name], "bazel": profile}
    return result


def verify(options):
    """Requires complete installed, compiler, release-test, and native parity."""
    packages = json.loads(options.packages.read_text())
    if set(packages) != set(FAMILIES) or any(set(value) != {"ordinary", "bazel"} for value in packages.values()):
        raise ValueError("BPF provider parity requires both builders for both families")
    attributes = json.loads(options.closure_attributes.read_text())
    installed, closures, source_paths = {}, {}, {}
    loaders, objects = {}, {}
    for name, family in FAMILIES.items():
        selected = packages[name]
        closures[name] = runtime_closures(selected, {
            driver + "_out": attributes[name + "_" + driver + "_out"] for driver in selected})
        if closures[name]["changes"] != {"out": {"added": [], "removed": []}}:
            raise ValueError("BPF provider changed the required runtime closure: " + name)

        def inspect(path, readelf, loader):
            if path.name == family["command"]:
                return static_contract(path, readelf, loader)
            if path.name == family["object"]:
                contract, locations = object_contract(path, "aos-ebpf-" + name + "-policy.bpf.c")
                source_paths[str(path)] = locations
                return {"rpath_directories": [], "needed": [], "interpreter": [],
                        "resolved_libraries": [], "bpf": contract}
            return elf_contract(path, readelf, loader)

        installed[name] = {driver: inventory(outputs, options.readelf, options.loader, elf_inspector=inspect)
                           for driver, outputs in selected.items()}
        compare_installed(installed[name]["ordinary"], installed[name]["bazel"])
        loaders[name] = {driver: Path(value["out"]) / "libexec" / family["loader"] for driver, value in selected.items()}
        objects[name] = {driver: Path(value["out"]) / "lib/bpf" / family["object"] for driver, value in selected.items()}

    execution = execution_events(options.build)
    if not execution or any(event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"] for event in execution):
        raise ValueError("BPF production qualification requires fresh Linux sandbox execution")
    graph = json.loads((options.build / "evidence/actions.json").read_text())
    links = {}
    for family in FAMILIES.values():
        label = "//" + PACKAGE_PATHS[family["package"]] + ":static_provider"
        matching = [event for event in execution if event["targetLabel"] == label and event["mnemonic"] == "Rustc"]
        if len(matching) != 1:
            raise ValueError("BPF provider static link was not executed exactly once")
        event = matching[0]
        for name in ["static/lib/libc.a", "static/lib/libm.a", "static/lib/libgcc_eh.a", "static/closure.json"]:
            digest = hashlib.sha256((options.libraries / name).read_bytes()).hexdigest()
            if not any(entry["path"].endswith("/" + name) and entry.get("digest", {}).get("hash") == digest
                       for entry in event["inputs"]):
                raise ValueError("BPF link omitted the exact static runtime input: " + name)
        arguments = expanded_command(graph, event)
        if not all(any(flag in argument for argument in arguments)
                   for flag in ["target-feature=+crt-static", "relocation-model=static"]):
            raise ValueError("BPF production command lost its static link options")
        links[label] = arguments

    with tempfile.TemporaryDirectory(prefix="aos-bpf-provider-") as directory:
        native_cases = loader_parity(
            {name: {"baseline": value["ordinary"], "bazel": value["bazel"]} for name, value in loaders.items()},
            {name: {"baseline": value["ordinary"], "bazel": value["bazel"]} for name, value in objects.items()}, Path(directory))
    empty_bins = ["//" + PACKAGE_PATHS[family["package"]] + ":static_bin" for family in FAMILIES.values()]
    tests = verify_tests(options.tests / "evidence/tests", cargo_tests(options.oracle), allow_empty=empty_bins)
    features = {
        "production": compare_features(options.build / "inventory.json", options.production_messages,
                                       PACKAGE_PATHS, required_packages=PACKAGE_PATHS),
        "release_tests": compare_features(options.tests / "inventory.json", options.oracle / "cargo-messages.jsonl",
                                          PACKAGE_PATHS, required_packages=PACKAGE_PATHS),
    }
    manifests = [str(path) for path in options.workspace.rglob("Cargo.*") if path.name in {"Cargo.toml", "Cargo.lock"}]
    if manifests:
        raise ValueError("BPF Bazel source selection retains Cargo manifests or locks")
    return {"schema_version": 1, "packages": packages, "installed": installed, "runtime_closures": closures,
            "production_profiles": production_profiles(options.build, options.production_messages),
            "features": features, "test_parity": tests,
            "doctest_parity": compare_doctests(options.tests / "evidence/tests", options.oracle / "cargo-tests.log",
                                               {family["package"]: PACKAGE_PATHS[family["package"]] for family in FAMILIES.values()},
                                               target_suffix="_static"),
            "provider_cli_cases": command_parity(packages), "loader_cli_cases": native_cases,
            "native_actions": native_actions(options.build, options.workspace, options.tools, options.native, options.compilers),
            "bpf_source_locations": source_paths, "static_links": links,
            "fresh_linux_sandbox_actions": len(execution),
            "kernel_attachment_qualified": False, "production_default_cutover": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["packages", "build", "tests", "oracle", "workspace", "libraries", "readelf", "loader",
                 "closure-attributes", "production-messages", "tools", "native", "compilers", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")
