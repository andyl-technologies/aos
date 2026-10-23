"""Qualifies foreign family test binaries against the native case inventory."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil

from family_libtest import bazel_binaries
from verify_cache import execution_events
from verify_cross_linux import elf_machine


def option_value(arguments, name):
    """Reads Rust's equivalent split and joined option spellings."""
    for index, argument in enumerate(arguments):
        if argument.startswith(name + "="):
            return argument[len(name) + 1:]
        if argument == name and index + 1 < len(arguments):
            return arguments[index + 1]
    return None


def compiler_arguments(workspace, arguments):
    """Reads Bazel's multiline response files while the execution tree exists."""
    expanded = []
    for argument in arguments:
        if argument.startswith("@"):
            path = workspace / argument[1:]
            expanded.extend(path.read_text().splitlines())
        else:
            expanded.append(argument)
    return expanded


def platform_case_differences(expected):
    """Applies the reviewed shared-memory layout case only when that target exists."""
    layout = "//crates/crucible/protocol/crucible-qemu-shmem:region_layout"
    if layout not in expected:
        return {}

    # The protocol pins region allocation to the published x86_64 layout.
    # Its foreign rejection case preserves that policy in larger host families.
    native_case = "region_allocation_initializes_slots_rings_and_storage"
    foreign_case = "region_allocation_rejects_unpinned_developer_targets"
    cases = expected[layout]["executed"]
    if cases.count(native_case) != 1 or foreign_case in cases:
        raise ValueError("pinned-layout platform case contract changed; review the foreign oracle")
    expected[layout]["executed"] = sorted(foreign_case if case == native_case else case for case in cases)
    return {layout: {"native_only": [native_case], "foreign_only": [foreign_case]}}


def verify(workspace, events_path, execution, parity, output, evidence):
    """Checks toolchain roles and exports declared binaries for guest execution."""
    expected = json.loads(parity.read_text())["targets"]
    platform_differences = platform_case_differences(expected)
    events = [json.loads(line) for line in events_path.read_text().splitlines()]
    targets = [label + "_binary" for label in expected]
    binaries = bazel_binaries(events, targets)
    if binaries.keys() != expected.keys():
        raise ValueError("foreign family omitted qualified test targets")

    # The execution log uses the same streaming format as the Nix builder.
    (evidence / "evidence").mkdir(parents=True)
    shutil.copyfile(execution, evidence / "evidence/execution.json")
    records = execution_events(evidence)
    packages = {label.split(":", 1)[0] for label in expected}
    first_party = []
    native_macros = []
    compiler_records = []
    for event in records:
        if event["mnemonic"] != "Rustc":
            continue
        label = event["targetLabel"]
        inputs = [entry["path"] for entry in event["inputs"]]
        arguments = compiler_arguments(workspace, event["commandArgs"])
        target = option_value(arguments, "--target")
        crate_type = option_value(arguments, "--crate-type")
        compiler_records.append({"label": label, "target": target, "crate_type": crate_type,
                                 "arguments": arguments})
        foreign_std = any("/rustlib/aarch64-unknown-linux-gnu/lib/libstd-" in path for path in inputs)
        native_std = any("/rustlib/x86_64-unknown-linux-gnu/lib/libstd-" in path for path in inputs)
        if label.split(":", 1)[0] in packages:
            if (not foreign_std or native_std or "sandbox" not in event["runner"]
                    or target != "aarch64-unknown-linux-gnu"):
                raise ValueError(f"first-party compile did not use the sandboxed foreign toolchain: {label}")
            first_party.append(label)
        if crate_type == "proc-macro":
            if foreign_std or not native_std or "sandbox" not in event["runner"]:
                raise ValueError(f"procedural macro did not use the native execution toolchain: {label}")
            native_macros.append(label)
    if not set(targets) <= set(first_party) or not native_macros:
        raise ValueError("family did not exercise both target compilation and native procedural macros")
    (evidence / "evidence/compiler-arguments.json").write_text(json.dumps(compiler_records, indent=2, sort_keys=True) + "\n")

    artifacts = {}
    (output / "binaries").mkdir()
    for label, binary in sorted(binaries.items()):
        contents = binary.read_bytes()
        if elf_machine(contents) != 183:
            raise ValueError(f"family test binary is not AArch64 ELF: {label}")
        destination = "binaries/" + hashlib.sha256(label.encode()).hexdigest()
        shutil.copyfile(binary, output / destination)
        (output / destination).chmod(0o555)
        artifacts[label] = {"file": destination, "elf_machine": 183,
                            "sha256": hashlib.sha256(contents).hexdigest()}
    return {
        "schema_version": 1,
        "target": "aarch64-unknown-linux-gnu",
        "execution": "x86_64-unknown-linux-gnu",
        "runtime": "compile-only; guest execution is a separate qualification",
        "native_inventory_sha256": hashlib.sha256(parity.read_bytes()).hexdigest(),
        "platform_differences": platform_differences,
        "artifacts": artifacts,
        "first_party_compiles": sorted(first_party),
        "native_procedural_macros": sorted(native_macros),
        "compiled_cases": sum(len(item["executed"]) for item in expected.values()),
        "ignored_cases": sum(len(item["ignored"]) for item in expected.values()),
        "targets": expected,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["workspace", "events", "execution", "parity", "output", "evidence"]:
        parser.add_argument("--" + name, required=True, type=Path)
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=True)
    report = verify(options.workspace, options.events, options.execution, options.parity, options.output, options.evidence)
    (options.output / "parity.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
