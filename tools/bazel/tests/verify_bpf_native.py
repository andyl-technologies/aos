"""Qualifies native BPF artifacts against independently built original recipes.

This check exercises userspace validation only. It does not claim kernel
attachment, privileged effects, Rust-provider parity, or production cutover.
"""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from bpf_object import object_contract
from installed_package import elf_contract
from verify_cache import execution_events
from verify_static_runtime import expanded_command


PREFIX = "//pkgs/security:"
LOADERS = {"lsm": "aos-ebpf-lsm-loader", "net": "aos-ebpf-net-policy-loader"}
POLICIES = {
    "lsm": {"version": 1, "name": "aos-lsm-task-audit", "programs": ["aos_lsm_file_mprotect"]},
    "net": {"version": 1, "package": "sample", "mode": "private", "securityLabel": "aos-pkg-sample",
            "tcp": {"bind": [8000], "connect": [443]},
            "ebpf": {"identity": "aos-pkg-sample", "hooks": ["socket_bind", "socket_connect"],
                     "tcp": {"bind": [8000], "connect": [443]}}},
}


def sha(path):
    """Hashes the actual selected artifact or action input."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exported_files(build):
    """Requires the exact four declared native package artifacts."""
    index = json.loads((build / "packages/index.json").read_text())
    label = PREFIX + "bpf_native_artifacts"
    if set(index) != {label}:
        raise ValueError("native BPF build exports an unexpected package set")
    root = build / "packages" / index[label]
    manifest = json.loads((root / "manifest.json").read_text())
    expected = {"libexec/" + name for name in LOADERS.values()} | {
        "lib/bpf/aos-ebpf-lsm-task-audit.bpf.o", "lib/bpf/aos-ebpf-net-policy.bpf.o"}
    files = {entry["destination"]: root / "files" / entry["destination"] for entry in manifest["artifacts"]}
    if set(files) != expected or len(manifest["artifacts"]) != 4:
        raise ValueError("native BPF artifact set changed")
    return files


def require_input(event, suffix, path):
    """Requires the exact source/tool/library bytes in an executed action."""
    matches = [entry for entry in event["inputs"] if entry["path"].endswith(suffix)]
    if len(matches) != 1 or matches[0].get("digest", {}).get("hash") != sha(path):
        raise ValueError("native BPF action omitted or changed input: " + suffix)
    return matches[0]


def actions(build, source, tools, native, compilers):
    """Requires eight fresh Linux-sandbox compiler, linker, and strip actions."""
    graph = json.loads((build / "evidence/actions.json").read_text())
    events = [event for event in execution_events(build)
              if event["mnemonic"] in {"AosBpfCompile", "AosBpfStrip", "CppCompile", "CppLink"}]
    result = validate_actions(events, graph, source, tools, native, compilers)
    controls = []
    for name in ["cache-hit", "local-runner", "changed-source", "changed-tool-closure"]:
        tampered = copy.deepcopy(events)
        if name == "cache-hit":
            tampered[0]["cacheHit"] = True
        elif name == "local-runner":
            tampered[0]["runner"] = "local"
        else:
            event = next(item for item in tampered if item["mnemonic"] == "AosBpfCompile")
            suffix = ".bpf.c" if name == "changed-source" else "/closure.json"
            entry = next(item for item in event["inputs"] if item["path"].endswith(suffix))
            entry["digest"]["hash"] = "0" * 64
        try:
            validate_actions(tampered, graph, source, tools, native, compilers)
        except ValueError as error:
            controls.append({"case": name, "rejected": str(error)})
        else:
            raise ValueError("native BPF action proof accepted negative control: " + name)
    return {"executed": result, "negative_controls": controls}


def validate_actions(events, graph, source, tools, native, compilers):
    """Checks executed inputs, allowing no cached or unsandboxed qualification."""
    expected = {(PREFIX + name, mnemonic) for name in LOADERS.values() for mnemonic in ["CppCompile", "CppLink"]}
    expected |= {(PREFIX + "aos-ebpf-" + policy + "-policy.bpf", mnemonic)
                 for policy in LOADERS for mnemonic in ["AosBpfCompile", "AosBpfStrip"]}
    if len(events) != 8 or {(event["targetLabel"], event["mnemonic"]) for event in events} != expected:
        raise ValueError("native BPF compiler action inventory differs")
    result = []
    for event in events:
        if event["cacheHit"] or event["exitCode"] or event["runner"] != "linux-sandbox":
            raise ValueError("native BPF action was cached, failed, or ran outside Linux sandbox")
        kind = event["mnemonic"]
        command = expanded_command(graph, event)
        bindings = []
        if kind.startswith("AosBpf"):
            bindings.append(require_input(event, "aos_bpf_tools/closure.json", tools / "closure.json"))
            executable = "clang" if kind == "AosBpfCompile" else "llvm-strip"
            bindings.append(require_input(event, "aos_bpf_tools/bin/" + executable, tools / "bin" / executable))
            if not command[0].endswith("aos_bpf_tools/bin/" + executable):
                raise ValueError("BPF action selected a different executable")
            if kind == "AosBpfCompile":
                for flag in ["-target", "bpf", "-O2", "-g", "-Werror", "-fdebug-compilation-dir=."]:
                    if flag not in command:
                        raise ValueError("BPF action omitted compiler flag: " + flag)
                for suffix in ["/kernel/include/linux/bpf.h", "/libbpf/include/bpf/bpf_helpers.h"]:
                    bindings.append(require_input(event, suffix, tools / suffix.removeprefix("/")))
            elif command[1:3] != ["-g", "-o"]:
                raise ValueError("BPF strip action changed its BTF-preserving flags")
        else:
            bindings.append(require_input(event, "aos_tools/closure.json", compilers / "closure.json"))
            bindings.append(require_input(event, "aos_tools/bin/cc", compilers / "bin/cc"))
            if kind == "CppLink":
                for name in ["bpf", "json"]:
                    bindings.append(require_input(event, "/" + name + "/closure.json", native / name / "closure.json"))
                    identity = json.loads((native / name / "closure.json").read_text())
                    library = Path(identity["package"]) / identity["libraryFile"]
                    matches = [entry for entry in event["inputs"]
                               if entry["path"].endswith("/" + library.name)
                               and entry.get("digest", {}).get("hash") == sha(library)]
                    if not matches:
                        raise ValueError("native BPF linker omitted selected library bytes: " + name)
                    bindings.extend(matches)
        if kind in {"CppCompile", "AosBpfCompile"}:
            if not all(flag in command for flag in ["-O2", "-Wall", "-Wextra", "-Werror"]):
                raise ValueError("native BPF compiler changed required optimization or diagnostics")
            suffix = ".bpf.c" if kind == "AosBpfCompile" else ".c"
            policy = "lsm" if "-lsm-" in event["targetLabel"] else "net"
            name = "pkgs/security/aos-ebpf-" + policy + "-policy" + suffix
            bindings.append(require_input(event, name, source / name))
        result.append({"label": event["targetLabel"], "mnemonic": kind, "runner": event["runner"],
                       "command": command, "bound_inputs": bindings, "outputs": event["actualOutputs"]})
    return result


def command_parity(loaders, objects, directory):
    """Cross-tests both loaders against both object builders and rejection cases."""
    results = []
    for policy, programs in loaders.items():
        document = directory / (policy + ".json")
        document.write_text(json.dumps(POLICIES[policy]))
        malformed = directory / (policy + "-malformed.json")
        malformed.write_text("{invalid")
        cases = [("no-arguments", [], 2), ("help", ["validate", "--help"], 0),
                 ("missing-object", ["validate", "--policy", str(document)], 2),
                 ("unknown-option", ["validate", "--unknown"], 2)]
        for driver in ["baseline", "bazel"]:
            object_path = objects[policy][driver]
            common = ["validate", "--policy", str(document), "--object", str(object_path)]
            cases.extend([
                (driver + "-valid", common, 0),
                (driver + "-malformed-json", ["validate", "--policy", str(malformed), "--object", str(object_path)], 1),
                (driver + "-absent-policy", ["validate", "--policy", str(directory / "absent"), "--object", str(object_path)], 1),
                (driver + "-unknown-mode", ["unknown", *common[1:]], 2),
                (driver + "-missing-pin-directory", ["load", *common[1:]], 2),
            ])
            other = "net" if policy == "lsm" else "lsm"
            cases.append((driver + "-foreign-object", ["validate", "--policy", str(document),
                                                       "--object", str(objects[other][driver])], 1))
        truncated = directory / (policy + "-truncated.bpf.o")
        truncated.write_bytes(objects[policy]["bazel"].read_bytes()[:32])
        cases.append(("truncated-object", ["validate", "--policy", str(document), "--object", str(truncated)], 1))
        cases.append(("absent-object", ["validate", "--policy", str(document),
                                         "--object", str(directory / "absent.bpf.o")], 1))
        for name, arguments, expected in cases:
            executions = [subprocess.run([str(programs[driver]), *arguments], capture_output=True, timeout=30)
                          for driver in ["baseline", "bazel"]]
            before, after = [(item.returncode, item.stdout, item.stderr) for item in executions]
            if before != after or before[0] != expected:
                raise ValueError("native BPF loader parity failed: " + policy + "/" + name + ": " + repr([before, after]))
            results.append({"policy": policy, "case": name, "status": expected,
                            "stdout_sha256": hashlib.sha256(before[1]).hexdigest(),
                            "stderr_sha256": hashlib.sha256(before[2]).hexdigest()})
    return results


def verify(options):
    """Requires object semantics, native runtime contracts, and CLI parity."""
    files = exported_files(options.build)
    objects, loaders, contracts = {}, {}, {}
    for policy, loader_name in LOADERS.items():
        stem = "aos-ebpf-" + policy + "-policy"
        destination = "aos-ebpf-lsm-task-audit.bpf.o" if policy == "lsm" else stem + ".bpf.o"
        objects[policy] = {"baseline": options.baseline / (stem + ".bpf.o"),
                           "bazel": files["lib/bpf/" + destination]}
        object_results = {driver: object_contract(path, stem + ".bpf.c") for driver, path in objects[policy].items()}
        if object_results["baseline"][0] != object_results["bazel"][0]:
            raise ValueError("native BPF instructions, maps, types, or relocations differ: " + policy)
        if object_results["bazel"][1] != ["./pkgs/security/" + stem + ".bpf.c"]:
            raise ValueError("Bazel BTF retains a private build directory")
        loaders[policy] = {"baseline": options.baseline / loader_name, "bazel": files["libexec/" + loader_name]}
        elf = {driver: elf_contract(path, options.readelf, options.loader) for driver, path in loaders[policy].items()}
        for driver, path in loaders[policy].items():
            elf[driver]["elf_type_machine_version"] = list(struct.unpack_from("<HHI", path.read_bytes(), 16))
        if ({k: v for k, v in elf["baseline"].items() if k != "rpath_directories"}
                != {k: v for k, v in elf["bazel"].items() if k != "rpath_directories"}):
            raise ValueError("native BPF loader imports or resolved library identities differ: " + policy)
        contracts[policy] = {"object": object_results["bazel"][0],
                             "source_locations": {driver: result[1] for driver, result in object_results.items()},
                             "elf": elf, "objects": {driver: sha(path) for driver, path in objects[policy].items()}}
    with tempfile.TemporaryDirectory(prefix="aos-bpf-native-") as directory:
        cases = command_parity(loaders, objects, Path(directory))
    return {"schema_version": 1, "scope": "native-artifacts-and-userspace-validation",
            "actions": actions(options.build, options.source, options.tools, options.native, options.compilers),
            "contracts": contracts, "command_cases": cases,
            "kernel_attachment_qualified": False, "rust_provider_package_qualified": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["build", "baseline", "source", "tools", "native", "compilers", "readelf", "loader", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    options = parser.parse_args()
    report = verify(options)
    options.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
