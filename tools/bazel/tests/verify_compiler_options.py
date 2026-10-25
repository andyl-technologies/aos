"""Pairs retained first-party compile actions with captured Cargo invocations.

This audit verifies cfg and edition arguments, expanding digest-checked wrapper
inputs when retained and otherwise identifying the older direct-only scope.
Codegen and link options remain available for review. Matching those selections
does not establish identical artifacts or equivalent compiler profiles.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath

from verify_cache import execution_events
from reconstruct_compiler_inputs import reconstruct
from retain_compiler_inputs import action_candidates, command_digest, executed_command


# Rust accumulates metadata values; they remain in the ordered option evidence.
SCALAR_CODEGEN = {
    "opt-level", "debuginfo", "debug-assertions", "overflow-checks", "panic",
    "lto", "embed-bitcode", "codegen-units", "strip", "target-cpu",
    "relocation-model", "incremental", "extra-filename", "linker",
}


def compiler_options(arguments):
    """Retains repeated options while identifying effective scalar codegen values."""
    options = {"cfg": [], "codegen": [], "edition": None, "target": None, "test": False}
    scalar = {}
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in {"-C", "--codegen", "--cfg", "--edition", "--target"}:
            if index + 1 == len(arguments):
                raise ValueError("missing compiler option value: " + argument)
            index += 1
            name, value = argument, arguments[index]
        elif argument.startswith("-C"):
            name, value = "-C", argument[2:]
        elif any(argument.startswith(prefix + "=") for prefix in ["--codegen", "--cfg", "--edition", "--target"]):
            name, _, value = argument.partition("=")
        else:
            if argument == "--test":
                options["test"] = True
            index += 1
            continue

        if not value:
            raise ValueError("empty compiler option value: " + name)
        if name in {"-C", "--codegen"}:
            key, separator, setting = value.partition("=")
            if not key or (separator and not setting):
                raise ValueError("invalid compiler codegen option: " + value)
            options["codegen"].append(value)
            if key in SCALAR_CODEGEN:
                scalar[key] = setting if separator else True
        elif name == "--cfg":
            options["cfg"].append(value)
        else:
            options[name[2:]] = value
        index += 1

    options["cfg"].sort()
    options["effective_scalar_codegen"] = scalar
    return options


def compilation_source(arguments, prefix):
    """Selects one positional first-party source without interpreting shell text."""
    sources = [argument for argument in arguments
               if argument.startswith(prefix) and argument.endswith(".rs")]
    if len(sources) > 1:
        raise ValueError("ambiguous first-party compilation source")
    return sources[0] if sources else None


def cargo_compilation_source(invocation):
    """Maps captured workspace sources without depending on crate domain names."""
    directory = PurePosixPath(invocation["directory"])
    if not directory.is_absolute() or "crates" not in directory.parts:
        return None

    # Cargo runs from the workspace or a package directory. Registry sources
    # live outside this root and must not become first-party compiler units.
    workspace_end = len(directory.parts) - directory.parts[::-1].index("crates")
    workspace = PurePosixPath(*directory.parts[:workspace_end])
    sources = []
    for argument in invocation["arguments"]:
        if argument.startswith("-") or not argument.endswith(".rs"):
            continue
        source = PurePosixPath(posixpath.normpath(str(directory / argument)))
        if source.is_relative_to(workspace):
            sources.append("crates/" + str(source.relative_to(workspace)))

    if len(sources) > 1:
        raise ValueError("ambiguous first-party compilation source")
    return sources[0] if sources else None


def pair_invocations(bazel, cargo):
    """Requires complete, unambiguous source/libtest pairing and explicit cfg/edition parity."""
    def indexed(invocations):
        result = {}
        for invocation in invocations:
            options = compiler_options(invocation["arguments"])
            key = (invocation["source"], options["test"])
            if key in result:
                raise ValueError("ambiguous compiler invocation: " + str(key))
            result[key] = {**invocation, "options": options}
        return result

    bazel, cargo = indexed(bazel), indexed(cargo)
    if not bazel or bazel.keys() != cargo.keys():
        raise ValueError("first-party compiler unit inventories differ")
    pairs = []
    for key in sorted(bazel):
        left, right = bazel[key], cargo[key]
        for field in ["cfg", "edition"]:
            if left["options"][field] != right["options"][field]:
                raise ValueError("compiler " + field + " differs: " + str(key))
        differences = {
            field: {"bazel": left["options"][field], "cargo": right["options"][field]}
            for field in left["options"] if left["options"][field] != right["options"][field]
        }
        pairs.append({"source": key[0], "test": key[1], "differences": differences,
                      "bazel": left, "cargo": right})
    return pairs


def audit(build, cargo):
    """Binds Bazel response files to execution digests and pairs captured Cargo calls."""
    graph_path = build / "evidence/actions.json"
    trace_path = cargo / "compiler-arguments.jsonl"
    graph = json.loads(graph_path.read_text())
    events = execution_events(build)
    candidates = action_candidates(graph)
    indirect_path = build / "evidence/compiler-inputs.json"
    reconstructed = None
    if indirect_path.exists():
        reconstructed = reconstruct(graph, events, json.loads(indirect_path.read_text()))
    expanded = {
        (action["target_label"], action["command_sha256"]): action
        for action in reconstructed["actions"]
    } if reconstructed is not None else {}
    bazel = []
    for event in events:
        if event["mnemonic"] != "Rustc" or not event["targetLabel"].startswith("//crates/"):
            continue
        execution_command = executed_command(candidates, event)
        arguments = execution_command
        # Ignore wrapper arguments, which may include unrelated file paths.
        # The source-built rules_rust wrapper has one literal compiler delimiter.
        if arguments.count("--") != 1:
            raise ValueError("unsupported Rust process-wrapper compiler boundary")
        arguments = arguments[arguments.index("--") + 1:]
        reconstructed_action = expanded.get((event["targetLabel"], command_digest(execution_command)))
        if reconstructed_action is not None:
            arguments = reconstructed_action["arguments"]
        source = compilation_source(arguments, "crates/")
        if source is None:
            raise ValueError("first-party Rust action omitted its source")
        if event["exitCode"] != 0:
            raise ValueError("first-party Rust compiler action failed")
        bazel.append({"source": source, "arguments": arguments, "label": event["targetLabel"],
                      "cache_hit": event["cacheHit"], "runner": event["runner"],
                      "execution_command": execution_command,
                      **({"environment": reconstructed_action["environment"]} if reconstructed_action is not None else {})})

    cargo_invocations = []
    for line in trace_path.read_text().splitlines():
        invocation = json.loads(line)
        if invocation["schema_version"] != 1:
            raise ValueError("unsupported Cargo compiler trace schema")
        source = cargo_compilation_source(invocation)
        if source:
            cargo_invocations.append({**invocation, "source": source})
    pairs = pair_invocations(bazel, cargo_invocations)
    result = {
        "schema_version": 1,
        "status": "PASS: paired first-party invocations and matching "
                  + ("wrapper-expanded" if reconstructed is not None else "direct") + " cfg/edition arguments",
        "build": str(build), "cargo": str(cargo), "units": len(pairs), "pairs": pairs,
        "inputs_sha256": {"actions": hashlib.sha256(graph_path.read_bytes()).hexdigest(),
                          "compiler_trace": hashlib.sha256(trace_path.read_bytes()).hexdigest(),
                          "execution": hashlib.sha256((build / "evidence/execution.json").read_bytes()).hexdigest()},
        "limits": [
            ("Bazel response and indirect wrapper input files are bound to execution digests. Working-directory, output-base, and execution-root identities remain explicit symbolic roots."
             if reconstructed is not None else
             "Bazel response files are bound to execution input digests. Additional rules_rust wrapper argument/environment files are retained by path in execution_command but their contents are not expanded here."),
            "Compiler defaults and compiler/linker closure or ABI equivalence are not checked here.",
            "Codegen, target, linker, incremental, and artifact-identity differences are retained for explicit review; this audit does not establish semantic compiler-option equivalence.",
            "Scalar codegen options use their last explicit value. Repeated and unknown options remain in order; compiler defaults are not inferred.",
            "The source/test key requires an unambiguous native family. Families compiling the same source in multiple execution/target configurations need an explicit role-aware comparison.",
            "Captured Cargo invocations prove compiler execution was requested, not that every request succeeded. Runtime and compilation results require their independent gates.",
        ],
    }
    if reconstructed is not None:
        result["inputs_sha256"]["indirect_inputs"] = hashlib.sha256(indirect_path.read_bytes()).hexdigest()
        result["symbolic_execution_roots"] = reconstructed["symbolic_execution_roots"]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    options.output.write_text(json.dumps(audit(options.build, options.cargo), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
