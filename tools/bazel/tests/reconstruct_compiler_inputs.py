"""Reconstructs Rust compiler arguments from execution-bound wrapper input bytes."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from compiler_wrapper import expand_wrapper
from retain_compiler_inputs import action_candidates, command_digest, executed_command, wrapper_files
from verify_cache import execution_events


SYMBOLIC_ROOTS = {
    "pwd": "${AOS_ACTION_WORKING_DIRECTORY}",
    "output_base": "${AOS_BAZEL_OUTPUT_BASE}",
    "exec_root": "${AOS_EXECUTION_ROOT}",
}


def reconstruct(graph, events, retained):
    """Requires complete action/file inventories and checks every consumed digest."""
    if retained.get("schema_version") != 1:
        raise ValueError("unsupported compiler input retention schema")
    candidates = action_candidates(graph)
    recorded = Counter()
    for action in retained["actions"]:
        recorded[action["target_label"], action["command_sha256"], json.dumps(action["files"], sort_keys=True)] += 1
    files = retained["files"]
    consumed = set()
    actual = Counter()
    actions = []
    for event in events:
        if event["mnemonic"] != "Rustc":
            continue
        if event["exitCode"] != 0:
            raise ValueError("cannot reconstruct a failed Rust compiler action")
        command = executed_command(candidates, event)
        selected = wrapper_files(command)
        digest = command_digest(command)
        actual[event["targetLabel"], digest, json.dumps(selected, sort_keys=True)] += 1
        inputs = {entry["path"]: entry for entry in event["inputs"]}
        text = {}
        for reference in selected:
            name = reference["path"]
            if name not in files or name not in inputs:
                raise ValueError("missing executed or retained compiler input: " + name)
            contents = files[name]
            data = contents["text"].encode("utf-8")
            fingerprint = hashlib.sha256(data).hexdigest()
            if (len(data) != contents["size"] or fingerprint != contents["sha256"]
                    or fingerprint != inputs[name].get("digest", {}).get("hash")):
                raise ValueError("retained compiler input differs from execution digest: " + name)
            text[name] = contents["text"]
            consumed.add(name)
        environment = {}
        for entry in event["environmentVariables"]:
            if entry["name"] in environment:
                raise ValueError("ambiguous executed compiler environment")
            environment[entry["name"]] = entry.get("value", "")
        expanded = expand_wrapper(command, environment, text, SYMBOLIC_ROOTS)
        actions.append({"target_label": event["targetLabel"], "command_sha256": digest, **expanded})
    if actual != recorded:
        raise ValueError("retained compiler action inventory differs from execution")
    if consumed != files.keys():
        raise ValueError("retained compiler file inventory contains unconsumed inputs")
    return {"schema_version": 1, "actions": actions, "symbolic_execution_roots": SYMBOLIC_ROOTS,
            "limits": [
                "Sandbox working-directory, output-base, and execution-root identities remain explicit symbolic roots.",
                "This reconstructs wrapper inputs. Compiler defaults, native ABI, runtime closure, and semantic equivalence need independent checks.",
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    evidence = options.build / "evidence"
    graph = json.loads((evidence / "actions.json").read_text())
    retained = json.loads((evidence / "compiler-inputs.json").read_text())
    result = reconstruct(graph, execution_events(options.build), retained)
    result["inputs_sha256"] = {
        name: hashlib.sha256((evidence / name).read_bytes()).hexdigest()
        for name in ["actions.json", "execution.json", "compiler-inputs.json"]
    }
    options.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
