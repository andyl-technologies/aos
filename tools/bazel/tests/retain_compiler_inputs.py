"""Retains digest-checked rules_rust wrapper input files before build cleanup.

The action graph expands Bazel response files, but build-script argument and
environment files remain indirect inputs. Their exact bytes are needed for a
later compiler-option comparison; this snapshot does not interpret their syntax.
"""

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path, PurePosixPath

from verify_cache import execution_events
from verify_static_runtime import expanded_command


INPUT_FLAGS = {"--arg-file", "--env-file", "--stable-status-file", "--volatile-status-file"}


def command_digest(command):
    """Identifies the exact expanded argument vector without shell serialization."""
    return hashlib.sha256(json.dumps(command, separators=(",", ":")).encode()).hexdigest()


def action_candidates(graph):
    """Indexes configurations separately instead of assuming one action per label."""
    targets = {target["id"]: target["label"] for target in graph["targets"]}
    result = defaultdict(list)
    for action in graph["actions"]:
        label = targets[action["targetId"]]
        result[label, action["mnemonic"]].append({
            "targets": [{"id": action["targetId"], "label": label}], "actions": [action],
        })
    return result


def executed_command(candidates, event):
    """Requires one expanded vector matching the actual command and response digest."""
    matches = set()
    for graph in candidates.get((event["targetLabel"], event["mnemonic"]), []):
        try:
            matches.add(tuple(expanded_command(graph, event)))
        except ValueError:
            continue
    if len(matches) != 1:
        raise ValueError("Rust compiler execution has no unambiguous retained command")
    return list(matches.pop())


def file_write_inputs(graph):
    """Recovers virtual FileWrite inputs from aquery's declared output contents."""
    fragments = {fragment["id"]: fragment for fragment in graph.get("pathFragments", [])}
    paths = {}

    def path(identifier, active=()):
        if identifier in active:
            raise ValueError("cyclic action graph path fragments")
        if identifier not in paths:
            fragment = fragments[identifier]
            parent = fragment.get("parentId")
            prefix = path(parent, (*active, identifier)) + "/" if parent else ""
            paths[identifier] = prefix + fragment["label"]
        return paths[identifier]

    artifacts = {artifact["id"]: artifact for artifact in graph.get("artifacts", [])}
    result = {}
    for action in graph["actions"]:
        if action["mnemonic"] != "FileWrite":
            continue
        # Protobuf JSON omits an empty string. An omitted nonempty file cannot
        # pass the consuming execution's digest check below.
        data = action.get("fileContents", "").encode("utf-8")
        for identifier in action["outputIds"]:
            name = path(artifacts[identifier]["pathFragmentId"])
            if name in result and result[name] != data:
                raise ValueError("conflicting FileWrite contents for one artifact")
            result[name] = data
    return result


def wrapper_files(command):
    """Selects input-file flags before the wrapper's literal compiler delimiter."""
    if command.count("--") != 1:
        raise ValueError("unsupported Rust wrapper compiler boundary")
    wrapper = command[:command.index("--")]
    result = []
    index = 1
    while index < len(wrapper):
        argument = wrapper[index]
        name, separator, value = argument.partition("=")
        if name in INPUT_FLAGS:
            if not separator:
                index += 1
                if index == len(wrapper):
                    raise ValueError("missing Rust wrapper input-file value")
                value = wrapper[index]
            if not value or value.startswith("--"):
                raise ValueError("empty or ambiguous Rust wrapper input-file value")
            path = PurePosixPath(value)
            if path.is_absolute() or value != path.as_posix() or any(part in {"", ".", ".."} for part in value.split("/")):
                raise ValueError("Rust wrapper input must be a canonical execution-root path")
            result.append({"flag": name, "path": value})
        index += 1
    return result


def retain(graph, events, execution_root):
    """Binds every retained file to its successful compiler action's input digest."""
    files = {}
    actions = []
    candidates = action_candidates(graph)
    virtual_files = file_write_inputs(graph)
    for event in events:
        if event["mnemonic"] != "Rustc":
            continue
        if event["exitCode"] != 0:
            raise ValueError("cannot retain inputs from a failed Rust compiler action")
        command = executed_command(candidates, event)
        selected = wrapper_files(command)
        inputs = {entry["path"]: entry for entry in event["inputs"]}
        for entry in selected:
            name = entry["path"]
            if name not in inputs:
                raise ValueError("Rust wrapper file omitted from executed action inputs: " + name)
            # Bazel can materialize FileWrite inputs only inside action
            # sandboxes. Use their aquery contents with the same mandatory
            # execution digest verification as ordinary execution-root files.
            data = virtual_files[name] if name in virtual_files else (execution_root / name).read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if digest != inputs[name].get("digest", {}).get("hash"):
                raise ValueError("Rust wrapper input differs from execution digest: " + name)
            contents = {"sha256": digest, "size": len(data), "text": data.decode("utf-8")}
            if name in files and files[name] != contents:
                raise ValueError("Rust wrapper input changed between compiler actions: " + name)
            files[name] = contents
        actions.append({"target_label": event["targetLabel"], "command_sha256": command_digest(command), "files": selected})
    return {"schema_version": 1, "actions": actions, "files": dict(sorted(files.items()))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--execution-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    graph = json.loads((options.build / "evidence/actions.json").read_text())
    result = retain(graph, execution_events(options.build), options.execution_root)
    options.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
