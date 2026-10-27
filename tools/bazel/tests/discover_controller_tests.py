"""Retains libtest case discovery before a private Bazel build tree is removed.

Only successful default outputs of the requested test binaries are inspected.
Listing does not execute test cases and supplies no runtime qualification.
"""

import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import unquote, urlparse

from verify_pilot import cases


def binary_outputs(events, labels, execution_root):
    """Requires one completed, local executable per requested binary label."""
    if not labels or len(labels) != len(set(labels)):
        raise ValueError("test binary selection must be nonempty and unique")

    named_sets = {}
    completed = {}
    for event in events:
        identifier = event.get("id", {})
        if "namedSet" in identifier:
            key = identifier["namedSet"]["id"]
            if key in named_sets:
                raise ValueError("duplicate build-event file set")
            named_sets[key] = event["namedSetOfFiles"]

        target = identifier.get("targetCompleted", {})
        label = target.get("label", "").removeprefix("@@")
        if label not in labels or target.get("aspect"):
            continue
        if label in completed:
            raise ValueError("ambiguous completed test binary: " + label)
        value = event["completed"]
        if not value.get("success"):
            raise ValueError("unsuccessful test binary: " + label)
        completed[label] = value

    if set(completed) != set(labels):
        raise ValueError("build events omitted requested test binaries")

    root = execution_root.resolve(strict=True)
    outputs = {}
    for label, target in sorted(completed.items()):
        roots = [item["id"] for group in target.get("outputGroup", [])
                 if group["name"] == "default" for item in group.get("fileSets", [])]
        pending = [(key, ()) for key in roots]
        files = set()
        while pending:
            key, ancestors = pending.pop()
            if key in ancestors:
                raise ValueError("cyclic build-event file sets")
            value = named_sets[key]
            pending.extend((item["id"], (*ancestors, key)) for item in value.get("fileSets", []))
            for item in value.get("files", []):
                uri = urlparse(item["uri"])
                if uri.scheme != "file" or uri.netloc or uri.query or uri.fragment:
                    raise ValueError("test discovery requires a local output URI")
                binary = Path(unquote(uri.path)).resolve(strict=True)
                if not binary.is_file() or not binary.is_relative_to(root):
                    raise ValueError("test binary is outside the private execution root")
                files.add(binary)
        if len(files) != 1:
            raise ValueError("test target must produce exactly one binary: " + label)
        outputs[label] = files.pop()
    return outputs


def discover(outputs):
    """Lists all cases and ignored cases without executing any test body."""
    targets = {}
    for label, binary in sorted(outputs.items()):
        all_cases = cases(binary)
        ignored = cases(binary, ignored=True)
        if len(all_cases) != len(set(all_cases)) or len(ignored) != len(set(ignored)):
            raise ValueError("duplicate libtest case: " + label)
        if not set(ignored) <= set(all_cases):
            raise ValueError("ignored libtest case is absent from the complete list: " + label)
        with binary.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        targets[label] = {
            "binary_sha256": digest,
            "cases": all_cases,
            "ignored": ignored,
        }
    return {
        "schema_version": 1,
        "test_execution_qualified": False,
        "targets": targets,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--execution-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    events = [json.loads(line) for line in options.events.read_text().splitlines() if line]
    labels = json.loads(options.targets.read_text())
    outputs = binary_outputs(events, labels, options.execution_root)
    options.output.write_text(json.dumps(discover(outputs), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
