"""Executes exported family libtests inside their target Linux kernel."""

import argparse
import hashlib
import json
import os
from pathlib import Path

from family_libtest import validate


def run(compilation, workspace, output):
    """Checks the exported bytes and exact case inventory before reporting pass."""
    manifest = compilation / "parity.json"
    report = json.loads(manifest.read_text())
    binaries = {}
    for label, artifact in report["artifacts"].items():
        binary = compilation / artifact["file"]
        if hashlib.sha256(binary.read_bytes()).hexdigest() != artifact["sha256"]:
            raise ValueError(f"guest test artifact digest changed: {label}")
        binaries[label] = binary

    output.mkdir(parents=True, exist_ok=True)
    validate(binaries, report["targets"], workspace, output, dict(os.environ))
    for log in sorted(output.glob("validation-*.log")):
        print(log.read_text(), flush=True)
    return {"schema_version": 1, "target": report["target"],
            "compilation_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            "executed_targets": len(binaries), "executed_cases": report["compiled_cases"],
            "ignored_cases": report["ignored_cases"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["compilation", "workspace", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    options = parser.parse_args()
    result = run(options.compilation, options.workspace, options.output)
    print("AOS_BAZEL_FAMILY_VM_PASS " + json.dumps(result, sort_keys=True), flush=True)
