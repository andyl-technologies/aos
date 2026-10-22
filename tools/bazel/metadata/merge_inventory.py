"""Combines configured build/test selections without rerunning analysis."""

import argparse
import hashlib
import json
from pathlib import Path

from export_inventory import inventory


def merge(root, inputs):
    """Rejects stale inputs and merges distinct configured target reports."""
    reports = {}
    targets = set()
    declarations = set()
    generator = hashlib.sha256(Path(__file__).with_name("export_inventory.py").read_bytes()).hexdigest()
    for value in inputs:
        if value["schema_version"] != 1 or value["generator_sha256"] != generator:
            raise ValueError("stale source inventory exporter")
        for name, digest in value["contracts"].items():
            if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
                raise ValueError(f"stale source inventory contract: {name}")
        targets.update(value["targets"])
        declarations.update(value["contracts"])
        for report in value["configured_targets"]:
            reports[json.dumps(report, sort_keys=True)] = report
    return inventory(root, sorted(targets), list(reports.values()), declarations)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, nargs="+", required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    result = merge(options.root, [json.loads(path.read_text()) for path in options.inputs])
    options.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
