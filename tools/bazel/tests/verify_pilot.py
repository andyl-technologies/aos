"""Compares the real Rust pilot's discovered cases with native rustc oracles."""

import argparse
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET


def cases(binary, ignored=False):
    command = [str(binary), "--list", "--format=terse"]
    if ignored:
        command.append("--ignored")
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return sorted(line.removesuffix(": test") for line in result.stdout.splitlines() if line.endswith(": test"))


def verify(root, oracles, allow_empty=()):
    results = json.loads((root / "index.json").read_text())["results"]
    records = {}
    for label, binary in oracles.items():
        selected = [result for result in results if result["identity"]["label"] == label]
        if len(selected) != 1 or selected[0]["status"] != "PASSED":
            raise ValueError(f"pilot target did not pass exactly once: {label}")
        ignored = cases(binary, ignored=True)
        expected = sorted(set(cases(binary)) - set(ignored))
        xml = ET.parse(root / selected[0]["outputs"]["test.xml"])
        actual = sorted(case.attrib["name"] for case in xml.findall("testcase"))
        if (not expected and label not in allow_empty) or actual != expected:
            raise ValueError(f"pilot test inventory differs: {label}: expected={expected}, actual={actual}")
        records[label] = {"executed": actual, "ignored": ignored}
    return {"schema_version": 1, "targets": records}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--oracles", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    oracles = {label: Path(path) for label, path in json.loads(options.oracles.read_text()).items()}
    options.output.write_text(json.dumps(verify(options.tests, oracles), indent=2, sort_keys=True) + "\n")
