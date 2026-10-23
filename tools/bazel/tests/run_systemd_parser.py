"""Executes Bazel-built systemd libtests with Nix-declared parser tools.

The source-built systemd executable and its vendor unit directory belong to
the enclosing Nix sandbox. The shared libtest runner retains case isolation,
timeouts and scheduling policy; this adapter records its successful XML output
for the ordinary Cargo case and feature comparison.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--runner", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()

    environment = {
        name: os.environ[name]
        for name in ["AOS_SYSTEMD_ANALYZE", "AOS_SYSTEMD_UNIT_PATH", "AOS_SYSTEMD_PARSER_SHELL"]
    }
    if not all(Path(path).exists() for path in environment.values()):
        raise ValueError("declared systemd parser tools or vendor units are absent")

    options.output.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((options.artifacts.parent / "nix-support/bazel-package.json").read_text())
    declared = {entry["destination"]: entry["sha256"] for entry in manifest["artifacts"]}
    binaries = [
        ("aos-systemd-native-resource-provider", "native-parser-tests"),
        ("aos-systemd-credential-encrypt", "credential-parser-tests"),
    ]
    artifact_hashes = {}
    for _, artifact in binaries:
        actual = hashlib.sha256((options.artifacts / artifact).read_bytes()).hexdigest()
        if declared.get("libexec/" + artifact) != actual:
            raise ValueError("installed parser libtest bytes differ from the Bazel export: " + artifact)
        artifact_hashes[artifact] = actual

    results = []
    for command, artifact in binaries:
        xml_name = command + ".xml"
        log_name = command + ".log"
        invocation_environment = {**os.environ, "XML_OUTPUT_FILE": str(options.output / xml_name)}
        with (options.output / log_name).open("w") as log:
            result = subprocess.run(
                [
                    sys.executable, str(options.runner),
                    "--binary", str(options.artifacts / artifact),
                    "--package", "aos-activation-systemd",
                    "--policy", str(options.policy), "--jobs", "4",
                ],
                env=invocation_environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
            )

        if result.returncode:
            sys.stderr.write((options.output / log_name).read_text())
            result.check_returncode()

        xml = ET.parse(options.output / xml_name)
        cases = xml.findall("testcase")
        if not cases or any(case.find("failure") is not None for case in cases):
            raise ValueError("systemd parser artifact has no successful test inventory")

        results.append({
            "identity": {"label": "//crates/aos/activation/aos-activation-systemd:bin_" + command + "_parser"},
            "status": "PASSED",
            "outputs": {"test.xml": xml_name, "test.log": log_name},
        })

    report = {
        "schema_version": 1,
        "runner": "Nix sandbox with Bazel-built libtest artifacts",
        "environment": environment,
        "artifact_sha256": artifact_hashes,
        "results": results,
    }
    (options.output / "index.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
