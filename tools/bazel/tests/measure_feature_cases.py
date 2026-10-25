"""Runs the temporary Cargo feature-case oracle with source-built tools."""

import argparse
import json
from pathlib import Path
import subprocess

from verify_feature_powerset import validate_contract


def run(cargo, source, contract, output):
    """Retains each check's artifact features and fails on missing root evidence."""
    validate_contract(contract)
    reports = {}
    output.mkdir(parents=True, exist_ok=True)
    for index, case in enumerate(contract["cases"]):
        command = [str(cargo), "check", "--manifest-path", "crates/Cargo.toml", "--frozen", "--offline",
                   "--jobs", "2", "--message-format=json", "--verbose", "-p", case["package"]]
        if case["no_default_features"]:
            command.append("--no-default-features")
        if case["requested_features"]:
            command.extend(["--features", ",".join(case["requested_features"])])
        print("checking feature case: " + case["name"], flush=True)
        stdout = output / f"{index}.jsonl"
        stderr = output / f"{index}.log"
        with stdout.open("w") as events, stderr.open("w") as log:
            process = subprocess.run(command, cwd=source, stdout=events, stderr=log)
        if process.returncode:
            raise ValueError("Cargo feature check failed: " + case["name"] + "\n" + stderr.read_text()[-12000:])

        events = [json.loads(line) for line in stdout.read_text().splitlines()]
        artifacts = [event for event in events if event.get("reason") == "compiler-artifact"]
        expected_source = source / "crates/crucible" / case["package"] / "src/lib.rs"
        roots = [event for event in artifacts if Path(event["target"]["src_path"]) == expected_source
                 and "lib" in event["target"]["kind"]]
        if len(roots) != 1 or sorted(roots[0]["features"]) != sorted(case["expected_features"]):
            raise ValueError("Cargo root feature inventory differs: " + case["name"])
        if not any(event.get("reason") == "build-finished" and event["success"] for event in events):
            raise ValueError("Cargo did not report a successful feature check")
        reports[case["name"]] = {"command": command, "features": sorted(roots[0]["features"]),
                                 "artifact": roots[0], "stdout": stdout.name, "stderr": stderr.name}
    return {"schema_version": 1, "scope": "temporary Cargo check oracle; feature selection only", "cases": reports}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    report = run(options.cargo, options.source.resolve(), json.loads(options.contract.read_text()), options.output)
    (options.output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
