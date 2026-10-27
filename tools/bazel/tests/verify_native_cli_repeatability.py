"""Checks raw and installed CLI programs from distinct uncached builds."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from verify_cache import execution_events


def verify(first, second, installed, repeated, runtime):
    """Authenticates executions and compares the exact declared program bytes."""
    assert first != second and installed != repeated
    assert (first / "inventory.json").read_bytes() == (second / "inventory.json").read_bytes()
    requests = [json.loads((build / "evidence/compiler-invocations.json").read_text())["actions"]
                for build in [first, second]]
    assert requests[0] and requests[0] == requests[1]
    runtime_report = json.loads(runtime.read_text())
    commands = runtime_report["commands"]
    assert len(commands) == 15
    assert all(item["loader_exit_code"] == 0 for item in commands.values())
    assert {name for name, item in commands.items()
            if item.get("help_exit_code") == 0} == {"aos", "apm", "apr"}
    for package in [installed, repeated]:
        assert {path.name for path in (package / "bin").iterdir()} == set(commands)

    label = "//crates/cli/aos-cli:production_binaries"
    identifier = hashlib.sha256(label.encode()).hexdigest()
    packages = []
    runs = {}
    for build in [first, second]:
        index = json.loads((build / "packages/index.json").read_text())
        assert index == {label: identifier}
        packages.append(build / "packages" / identifier)
        events = execution_events(build)
        assert events and all(event["runner"] == "linux-sandbox" and not event["cacheHit"]
                              and event["exitCode"] == 0 for event in events)
        runs[str(build)] = {
            "executed_actions": len(events),
            "action_cache_hits": 0,
            "action_mnemonics": dict(sorted(Counter(event["mnemonic"] for event in events).items())),
            "execution_sha256": hashlib.sha256((build / "evidence/execution.json").read_bytes()).hexdigest(),
        }

    assert (packages[0] / "manifest.json").read_bytes() == (packages[1] / "manifest.json").read_bytes()
    manifest = json.loads((packages[0] / "manifest.json").read_text())
    assert {entry["destination"] for entry in manifest["artifacts"]} == {"bin/" + name for name in commands}
    assert len(manifest["artifacts"]) == len(commands)
    artifacts = {}
    for entry in manifest["artifacts"]:
        destination = entry["destination"]
        assert entry["mode"] == "0755"
        raw = [(package / "files" / destination).read_bytes() for package in packages]
        assert raw[0] == raw[1] and hashlib.sha256(raw[0]).hexdigest() == entry["sha256"]
        assert not re.search(rb"/sandbox/linux-sandbox/[0-9]+/execroot/", raw[0])
        fixed = [(package / destination).read_bytes() for package in [installed, repeated]]
        assert fixed[0] == fixed[1]
        artifacts[destination] = {
            "raw_sha256": entry["sha256"],
            "installed_sha256": hashlib.sha256(fixed[0]).hexdigest(),
        }

    return {
        "schema_version": 1,
        "status": "PASS",
        "runs": runs,
        "first_installed": str(installed),
        "second_installed": str(repeated),
        "compiler_requests": len(requests[0]),
        "artifacts": artifacts,
        "runtime_smoke": runtime_report,
        "limits": ["Checks the declared CLI programs and their normal installed bytes, not all intermediate build-script files, native ABI, runtime services, cache restoration, or performance."],
    }


def main():
    """Writes the repeatability evidence after all comparisons pass."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["first", "second", "installed", "repeated", "runtime", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    options = parser.parse_args()
    report = verify(options.first, options.second, options.installed, options.repeated, options.runtime)
    options.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
