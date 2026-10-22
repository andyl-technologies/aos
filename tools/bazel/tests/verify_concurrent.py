"""Checks overlapping Nix builders sharing only their disk action cache."""

import argparse
import hashlib
import json
from pathlib import Path

from verify_cache import execution_events, package_files, require_action


def verify(left, right, original, edited):
    builds = {"left": left, "right": right}
    metrics = {name: json.loads((build / "evidence/metrics.json").read_text()) for name, build in builds.items()}
    start = max(metric["started_unix_ns"] for metric in metrics.values())
    finish = min(metric["finished_unix_ns"] for metric in metrics.values())
    if start >= finish:
        raise ValueError("builders did not overlap; run with at least two available Nix build jobs")
    if metrics["left"]["disk_cache"] != metrics["right"]["disk_cache"] or not metrics["left"]["disk_cache"]:
        raise ValueError("concurrent builders did not share the same disk cache")
    # Nix maps each sandbox's builder to the same visible UID and PID. Compare
    # namespaces and directory identity instead of mistaking those for sharing.
    for namespace in ["mnt", "pid", "user"]:
        if metrics["left"]["namespaces"][namespace] == metrics["right"]["namespaces"][namespace]:
            raise ValueError(f"concurrent Nix builds share their {namespace} namespace")
    if metrics["left"]["output_base_inode"] == metrics["right"]["output_base_inode"]:
        raise ValueError("concurrent Nix builds share an output directory")
    evidence = {"schema_version": 1, "metrics": metrics, "overlap_seconds": (finish - start) / 1e9, "artifacts": {}, "actions": {}}
    for name, oracle in [("left", original), ("right", edited)]:
        artifacts = package_files(builds[name])
        expected = package_files(oracle)
        if artifacts.keys() != expected.keys():
            raise ValueError("concurrent and isolated artifact sets differ")
        evidence["artifacts"][name] = {}
        for destination, path in artifacts.items():
            if path.read_bytes() != expected[destination].read_bytes():
                raise ValueError(f"concurrent output differs from isolated execution: {name}: {destination}")
            evidence["artifacts"][name][destination] = hashlib.sha256(path.read_bytes()).hexdigest()
        events = execution_events(builds[name])
        if any(event["exitCode"] != 0 for event in events):
            raise ValueError("an action failed during concurrent cache access")
        evidence["actions"][name] = {}
        for target, mnemonic in [("rust_library", "Rustc"), ("cpp_library", "CppCompile"), ("generated", "AosPythonGenerate")]:
            label = "//tools/bazel/tests/fixture:" + target
            selected = [event for event in events if event["targetLabel"] == label and event["mnemonic"] == mnemonic]
            if len(selected) != 1:
                raise ValueError("concurrent build omitted a required action")
            evidence["actions"][name][target] = require_action(events, label, mnemonic, hit=selected[0]["cacheHit"])
    for target in evidence["actions"]["left"]:
        if evidence["actions"]["left"][target]["fingerprint"] != evidence["actions"]["right"][target]["fingerprint"]:
            raise ValueError(f"unchanged concurrent action identity differs: {target}")
    return evidence


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["left", "right", "original", "edited", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    options = parser.parse_args()
    result = verify(options.left, options.right, options.original, options.edited)
    options.output.mkdir(parents=True, exist_ok=True)
    (options.output / "evidence.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
