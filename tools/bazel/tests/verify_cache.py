"""Qualifies local cache reuse using execution events and exported artifacts."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess


def execution_events(build):
    """Reads Bazel's stream of successive JSON execution records."""
    text = (build / "evidence/execution.json").read_text()
    decoder = json.JSONDecoder()
    events = []
    position = 0
    # Execution logs can exceed hundreds of megabytes. Advance within the
    # original string instead of repeatedly copying its unconsumed suffix.
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if position == len(text):
            break
        event, position = decoder.raw_decode(text, position)
        events.append(event)
    return events


def package_files(build):
    index = json.loads((build / "packages/index.json").read_text())
    package = build / "packages" / index["//tools/bazel/tests/fixture:package"]
    manifest = json.loads((package / "manifest.json").read_text())
    return {entry["destination"]: package / "files" / entry["destination"] for entry in manifest["artifacts"]}


def require_action(events, label, mnemonic, hit):
    selected = [event for event in events if event["targetLabel"] == label and event["mnemonic"] == mnemonic]
    if len(selected) != 1:
        raise ValueError(f"expected one {mnemonic} action for {label}, got {len(selected)}")
    event = selected[0]
    if event["cacheHit"] != hit or event["exitCode"] != 0:
        raise ValueError(f"unexpected cache result for {label}: {event['runner']}, hit={event['cacheHit']}")
    if hit and "cache" not in event["runner"]:
        raise ValueError(f"cache hit unexpectedly used an execution runner: {event['runner']}")
    action_digest = event.get("digest")
    if action_digest is not None:
        if (action_digest.get("hashFunctionName") != "SHA256"
                or not re.fullmatch(r"[0-9a-f]{64}", action_digest.get("hash", ""))
                or int(action_digest.get("sizeBytes", 0)) <= 0):
            raise ValueError(f"invalid Bazel action digest for {label}: {action_digest}")
    if hit and action_digest is None:
        raise ValueError(f"cache hit omitted its Bazel action digest: {label}")
    # With the cache disabled Bazel omits the REAPI action digest. Keep a
    # separate semantic fingerprint for comparison with the uncached oracle.
    identity = {key: event.get(key) for key in ["commandArgs", "environmentVariables", "inputs", "platform"]}
    fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    return {"fingerprint": fingerprint, "action_digest": action_digest, "runner": event["runner"], "cache_hit": hit}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["producer", "consumer", "uncached", "output"]:
        parser.add_argument(f"--{name}", type=Path, required=True)
    options = parser.parse_args()
    builds = {name: getattr(options, name) for name in ["producer", "consumer", "uncached"]}
    if len(set(builds.values())) != 3:
        raise ValueError("cache proof requires three distinct Nix derivation outputs")
    records = {name: execution_events(build) for name, build in builds.items()}
    evidence = {"schema_version": 1, "builds": {name: str(path) for name, path in builds.items()}, "actions": {}}
    prefix = "//tools/bazel/tests/fixture:"
    for target, mnemonic, unchanged in [
        ("generated", "AosPythonGenerate", True),
        ("generated_library", "Rustc", True), ("fixture_macro", "Rustc", True),
        ("rust_library", "Rustc", True), ("cpp_library", "CppCompile", True),
        ("native_app", "Rustc", True),
        ("rust_app", "Rustc", False), ("cpp_app", "CppCompile", False),
    ]:
        actions = {}
        for name, events in records.items():
            actions[name] = require_action(events, prefix + target, mnemonic, hit=name == "consumer" and unchanged)
        if unchanged and actions["producer"]["fingerprint"] != actions["consumer"]["fingerprint"]:
            raise ValueError(f"unchanged action identity differs across Nix derivations: {target}")
        if not unchanged and actions["producer"]["fingerprint"] == actions["consumer"]["fingerprint"]:
            raise ValueError(f"edited action did not change identity: {target}")
        if any(actions[name]["action_digest"] is None for name in ["producer", "consumer"]):
            raise ValueError(f"disk-cache experiment omitted an action digest: {target}")
        if (actions["producer"]["action_digest"] == actions["consumer"]["action_digest"]) != unchanged:
            raise ValueError(f"unexpected Bazel action digest across Nix derivations: {target}")
        evidence["actions"][target] = actions

    artifacts = {name: package_files(build) for name, build in builds.items()}
    evidence["artifacts"] = {}
    for destination in artifacts["consumer"]:
        restored = artifacts["consumer"][destination]
        rebuilt = artifacts["uncached"][destination]
        if restored.read_bytes() != rebuilt.read_bytes():
            raise ValueError(f"cached and uncached artifacts differ: {destination}")
        for name in builds:
            expected = "answer=42" if name == "producer" else "answer=43"
            if destination == "bin/native-fixture":
                expected = "answer=84"
            result = subprocess.run([str(artifacts[name][destination])], check=True, text=True, capture_output=True)
            if result.stdout.strip() != expected:
                raise ValueError(f"incorrect {name} program output: {destination}")
        evidence["artifacts"][destination] = hashlib.sha256(restored.read_bytes()).hexdigest()
    evidence["summary"] = {
        name: dict(Counter(f"{event['mnemonic']}:{event['runner']}" for event in events))
        for name, events in records.items()
    }
    options.output.mkdir(parents=True, exist_ok=True)
    (options.output / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
