"""Qualifies target cache separation, execution-tool reuse and fresh restoration."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from verify_cache import execution_events, package_files, require_action
from verify_cross_linux import elf_machine


def verify(native, foreign, restored, qemu):
    """Requires real native/foreign artifacts and isolated action identities."""
    builds = {"native": native, "foreign": foreign, "restored": restored}
    if len(set(builds.values())) != 3:
        raise ValueError("target invalidation requires three distinct Nix outputs")
    events = {name: execution_events(build) for name, build in builds.items()}
    actions = {}
    for target, mnemonic in [
        ("generated", "AosPythonGenerate"),
        ("fixture_macro", "Rustc"),
        ("generated_library", "Rustc"),
        ("rust_library", "Rustc"),
        ("rust_app", "Rustc"),
        ("native_app", "Rustc"),
        ("cpp_library", "CppCompile"),
        ("cpp_app", "CppCompile"),
        ("cpp_app", "CppLink"),
    ]:
        label = "//tools/bazel/tests/fixture:" + target
        original = require_action(events["native"], label, mnemonic, hit=False)
        # The proc macro retains its execution configuration. A generator's
        # output paths can change with target configuration, even when its
        # script and interpreter are unchanged; record that distinction.
        selected = [event for event in events["foreign"]
                    if event["targetLabel"] == label and event["mnemonic"] == mnemonic]
        if len(selected) != 1:
            raise ValueError(f"missing unique foreign action: {label}: {mnemonic}")
        hit = selected[0]["cacheHit"] if target == "generated" else target == "fixture_macro"
        changed = require_action(events["foreign"], label, mnemonic, hit=hit)
        same = original["fingerprint"] == changed["fingerprint"]
        if same != hit:
            raise ValueError(f"target change restored an incompatible action: {label}: {mnemonic}")
        if original["action_digest"] is None or changed["action_digest"] is None:
            raise ValueError("target invalidation omitted a cache action digest")
        if (original["action_digest"] == changed["action_digest"]) != same:
            raise ValueError("target action digest disagrees with semantic identity")
        reused = require_action(events["restored"], label, mnemonic, hit=True)
        if changed["fingerprint"] != reused["fingerprint"] or changed["action_digest"] != reused["action_digest"]:
            raise ValueError(f"fresh foreign restoration changed identity: {label}: {mnemonic}")

        if mnemonic == "Rustc":
            foreign_std = any("/rustlib/aarch64-unknown-linux-gnu/lib/libstd-" in entry["path"]
                              for entry in selected[0].get("inputs", []))
            if foreign_std != (target != "fixture_macro"):
                raise ValueError(f"incorrect execution/target standard library: {label}")
        actions[target + ":" + mnemonic] = {"native": original, "foreign": changed, "restored": reused}

    files = {name: package_files(build) for name, build in builds.items()}
    expected = {"bin/rust-fixture": "answer=42", "bin/cpp-fixture": "answer=42", "bin/native-fixture": "answer=84"}
    artifacts = {}
    for name, paths in files.items():
        if paths.keys() != expected.keys():
            raise ValueError("target invalidation omitted a declared executable")
        artifacts[name] = {}
        for destination, path in paths.items():
            contents = path.read_bytes()
            if elf_machine(contents) != (62 if name == "native" else 183):
                raise ValueError(f"incorrect ELF target: {name}: {destination}")
            if name == "restored" and contents != files["foreign"][destination].read_bytes():
                raise ValueError("fresh foreign restoration changed artifact bytes")
            command = [str(path)] if name == "native" else [str(qemu), str(path)]
            result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
            if result.stdout.strip() != expected[destination]:
                raise ValueError(f"incorrect {name} runtime output: {destination}: {result.stdout}")
            artifacts[name][destination] = {"sha256": hashlib.sha256(contents).hexdigest(), "stdout": result.stdout}
    return {"schema_version": 1, "builds": {name: str(path) for name, path in builds.items()},
            "actions": actions, "artifacts": artifacts, "foreign_runtime": "AOS source-built QEMU linux-user"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["native", "foreign", "restored", "qemu", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    evidence = verify(options.native, options.foreign, options.restored, options.qemu)
    options.output.mkdir(parents=True, exist_ok=True)
    (options.output / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
