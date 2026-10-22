"""Verifies foreign ELF artifacts, native execution tools, and emulated behavior."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from verify_cache import execution_events, package_files, require_action


def elf_machine(contents):
    if contents[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected a 64-bit little-endian ELF artifact")
    return int.from_bytes(contents[18:20], "little")


def verify(build, qemu):
    events = execution_events(build)
    prefix = "//tools/bazel/tests/fixture:"
    actions = {}
    for name, mnemonic in [
        ("generated", "AosPythonGenerate"),
        ("fixture_macro", "Rustc"),
        ("generated_library", "Rustc"),
        ("rust_library", "Rustc"),
        ("rust_app", "Rustc"),
        ("native_app", "Rustc"),
        ("cpp_library", "CppCompile"),
        ("cpp_app", "CppLink"),
    ]:
        actions[name] = require_action(events, prefix + name, mnemonic, hit=False)
        event = next(event for event in events if event["targetLabel"] == prefix + name
                     and event["mnemonic"] == mnemonic)
        if "sandbox" not in event["runner"]:
            raise ValueError(f"cross action did not execute in a sandbox: {name}")
        inputs = [entry["path"] for entry in event.get("inputs", [])]
        foreign_std = any("/rustlib/aarch64-unknown-linux-gnu/lib/libstd-" in path for path in inputs)
        if mnemonic == "Rustc" and foreign_std != (name != "fixture_macro"):
            raise ValueError(f"incorrect standard-library platform for {name}")
        if name == "fixture_macro" and not any("/rustlib/x86_64-unknown-linux-gnu/lib/libstd-" in path for path in inputs):
            raise ValueError("procedural macro omitted its native execution standard library")
        if name == "fixture_macro" and not any(path.endswith(".so") for path in event["listedOutputs"]):
            raise ValueError("execution-platform procedural macro omitted its shared library")
        if name == "generated" and not event["commandArgs"][0].endswith("/+aos_tools_repository+aos_tools/bin/python3"):
            raise ValueError("generator did not execute the declared native Python")
        if mnemonic in {"CppCompile", "CppLink"} and not any("/cross/closure.json" in path for path in inputs):
            raise ValueError(f"foreign C++ action omitted the target compiler closure: {name}")

    artifacts = package_files(build)
    expected = {"bin/rust-fixture": "answer=42", "bin/cpp-fixture": "answer=42", "bin/native-fixture": "answer=84"}
    if artifacts.keys() != expected.keys():
        raise ValueError("unexpected foreign package artifact inventory")
    results = {}
    for destination, path in artifacts.items():
        contents = path.read_bytes()
        if elf_machine(contents) != 183:
            raise ValueError(f"artifact does not target AArch64: {destination}")
        result = subprocess.run([str(qemu), str(path)], capture_output=True, text=True, timeout=60, check=True)
        if result.stdout.strip() != expected[destination]:
            raise ValueError(f"emulated foreign program produced incorrect output: {destination}: {result.stdout}")
        results[destination] = {"sha256": hashlib.sha256(contents).hexdigest(), "stdout": result.stdout}
    return {"schema_version": 1, "target": "aarch64-unknown-linux-gnu", "build": str(build),
            "actions": actions, "artifacts": results, "runtime_execution": "AOS source-built QEMU linux-user"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options.build, options.qemu), indent=2, sort_keys=True) + "\n")
