"""Checks that foreign Rust outputs retain native execution tools and inputs."""

import argparse
import hashlib
import json
from pathlib import Path

from verify_cache import execution_events, require_action


def verify(build):
    events = execution_events(build)
    prefix = "//tools/bazel/tests/fixture:"
    actions = {}
    for name, mnemonic in [
        ("generated", "AosPythonGenerate"),
        ("fixture_macro", "Rustc"),
        ("generated_library", "Rustc"),
        ("rust_library", "Rustc"),
        ("wasm_app", "Rustc"),
    ]:
        actions[name] = require_action(events, prefix + name, mnemonic, hit=False)
        event = next(event for event in events if event["targetLabel"] == prefix + name
                     and event["mnemonic"] == mnemonic)
        if "sandbox" not in event["runner"]:
            raise ValueError(f"foreign graph action did not execute in a sandbox: {name}")
        inputs = [entry["path"] for entry in event.get("inputs", [])]
        wasm_standard_library = any("/rustlib/wasm32-unknown-unknown/lib/libstd-" in path for path in inputs)
        if mnemonic == "Rustc" and wasm_standard_library != (name != "fixture_macro"):
            raise ValueError(f"incorrect standard-library platform for {name}")
        if name == "fixture_macro" and not any(path.endswith(".so") for path in event["listedOutputs"]):
            raise ValueError("procedural macro did not produce a native shared library")
        if name == "wasm_app" and not any(path.endswith("/bin/rust-lld") for path in inputs):
            raise ValueError("WASM link omitted the declared source-built linker")

    if any(event["mnemonic"] in {"CppCompile", "CppLink"} for event in events):
        raise ValueError("pure Rust WASM graph unexpectedly selected a C/C++ compiler")
    index = json.loads((build / "packages/index.json").read_text())
    package = build / "packages" / index[prefix + "wasm_package"]
    manifest = json.loads((package / "manifest.json").read_text())
    if [entry["destination"] for entry in manifest["artifacts"]] != ["share/fixture.wasm"]:
        raise ValueError("unexpected foreign package artifact inventory")
    artifact = package / "files/share/fixture.wasm"
    contents = artifact.read_bytes()
    if contents[:8] != b"\x00asm\x01\x00\x00\x00" or len(contents) <= 8:
        raise ValueError("foreign artifact is not a WebAssembly version 1 module")
    return {
        "schema_version": 1,
        "build": str(build),
        "target": "wasm32-unknown-unknown",
        "actions": actions,
        "artifact_sha256": hashlib.sha256(contents).hexdigest(),
        "artifact_bytes": len(contents),
        "runtime_execution": "not qualified by this toolchain check",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options.build), indent=2, sort_keys=True) + "\n")
