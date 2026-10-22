"""Checks semantic cache invalidation against a separately built baseline."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from verify_cache import execution_events, package_files, require_action


def verify(baseline, variants):
    baseline_events = execution_events(baseline)
    # Expected misses follow dependency edges, including both native and Rust
    # consumers of the generator. Unrelated actions must remain cache hits.
    changed = {
        "header": {"cpp_library", "cpp_app", "cpp_link", "native_app"},
        "cpp-source": {"cpp_library", "cpp_link", "native_app"},
        "rust-source": {"rust_library", "rust_app", "native_app"},
        "generated-input": {"generated", "generated_library", "rust_library", "rust_app", "cpp_library", "cpp_app", "cpp_link", "native_app"},
        "generator-environment": {"generated", "generated_library", "rust_library", "rust_app", "cpp_library", "cpp_app", "cpp_link", "native_app"},
        "feature": {"rust_library", "rust_app", "native_app"},
        "rust-flags": {"rust_library", "rust_app", "native_app"},
        "link-flags": {"cpp_link"},
        "tool-closure": {"generated", "generated_library", "rust_library", "rust_app", "fixture_macro", "cpp_library", "cpp_app", "cpp_link", "native_app"},
    }
    actions = {
        "generated": "AosPythonGenerate", "generated_library": "Rustc",
        "rust_library": "Rustc", "rust_app": "Rustc", "fixture_macro": "Rustc",
        "cpp_library": "CppCompile", "cpp_app": "CppCompile", "native_app": "Rustc",
        "cpp_link": "CppLink",
    }
    expected_values = {
        "header": (42, 43, 85), "cpp-source": (42, 43, 85),
        "rust-source": (43, 42, 85), "generated-input": (43, 43, 86),
        "generator-environment": (43, 43, 86), "feature": (43, 42, 85),
        "rust-flags": (42, 42, 84), "tool-closure": (42, 42, 84),
        "link-flags": (42, 42, 84),
    }
    evidence = {"schema_version": 1, "baseline": str(baseline), "variants": {}}
    for variant, build in variants.items():
        events = execution_events(build)
        results = {}
        for target, mnemonic in actions.items():
            label = "//tools/bazel/tests/fixture:" + ("cpp_app" if target == "cpp_link" else target)
            original = require_action(baseline_events, label, mnemonic, hit=False)
            result = require_action(events, label, mnemonic, hit=target not in changed[variant])
            same_identity = result["fingerprint"] == original["fingerprint"]
            if same_identity != (target not in changed[variant]):
                raise ValueError(f"unexpected semantic identity for {variant}: {target}")
            if original["action_digest"] is None or result["action_digest"] is None:
                raise ValueError(f"invalidation experiment omitted an action digest: {variant}: {target}")
            if (original["action_digest"] == result["action_digest"]) != same_identity:
                raise ValueError(f"unexpected Bazel action digest for {variant}: {target}")
            results[target] = result
        artifacts = package_files(build)
        digests = {}
        for destination, value in zip(["bin/rust-fixture", "bin/cpp-fixture", "bin/native-fixture"], expected_values[variant]):
            executable = artifacts[destination]
            result = subprocess.run([str(executable)], capture_output=True, text=True, check=True)
            if result.stdout.strip() != f"answer={value}":
                raise ValueError(f"incorrect {variant} runtime output: {destination}: {result.stdout}")
            digests[destination] = hashlib.sha256(executable.read_bytes()).hexdigest()
        evidence["variants"][variant] = {"build": str(build), "actions": results, "artifacts": digests}
    return evidence


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--variants", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    variants = {name: Path(path) for name, path in json.loads(options.variants.read_text()).items()}
    result = verify(options.baseline, variants)
    options.output.mkdir(parents=True, exist_ok=True)
    (options.output / "evidence.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
