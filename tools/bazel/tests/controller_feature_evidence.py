"""Binds controller feature audit inputs to actual Bazel qualification results.

The resulting repository is a runtime input to the controller's structural
tests. It carries real compilation and policy reports, never replacement Cargo
manifests. Every compiled Crucible source must match the policy source tree.
"""

import argparse
import hashlib
import json
from pathlib import Path

from verify_crucible_feature_policy import FEATURE_LAYOUT
from verify_feature_powerset import validate_contract


PRODUCTION_PACKAGES = {
    "crucible-" + name for name in [
        "determinism", "test-support", "qemu-shmem", "qemu-protocol", "device",
        "engine", "session", "control-api", "daemon", "cli", "qemu-host", "qemu-plugin",
    ]
}
NEGATIVE_CONTROLS = {
    "default engine activates shared memory",
    "engine test support activates a dependency",
    "device no-default changes dependencies",
    "host test support loses engine forwarding",
    "compiled forwarded engine loses dependency defaults",
    "default engine acquires a transitive guest edge",
    "default engine enables test double",
}


def production_root(package):
    """Names the installed artifact or library selected by the policy gate."""
    target = "lib"
    if package == "crucible-cli":
        target = "crucible"
    elif package == "crucible-qemu-plugin":
        target = "plugin"
    return "//crates/crucible/" + package + ":" + target


def rust_sources(root):
    """Hashes the complete Crucible Rust tree used by each qualification."""
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((root / "crates/crucible").rglob("*.rs"))
    }


def validate_reports(policy, compilation, contract):
    """Rejects incomplete reports rather than treating their presence as success."""
    validate_contract(contract)
    if policy.get("schema_version") != 1 or compilation.get("schema_version") != 1:
        raise ValueError("unsupported feature qualification report")
    if policy.get("cargo_metadata_absent") is not True:
        raise ValueError("feature policy did not exclude Cargo metadata")

    for package, expected in FEATURE_LAYOUT.items():
        if set(policy["features"][package]["declared_features"]) != expected:
            raise ValueError("qualified feature layout differs: " + package)
    if set(policy.get("production_closures", {})) != PRODUCTION_PACKAGES:
        raise ValueError("missing qualified production feature closures")
    for name, closure in policy["production_closures"].items():
        if production_root(name) not in closure:
            raise ValueError("qualified production closure omits its root: " + name)
        if any(label.startswith("//crates/crucible/crucible-guest:") for label in closure):
            raise ValueError("qualified production closure contains a guest dependency")
    negatives = policy.get("rejected_negative_controls", [])
    if len(negatives) != len(NEGATIVE_CONTROLS) or set(negatives) != NEGATIVE_CONTROLS:
        raise ValueError("missing feature policy negative controls")

    cases = compilation["cases"]
    if set(cases) != {case["name"] for case in contract["cases"]}:
        raise ValueError("qualified feature cases differ from the contract")
    for case in contract["cases"]:
        actual = cases[case["name"]]
        if actual["features"] != sorted(case["expected_features"]):
            raise ValueError("qualified feature case differs: " + case["name"])
        action = actual["compilation"]
        if action["runner"] != "linux-sandbox" or action["cache_hit"]:
            raise ValueError("feature case lacks a fresh sandbox compilation")


def bundle(policy, compilation, contract, policy_root, compilation_root):
    """Rejects differing qualification source snapshots before binding reports."""
    validate_reports(policy, compilation, contract)
    sources = rust_sources(policy_root)
    compiled_sources = rust_sources(compilation_root)
    if not sources or not compiled_sources or any(
        sources.get(name) != digest for name, digest in compiled_sources.items()
    ):
        raise ValueError("feature qualification source trees differ")
    return {
        "schema_version": 1,
        "sources_sha256": sources,
        "policy": policy,
        "compilation": compilation,
        "contract": contract,
    }


def verify_bound_sources(evidence, root, expected_cases):
    """Requires the runtime Rust tree to match every qualified source exactly."""
    if evidence.get("schema_version") != 1:
        raise ValueError("unsupported bound feature evidence")
    validate_reports(evidence["policy"], evidence["compilation"], evidence["contract"])
    actual = {name: case["features"] for name, case in evidence["compilation"]["cases"].items()}
    if actual != expected_cases:
        raise ValueError("runtime feature cases differ from qualified compilations")
    if not evidence["sources_sha256"] or rust_sources(root) != evidence["sources_sha256"]:
        raise ValueError("runtime source tree differs from feature qualification")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    for name in ["policy", "compilation", "contract", "policy-root", "compilation-root", "output"]:
        prepare.add_argument("--" + name, required=True, type=Path)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--evidence", required=True, type=Path)
    verify.add_argument("--root", required=True, type=Path)
    verify.add_argument("--section", required=True, choices=["cases", "layout", "guest", "test-double"])
    verify.add_argument("--case", action="append", required=True)
    options = parser.parse_args()
    if options.command == "verify":
        cases = {}
        for value in options.case:
            name, separator, features = value.partition("=")
            if not name or not separator or name in cases:
                raise ValueError("invalid or duplicate runtime feature case")
            cases[name] = sorted(features.split(",")) if features else []
        verify_bound_sources(json.loads(options.evidence.read_text()), options.root, cases)
        return
    result = bundle(
        json.loads(options.policy.read_text()),
        json.loads(options.compilation.read_text()),
        json.loads(options.contract.read_text()),
        options.policy_root,
        options.compilation_root,
    )
    options.output.mkdir(parents=True, exist_ok=True)
    (options.output / "features.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    (options.output / "BUILD.bazel").write_text(
        'exports_files(["features.json"], visibility = ["//visibility:public"])\n'
    )
    (options.output / "REPO.bazel").touch()


if __name__ == "__main__":
    main()
