"""Compares protocol test discovery and resolved crate features with Cargo."""

import argparse
import json
from pathlib import Path
import re

from verify_pilot import verify


PACKAGES = {"crucible-qemu-protocol", "crucible-qemu-shmem"}


def compare(tests, inventory, messages):
    oracles = {}
    cargo_features = {}
    cargo_examples = set()
    for line in messages.read_text().splitlines():
        event = json.loads(line)
        if event.get("reason") != "compiler-artifact":
            continue
        identifier = event["package_id"].rsplit("#", 1)[-1]
        name, separator, version = identifier.rpartition("@")
        if not separator:
            name = Path(event["manifest_path"]).parent.name
            version = identifier
        if name in PACKAGES and "example" in event["target"]["kind"]:
            cargo_examples.add(f"//crates/crucible/protocol/{name}:" + event["target"]["name"])
        if (name in PACKAGES and event["profile"]["test"] and event.get("executable")
                and set(event["target"]["kind"]) & {"lib", "test"}):
            target = event["target"]
            suffix = "unit" if "lib" in target["kind"] else target["name"]
            label = f"//crates/crucible/protocol/{name}:{suffix}"
            if label in oracles:
                raise ValueError(f"duplicate Cargo test artifact: {label}")
            oracles[label] = Path(event["executable"])
        elif name not in PACKAGES:
            cargo_features.setdefault((name, version), set()).add(tuple(sorted(event["features"])))

    # Listing the Cargo binaries checks ignored cases as well as executed cases.
    result = verify(tests, oracles)
    executed_labels = {
        event["identity"]["label"]
        for event in json.loads((tests / "index.json").read_text())["results"]
        if not event["identity"]["label"].endswith(":doc")
    }
    if not oracles or executed_labels != set(oracles):
        raise ValueError(f"Bazel/Cargo integration target inventories differ: {executed_labels ^ set(oracles)}")

    reports = json.loads(inventory.read_text())["configured_targets"]
    bazel_examples = {
        report["label"] for report in reports
        if report["kind"] == "rust_binary"
        and report["label"].startswith("//crates/crucible/protocol/")
        and any("/examples/" in source for source in report["sources"])
    }
    if cargo_examples != bazel_examples:
        raise ValueError(f"Bazel/Cargo example inventories differ: {cargo_examples ^ bazel_examples}")
    result["examples"] = sorted(cargo_examples)

    bazel_features = {}
    for report in reports:
        match = re.search(r"aos_core_crates__(.+)-(\d[^/]*)//", report["label"])
        if match and report["kind"] in {"rust_library", "rust_proc_macro"}:
            bazel_features.setdefault(match.groups(), set()).add(tuple(sorted(report["features"])))
    if bazel_features != cargo_features:
        differences = {
            f"{name}@{version}": {
                "cargo": sorted(cargo_features.get((name, version), set())),
                "bazel": sorted(bazel_features.get((name, version), set())),
            }
            for name, version in sorted(set(cargo_features) | set(bazel_features))
            if cargo_features.get((name, version)) != bazel_features.get((name, version))
        }
        raise ValueError("resolved Rust feature inventories differ: " + json.dumps(differences, indent=2))
    result["features"] = {
        f"{name}@{version}": sorted(features)
        for (name, version), features in sorted(cargo_features.items())
    }
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--messages", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    options.output.write_text(json.dumps(compare(options.tests, options.inventory, options.messages), indent=2, sort_keys=True) + "\n")
