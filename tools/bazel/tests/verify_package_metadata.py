"""Compares declared Bazel package identity with the temporary Cargo oracle."""

import argparse
import json
from pathlib import Path
import tomllib


def expected_metadata(package, workspace):
    """Resolves Cargo's inherited package fields without invoking Cargo."""
    package = {
        key: workspace[key] if isinstance(value, dict) and value.get("workspace") else value
        for key, value in package.items()
    }
    version = package["version"]
    release = version.split("+", 1)[0].split("-", 1)
    major, minor, patch = release[0].split(".")
    environment = {
        "CARGO_PKG_NAME": package["name"],
        "CARGO_PKG_VERSION": version,
        "CARGO_PKG_VERSION_MAJOR": major,
        "CARGO_PKG_VERSION_MINOR": minor,
        "CARGO_PKG_VERSION_PATCH": patch,
        "CARGO_PKG_VERSION_PRE": release[1] if len(release) == 2 else "",
        "CARGO_PKG_AUTHORS": ":".join(package.get("authors", [])),
        "CARGO_PKG_LICENSE": package.get("license", ""),
    }
    for field in ["description", "homepage", "repository", "license-file", "readme", "rust-version"]:
        value = package.get(field, "")
        if not isinstance(value, str):
            raise ValueError(f"unsupported Cargo package metadata {field}: {value!r}")
        environment["CARGO_PKG_" + field.upper().replace("-", "_")] = value
    return package.get("edition", "2015"), environment


def verify(root, inventories):
    workspace = tomllib.loads((root / "crates/Cargo.toml").read_text())["workspace"]["package"]
    checked = {}
    for inventory in inventories:
        for target in inventory["configured_targets"]:
            label = target["label"]
            if not label.startswith("//crates/") or target["kind"] not in {
                "rust_library", "rust_binary", "rust_proc_macro", "rust_test",
            }:
                continue
            directory = root / label[2:].split(":", 1)[0]
            manifest = tomllib.loads((directory / "Cargo.toml").read_text())["package"]
            edition, expected = expected_metadata(manifest, workspace)
            actual = {key: target["rustc_env"].get(key) for key in expected}
            if actual != expected or target["version"] != expected["CARGO_PKG_VERSION"] or target["edition"] != edition:
                raise ValueError(f"Bazel package identity differs from Cargo for {label}: {actual!r} != {expected!r}")
            checked[label] = {"edition": edition, "environment": expected}
    if not checked:
        raise ValueError("package metadata oracle did not compare any Rust targets")
    return {"schema_version": 1, "targets": dict(sorted(checked.items()))}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    result = verify(options.root, [json.loads(path.read_text()) for path in options.inventory])
    options.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
