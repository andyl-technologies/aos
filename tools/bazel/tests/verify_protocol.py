"""Compares Rust-family tests, doctests, and configured features with Cargo."""

import argparse
import json
from pathlib import Path
import re

from verify_pilot import cases, verify


PACKAGE_PATHS = {
    name: f"crates/crucible/protocol/{name}"
    for name in ["crucible-qemu-protocol", "crucible-qemu-shmem"]
}


def doctest_cases(log, package_path):
    """Normalizes rustdoc's source-relative case names without losing status."""
    cases = {}
    for match in re.finditer(r"^test (.+?) \.\.\. (ok|ignored(?:, [^\n]*)?|FAILED)$", log, re.MULTILINE):
        name, status = match.groups()
        source, separator, location = name.partition(" - ")
        if not separator or not re.fullmatch(r"(?:.+ )?\(line \d+\)(?: - compile(?: fail)?)?", location):
            raise ValueError(f"unrecognized rustdoc case: {name}")
        for prefix in [package_path, package_path.removeprefix("crates/")]:
            marker = prefix + "/"
            if source.startswith(marker):
                source = source.removeprefix(marker)
                break
            if "/" + marker in source:
                source = source.split("/" + marker, 1)[1]
                break
        if not source.startswith(("src/", "tests/", "examples/")):
            raise ValueError(f"rustdoc case is outside the package: {name}")
        key = source + " - " + location
        if key in cases:
            raise ValueError(f"duplicate rustdoc case: {key}")
        cases[key] = "ignored" if status.startswith("ignored") else status
    summaries = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", log)
    counts = {status: sum(case == status for case in cases.values()) for status in ["ok", "FAILED", "ignored"]}
    expected = [sum(int(summary[index]) for summary in summaries) for index in range(3)]
    if not summaries or expected != [counts[status] for status in ["ok", "FAILED", "ignored"]]:
        raise ValueError("rustdoc summaries do not match discovered cases")
    return dict(sorted(cases.items()))


def compare_doctests(tests, cargo_log, package_paths, target_suffix=""):
    """Compares actual doctest names, locations, and ignored cases per package."""
    log = cargo_log.read_text()
    sections = re.split(r"^\s*Doc-tests ([a-zA-Z0-9_]+)\s*$", log, flags=re.MULTILINE)
    cargo = dict(zip(sections[1::2], sections[2::2]))
    results = json.loads((tests / "index.json").read_text())["results"]
    compared = {}
    for name, path in package_paths.items():
        label = "//" + path + ":doc" + target_suffix
        selected = [result for result in results if result["identity"]["label"] == label]
        if len(selected) != 1 or selected[0]["status"] != "PASSED" or name.replace("-", "_") not in cargo:
            raise ValueError(f"missing successful Cargo/Bazel doctest target: {label}")
        expected = doctest_cases(cargo[name.replace("-", "_")], path)
        actual = doctest_cases((tests / selected[0]["outputs"]["test.log"]).read_text(), path)
        if actual != expected:
            raise ValueError(f"Rust doctest inventories differ for {label}: {actual!r} != {expected!r}")
        compared[label] = expected
    return compared


def compare(
    tests,
    inventory,
    messages,
    package_paths=None,
    cargo_log=None,
    target_suffix="",
    dependency_paths=None,
    allow_empty_tests=(),
):
    package_paths = PACKAGE_PATHS if package_paths is None else package_paths
    first_party_paths = {**(dependency_paths or {}), **package_paths}
    oracles = {}
    empty_allowed = set()
    cargo_features = {}
    cargo_first_party_features = {}
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
        if name in first_party_paths:
            cargo_first_party_features.setdefault(name, set()).add(tuple(sorted(event["features"])))
        if name in package_paths and "example" in event["target"]["kind"]:
            cargo_examples.add(f"//{package_paths[name]}:" + event["target"]["name"] + target_suffix)
        if (name in package_paths and event["profile"]["test"] and event.get("executable")
                and set(event["target"]["kind"]) & {"lib", "test", "bin"}):
            target = event["target"]
            if "lib" in target["kind"]:
                suffix = "unit"
            elif "bin" in target["kind"]:
                suffix = "bin_" + target["name"]
            else:
                suffix = target["name"]
            label = f"//{package_paths[name]}:{suffix}{target_suffix}"
            if label in oracles:
                raise ValueError(f"duplicate Cargo test artifact: {label}")
            oracles[label] = Path(event["executable"])
            if "bin" in target["kind"]:
                empty_allowed.add(label)
        elif name not in first_party_paths:
            cargo_features.setdefault((name, version), set()).add(tuple(sorted(event["features"])))

    # Listing the Cargo binaries checks ignored cases as well as executed cases.
    for label in allow_empty_tests:
        if label not in oracles:
            raise ValueError(f"empty-test exception has no Cargo artifact: {label}")
        if cases(oracles[label]):
            raise ValueError(f"empty-test exception has nonempty Cargo cases: {label}")
        empty_allowed.add(label)
    result = verify(tests, oracles, allow_empty=empty_allowed)
    executed_labels = {
        event["identity"]["label"]
        for event in json.loads((tests / "index.json").read_text())["results"]
        if not event["identity"]["label"].endswith(":doc" + target_suffix)
    }
    if not oracles or executed_labels != set(oracles):
        raise ValueError(f"Bazel/Cargo integration target inventories differ: {executed_labels ^ set(oracles)}")

    reports = json.loads(inventory.read_text())["configured_targets"]
    bazel_first_party_features = {}
    package_labels = {"//" + path: name for name, path in first_party_paths.items()}
    for report in reports:
        name = package_labels.get(report["label"].split(":", 1)[0])
        if name and report["kind"] in {"rust_library", "rust_binary", "rust_test", "rust_proc_macro"}:
            bazel_first_party_features.setdefault(name, set()).add(tuple(sorted(report["features"])))
    if bazel_first_party_features != cargo_first_party_features:
        raise ValueError(f"first-party Rust feature inventories differ: {bazel_first_party_features!r} != {cargo_first_party_features!r}")
    result["first_party_features"] = {
        name: sorted(features) for name, features in sorted(cargo_first_party_features.items())
    }
    bazel_examples = {
        report["label"] for report in reports
        if report["kind"] == "rust_binary"
        and report["label"].split(":", 1)[0] in {"//" + path for path in package_paths.values()}
        and any("/examples/" in source for source in report["sources"])
    }
    if cargo_examples != bazel_examples:
        raise ValueError(f"Bazel/Cargo example inventories differ: {cargo_examples ^ bazel_examples}")
    result["examples"] = sorted(cargo_examples)

    bazel_features = {}
    for report in reports:
        match = re.search(r"aos_(?:core|device|store|guest|engine|quota|session|control|qemu_host)_crates__([^/]+)//", report["label"])
        if match and report["kind"] in {"rust_library", "rust_proc_macro"}:
            # Repository names normalize SemVer build metadata. Compare the
            # declared package identity instead of trying to reverse that loss.
            names = [tag.removeprefix("crate-name=") for tag in report.get("tags", []) if tag.startswith("crate-name=")]
            version = report.get("version")
            if len(names) != 1 or not version or match[1] != (names[0] + "-" + version).replace("+", "-"):
                raise ValueError("external Rust target omitted its exact package identity: " + report["label"])
            bazel_features.setdefault((names[0], version), set()).add(tuple(sorted(report["features"])))
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
    if cargo_log is not None:
        result["doctests"] = compare_doctests(tests, cargo_log, package_paths, target_suffix)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--messages", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--package-path", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument("--dependency-package-path", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument("--cargo-log", type=Path)
    parser.add_argument("--target-suffix", default="")
    parser.add_argument("--allow-empty-test", action="append", default=[], metavar="LABEL")
    options = parser.parse_args()
    package_paths = dict(value.split("=", 1) for value in options.package_path) if options.package_path else None
    dependencies = dict(value.split("=", 1) for value in options.dependency_package_path)
    result = compare(
        options.tests,
        options.inventory,
        options.messages,
        package_paths=package_paths,
        cargo_log=options.cargo_log,
        target_suffix=options.target_suffix,
        dependency_paths=dependencies,
        allow_empty_tests=options.allow_empty_test,
    )
    options.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
