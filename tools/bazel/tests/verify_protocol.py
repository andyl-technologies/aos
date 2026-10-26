"""Compares Rust-family tests, doctests, and configured features with Cargo."""

import argparse
import json
from pathlib import Path
import re

from verify_pilot import cases, verify


PACKAGE_PATHS = {
    name: f"crates/crucible/{name}"
    for name in ["crucible-qemu-protocol", "crucible-qemu-shmem"]
}

RUST_LIBRARY_KINDS = {"lib", "rlib", "cdylib", "dylib", "staticlib", "proc-macro"}


def doctest_cases(log, package_path, generated_sources=None):
    """Normalizes rustdoc's source-relative case names without losing status."""
    def generated_source(source):
        for directory, destination in (generated_sources or {}).items():
            if source.startswith(directory + "/"):
                relative = source.removeprefix(directory + "/")
                if not relative or ".." in Path(relative).parts or Path(relative).is_absolute():
                    raise ValueError(f"invalid generated rustdoc source: {source}")
                return destination + "/" + relative
        return source

    cases = {}
    for match in re.finditer(r"^test (.+?) \.\.\. (ok|ignored(?:, [^\n]*)?|FAILED)$", log, re.MULTILINE):
        name, status = match.groups()
        source, separator, location = name.partition(" - ")
        if not separator or not re.fullmatch(r"(?:.+ )?\(line \d+\)(?: - compile(?: fail)?)?", location):
            raise ValueError(f"unrecognized rustdoc case: {name}")
        source = generated_source(source)
        for prefix in [package_path, package_path.removeprefix("crates/")]:
            marker = prefix + "/"
            if source.startswith(marker):
                source = source.removeprefix(marker)
                break
            if "/" + marker in source:
                # A rustdoc runfiles root can itself live under this package.
                source = source.rsplit("/" + marker, 1)[1]
                break
        source = generated_source(source)
        if not source.startswith(("src/", "tests/", "examples/")):
            raise ValueError(f"rustdoc case is outside the package: {name}")
        if ".." in Path(source).parts:
            raise ValueError(f"rustdoc case escapes the package: {name}")
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


def generated_doctest_sources(messages, inventory, package_paths, declarations):
    """Binds generated doc sources to Cargo events and declared Bazel producers."""
    cargo, bazel = {}, {}
    events = [json.loads(line) for line in messages.read_text().splitlines()]
    reports = json.loads(inventory.read_text())["configured_targets"]
    for name, directory in declarations.items():
        if name not in package_paths or not directory or "/" in directory or directory in {".", ".."}:
            raise ValueError("invalid generated doctest package or output directory")
        path = package_paths[name]
        output = path + "/" + directory
        producers = {report["generated_inputs"][output] for report in reports
                     if report["label"] == "//" + path + ":lib"
                     and output in report.get("generated_inputs", {})}
        if len(producers) != 1 or not next(iter(producers)).startswith("//" + path + ":"):
            raise ValueError("generated doctest directory has no unique package-local producer")
        package_ids = {event["package_id"] for event in events
                       if event.get("reason") == "compiler-artifact"
                       and Path(event["manifest_path"]).as_posix().endswith("/" + path + "/Cargo.toml")}
        if len(package_ids) != 1:
            raise ValueError("generated doctest package has no unique compiled Cargo identity")
        roots = {event["out_dir"] for event in events
                 if event.get("reason") == "build-script-executed"
                 and event["package_id"] in package_ids}
        if len(roots) != 1 or not Path(next(iter(roots))).is_absolute():
            raise ValueError("generated doctest directory has no unique Cargo build-script output")
        cargo[name] = {next(iter(roots)): "src/generated"}
        # rules_rust reports package-relative generated inputs; rustdoc prints
        # their configured execution paths. Package normalization retains this
        # exact output directory instead of accepting arbitrary generated files.
        bazel[name] = {directory: "src/generated"}
    return cargo, bazel


def compare_doctests(tests, cargo_log, package_paths, target_suffix="", package_target_suffixes=None, generated_sources=None):
    """Compares actual doctest names, locations, and ignored cases per package."""
    log = cargo_log.read_text()
    sections = re.split(r"^\s*Doc-tests ([a-zA-Z0-9_]+)\s*$", log, flags=re.MULTILINE)
    cargo = dict(zip(sections[1::2], sections[2::2]))
    results = json.loads((tests / "index.json").read_text())["results"]
    suffixes = package_target_suffixes or {}
    expected_labels = {"//" + path + ":doc" + suffixes.get(name, target_suffix)
                       for name, path in package_paths.items()}
    actual_labels = {result["identity"]["label"] for result in results
                     if re.search(r":doc(?:_|$)", result["identity"]["label"])}
    if actual_labels != expected_labels:
        raise ValueError(f"Bazel/Cargo doctest target inventories differ: {actual_labels ^ expected_labels}")
    compared = {}
    for name, path in package_paths.items():
        label = "//" + path + ":doc" + suffixes.get(name, target_suffix)
        selected = [result for result in results if result["identity"]["label"] == label]
        if len(selected) != 1 or selected[0]["status"] != "PASSED" or name.replace("-", "_") not in cargo:
            raise ValueError(f"missing successful Cargo/Bazel doctest target: {label}")
        cargo_sources, bazel_sources = generated_sources or ({}, {})
        expected = doctest_cases(cargo[name.replace("-", "_")], path, cargo_sources.get(name))
        actual = doctest_cases((tests / selected[0]["outputs"]["test.log"]).read_text(), path, bazel_sources.get(name))
        if actual != expected:
            raise ValueError(f"Rust doctest inventories differ for {label}: {actual!r} != {expected!r}")
        compared[label] = expected
    return compared


def compare_features(inventory, messages, first_party_paths, required_packages=()):
    """Compares compiled library feature units without requiring libtest targets."""
    cargo_features = {}
    cargo_first_party_features = {}
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
        else:
            cargo_features.setdefault((name, version), set()).add(tuple(sorted(event["features"])))

    reports = json.loads(inventory.read_text())["configured_targets"]
    bazel_first_party_features = {}
    package_labels = {"//" + path: name for name, path in first_party_paths.items()}
    for report in reports:
        name = package_labels.get(report["label"].split(":", 1)[0])
        if name and report["kind"] in {"rust_library", "rust_binary", "rust_test", "rust_proc_macro", "rust_shared_library"}:
            bazel_first_party_features.setdefault(name, set()).add(tuple(sorted(report["features"])))
    if bazel_first_party_features != cargo_first_party_features:
        raise ValueError(f"first-party Rust feature inventories differ: {bazel_first_party_features!r} != {cargo_first_party_features!r}")
    result = {}
    result["first_party_features"] = {
        name: sorted(features) for name, features in sorted(cargo_first_party_features.items())
    }
    bazel_features = {}
    for report in reports:
        match = re.search(r"aos_(?:accache|core|device|store|guest|engine|quota|session|control|qemu_host|qemu_gpl_production|qemu_gpl_tests|qemu_gpl_plugin_tests|qemu_test_oracle_host|store_s3|daemon|crucible_cli|aos_cli_(?:tests|fleet_tests|production)|cli_support|build_services|deployment|hub_portable|registry_web(?:_wasm)?|hub_console(?:_wasm)?|hub_native_(?:postgres|tests)|hub_worker_(?:tests|all_features_tests|wasm(?:_do_e2e|_all_features)?)|hub_service(?:_all_features)?(?:_tests)?|hub_db(?:_all_features)?(?:_tests)?|package_manager(?:_tests)?|configuration_image(?:_tests)?|configuration_files(?:_tests)?|systemd_provider|kernel_tunable(?:_tests)?|preparation_provider(?:_tests)?|boot_preparation(?:_minimal)?|release_coordination|registry_native(?:_tests)?|release_preparation|hub_client|hub_model(?:_tests)?|formats|native_bindings|native_foundation(?:_tests|_minimal)?|activation_(?:core(?:_tests)?|crucible(?:_tests)?|storage|systemd))_crates__([^/]+)//", report["label"])
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
    if set(required_packages) - cargo_first_party_features.keys():
        raise ValueError("Cargo omitted first-party packages from its compiler messages")
    return result


def compare(
    tests,
    inventory,
    messages,
    package_paths=None,
    cargo_log=None,
    target_suffix="",
    dependency_paths=None,
    allow_empty_tests=(),
    package_target_suffixes=None,
    generated_doctests=None,
):
    package_paths = PACKAGE_PATHS if package_paths is None else package_paths
    suffixes = package_target_suffixes or {}
    if set(suffixes) - package_paths.keys():
        raise ValueError("target suffix names an unselected package")
    first_party_paths = {**(dependency_paths or {}), **package_paths}
    oracles = {}
    empty_allowed = set()
    cargo_examples = set()
    cargo_libraries = set()
    for line in messages.read_text().splitlines():
        event = json.loads(line)
        if event.get("reason") != "compiler-artifact":
            continue
        identifier = event["package_id"].rsplit("#", 1)[-1]
        name, separator, version = identifier.rpartition("@")
        if not separator:
            name = Path(event["manifest_path"]).parent.name
            version = identifier
        if name in package_paths and "example" in event["target"]["kind"]:
            cargo_examples.add(f"//{package_paths[name]}:" + event["target"]["name"] + suffixes.get(name, target_suffix))
        library = bool(set(event["target"]["kind"]) & RUST_LIBRARY_KINDS)
        if name in package_paths and library:
            cargo_libraries.add(name)
        if (name in package_paths and event["profile"]["test"] and event.get("executable")
                and set(event["target"]["kind"]) & (RUST_LIBRARY_KINDS | {"test", "bin"})):
            target = event["target"]
            if library:
                suffix = "unit"
            elif "bin" in target["kind"]:
                suffix = "bin_" + target["name"]
            else:
                suffix = target["name"]
            label = f"//{package_paths[name]}:{suffix}{suffixes.get(name, target_suffix)}"
            if label in oracles:
                raise ValueError(f"duplicate Cargo test artifact: {label}")
            oracles[label] = Path(event["executable"])
            if "bin" in target["kind"]:
                empty_allowed.add(label)

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
        if not re.search(r":doc(?:_|$)", event["identity"]["label"])
    }
    if not oracles or executed_labels != set(oracles):
        raise ValueError(f"Bazel/Cargo integration target inventories differ: {executed_labels ^ set(oracles)}")

    result.update(compare_features(
        inventory, messages, first_party_paths,
        required_packages=package_paths if cargo_log is not None else (),
    ))
    reports = json.loads(inventory.read_text())["configured_targets"]
    bazel_examples = {
        report["label"] for report in reports
        if report["kind"] == "rust_binary"
        and report["label"].split(":", 1)[0] in {"//" + path for path in package_paths.values()}
        and any("/examples/" in source for source in report["sources"])
    }
    if cargo_examples != bazel_examples:
        raise ValueError(f"Bazel/Cargo example inventories differ: {cargo_examples ^ bazel_examples}")
    result["examples"] = sorted(cargo_examples)

    if cargo_log is not None:
        # Binary-only packages have libtests but no Cargo library doctest target.
        libraries = {name: path for name, path in package_paths.items() if name in cargo_libraries}
        generated = generated_doctest_sources(messages, inventory, libraries, generated_doctests or {})
        result["doctests"] = compare_doctests(tests, cargo_log, libraries, target_suffix, suffixes, generated)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tests", type=Path)
    parser.add_argument("--features-only", action="store_true")
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--messages", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--package-path", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument("--dependency-package-path", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument("--cargo-log", type=Path)
    parser.add_argument("--target-suffix", default="")
    parser.add_argument("--package-target-suffix", action="append", default=[], metavar="NAME=SUFFIX")
    parser.add_argument("--allow-empty-test", action="append", default=[], metavar="LABEL")
    parser.add_argument("--generated-doctest", action="append", default=[], metavar="NAME=OUTPUT_DIRECTORY")
    options = parser.parse_args()
    package_paths = dict(value.split("=", 1) for value in options.package_path) if options.package_path else None
    dependencies = dict(value.split("=", 1) for value in options.dependency_package_path)
    if options.features_only:
        if options.tests or options.cargo_log or not package_paths:
            parser.error("feature-only comparison requires package paths and no test inputs")
        result = compare_features(
            options.inventory, options.messages, {**dependencies, **package_paths},
            required_packages=package_paths,
        )
    else:
        if options.tests is None:
            parser.error("test comparison requires --tests")
        result = compare(
            options.tests,
            options.inventory,
            options.messages,
            package_paths=package_paths,
            cargo_log=options.cargo_log,
            target_suffix=options.target_suffix,
            package_target_suffixes=dict(value.split("=", 1) for value in options.package_target_suffix),
            dependency_paths=dependencies,
            allow_empty_tests=options.allow_empty_test,
            generated_doctests=dict(value.split("=", 1) for value in options.generated_doctest),
        )
    options.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
