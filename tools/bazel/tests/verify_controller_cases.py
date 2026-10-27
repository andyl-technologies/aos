"""Compares compiled controller test discovery without qualifying execution.

Cargo compiler messages bind Nextest suites to package-owned source roots.
Configured Bazel reports bind the same roots to the listed test binaries.
No target-name convention or count alone establishes case equivalence.
"""

import argparse
import json
from pathlib import Path, PurePosixPath


def cargo_artifacts(messages):
    """Indexes test executables by their compiler-declared package and source."""
    artifacts = {}
    identities = set()
    for event in messages:
        if (event.get("reason") != "compiler-artifact"
                or not event.get("profile", {}).get("test")
                or not event.get("executable")):
            continue
        target = event["target"]
        kinds = target["kind"]
        if len(kinds) != 1 or kinds[0] not in {"lib", "test", "bin"}:
            raise ValueError("unsupported Cargo controller test kind: " + repr(kinds))
        manifest = PurePosixPath(event["manifest_path"])
        source = PurePosixPath(target["src_path"])
        if not manifest.is_absolute() or manifest.name != "Cargo.toml" or not source.is_absolute():
            raise ValueError("Cargo test omitted its absolute package source identity")
        relative = source.relative_to(manifest.parent)
        if ".." in relative.parts:
            raise ValueError("Cargo test source escapes its package")
        executable = event["executable"]
        identity = (event["package_id"], relative.as_posix())
        if executable in artifacts or identity in identities:
            raise ValueError("duplicate Cargo test executable or source identity")
        identities.add(identity)
        artifacts[executable] = {
            "package_id": event["package_id"],
            "package_directory": manifest.parent.name,
            "source": relative.as_posix(),
            "kind": kinds[0],
            "name": target["name"],
        }
    if not artifacts:
        raise ValueError("Cargo compiler messages contain no test executables")
    return artifacts


def compare_cases(inventory, discovery, messages, nextest):
    """Requires exact binary, case, and ignored-case correspondence."""
    if inventory.get("schema_version") != 1 or discovery.get("schema_version") != 1:
        raise ValueError("unsupported controller inventory or discovery schema")
    if discovery.get("test_execution_qualified") is not False or not discovery.get("targets"):
        raise ValueError("controller discovery must explicitly remain unqualified for execution")

    compiled = cargo_artifacts(messages)
    bazel = {}
    for report in inventory["configured_targets"]:
        label = report["label"]
        if label not in discovery["targets"]:
            continue
        package = report.get("rustc_env", {}).get("CARGO_PKG_NAME")
        directory = label.split(":", 1)[0].removeprefix("//")
        source = PurePosixPath(report["crate_root"]).relative_to(directory).as_posix()
        identity = (package, source)
        if not package or label in bazel.values() or identity in bazel:
            raise ValueError("ambiguous Bazel controller test source identity: " + label)
        bazel[identity] = label
    if set(bazel.values()) != set(discovery["targets"]):
        raise ValueError("Bazel configured reports omit discovered test binaries")

    seen = set()
    result = {}
    count = 0
    for suite_id, suite in nextest["rust-suites"].items():
        executable = suite["binary-path"]
        if executable not in compiled or executable in seen:
            raise ValueError("unknown or duplicate Nextest compiler artifact: " + executable)
        artifact = compiled[executable]
        if (suite_id != suite["binary-id"] or suite["package-id"] != artifact["package_id"]
                or suite["package-name"] != artifact["package_directory"]
                or suite["kind"] != artifact["kind"] or suite["binary-name"] != artifact["name"]
                or suite["status"] != "listed" or suite["build-platform"] != "target"):
            raise ValueError("Nextest suite identity or listing status differs: " + suite_id)
        seen.add(executable)
        identity = (suite["package-name"], artifact["source"])
        if identity not in bazel:
            raise ValueError("Cargo test source has no Bazel binary: " + repr(identity))
        label = bazel[identity]
        if label in result:
            raise ValueError("multiple Cargo suites map to one Bazel binary: " + label)

        cases = sorted(suite["testcases"])
        ignored = []
        for name, case in suite["testcases"].items():
            if not isinstance(case["ignored"], bool) or case["kind"] != "test":
                raise ValueError("unsupported Nextest case kind or ignore status: " + name)
            expected_filter = {"status": "mismatch", "reason": "ignored"} if case["ignored"] else {"status": "matches"}
            if case["filter-match"] != expected_filter:
                raise ValueError("Nextest unexpectedly filters a controller case: " + name)
            if case["ignored"]:
                ignored.append(name)
        actual = discovery["targets"][label]
        if cases != sorted(actual["cases"]) or sorted(ignored) != sorted(actual["ignored"]):
            raise ValueError("Cargo/Bazel controller cases or ignored cases differ: " + label)
        if len(actual["cases"]) != len(set(actual["cases"])) or len(actual["ignored"]) != len(set(actual["ignored"])):
            raise ValueError("Bazel discovery contains duplicate cases: " + label)
        count += len(cases)
        result[label] = {"cases": cases, "ignored": sorted(ignored), "cargo_suite": suite_id}

    if seen != set(compiled) or set(result) != set(discovery["targets"]):
        raise ValueError("Cargo, Nextest, and Bazel controller binary inventories differ")
    if count != nextest["test-count"]:
        raise ValueError("Nextest summary differs from its complete case inventory")
    return {"schema_version": 1, "test_execution_qualified": False, "targets": dict(sorted(result.items()))}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--discovery", type=Path, required=True)
    parser.add_argument("--messages", type=Path, required=True)
    parser.add_argument("--nextest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    result = compare_cases(
        json.loads(options.inventory.read_text()),
        json.loads(options.discovery.read_text()),
        [json.loads(line) for line in options.messages.read_text().splitlines()],
        json.loads(options.nextest.read_text()),
    )
    options.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
