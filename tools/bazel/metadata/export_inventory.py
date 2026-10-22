"""Turns configured aspect reports into a pure Nix source selection contract.

Source bytes remain live inputs. BUILD/Starlark/module bytes are hashed so a
changed graph cannot silently use stale selection. Source directories permit
new Rust/C/C++ implementation files without requiring evaluation-time builds.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlparse


def reports_from_events(events):
    reports = set()
    for event in events:
        for item in event.get("namedSetOfFiles", {}).get("files", []):
            if item.get("name", "").endswith(".aos-target.json"):
                uri = urlparse(item["uri"])
                if uri.scheme != "file" or uri.netloc:
                    raise ValueError("source inventory requires local aspect reports")
                reports.add(Path(unquote(uri.path)))
    return [json.loads(report.read_text()) for report in sorted(reports)]


def inventory(root, targets, reports):
    contracts = {"MODULE.bazel", "MODULE.bazel.lock"}
    sources = set()
    directories = set()
    labels = {report["label"] for report in reports}
    if not set(targets) <= labels:
        raise ValueError("configured inventory omitted a requested target")
    for report in reports:
        if report["schema_version"] != 1:
            raise ValueError("unsupported configured inventory schema")
        if not report.get("external", False):
            contracts.add(report["build_file"])
        for filename in report["sources"]:
            path = PurePosixPath(filename)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"non-workspace source: {filename}")
            sources.add(filename)
            # Retain discovery roots rather than freezing a glob's file list.
            # This includes new implementation files in an owned src/tests tree.
            for index, part in enumerate(path.parts[:-1]):
                if part in {"src", "tests", "benches"} and path.parts[0] in {"crates", "native"}:
                    directories.add(PurePosixPath(*path.parts[:index + 1]).as_posix())
                    break
    # Shared policy is a deliberately small declaration set. It is never a
    # hash of the whole checkout or of implementation bytes.
    for name in ["rules", "toolchains", "metadata"]:
        for path in (root / "tools/bazel" / name).rglob("*"):
            if path.name.endswith((".bzl", ".bazel")):
                contracts.add(path.relative_to(root).as_posix())
    return {
        "schema_version": 1,
        "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "targets": sorted(targets),
        "source_files": sorted(sources),
        "source_directories": sorted(directories),
        "contracts": {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sorted(contracts)},
        "configured_targets": sorted(reports, key=lambda report: (report["label"], report["target_cpu"])),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--targets", nargs="+", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-lock", type=Path)
    options = parser.parse_args()
    events = [json.loads(line) for line in options.events.read_text().splitlines() if line]
    result = inventory(options.root, options.targets, reports_from_events(events))
    if options.source_lock:
        result["contracts"]["MODULE.bazel.lock"] = hashlib.sha256(options.source_lock.read_bytes()).hexdigest()
    options.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
