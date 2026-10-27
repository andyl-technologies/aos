"""Turns configured aspect reports into a pure Nix source selection contract.

Source bytes remain live inputs. BUILD/Starlark/module bytes are hashed so a
changed graph cannot silently use stale selection. Source directories permit
new Rust/C/C++ implementation files without requiring evaluation-time builds.
"""

import argparse
import ast
import hashlib
import io
import json
import re
from pathlib import Path, PurePosixPath
import tokenize
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


def owning_build(root, path):
    """Finds the package that owns a checked-in file, including subdirectories."""
    for directory in PurePosixPath(path).parents:
        for name in ["BUILD.bazel", "BUILD"]:
            candidate = directory / name
            if (root / candidate).is_file():
                return candidate
    raise ValueError("local Starlark input has no owning BUILD file: " + path)


def local_loads(root, filename):
    """Reads literal imports without interpreting comments or example strings."""
    tokens = [token for token in tokenize.generate_tokens(io.StringIO((root / filename).read_text()).readline)
              if token.type not in {tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE}]
    for index, token in enumerate(tokens[:-2]):
        if (token.type != tokenize.NAME or token.string != "load" or token.start[1] != 0
                or tokens[index + 1].string != "(" or tokens[index + 2].type != tokenize.STRING):
            continue
        label = ast.literal_eval(tokens[index + 2].string)
        if not isinstance(label, str):
            raise ValueError("Starlark load requires a string label: " + filename)
        if label.startswith("@"):
            continue
        if label.startswith("//"):
            package, separator, name = label[2:].partition(":")
            if not separator:
                package, separator, name = label[2:].rpartition("/")
            path = PurePosixPath(package, name)
        else:
            package = owning_build(root, filename).parent
            path = package / label.removeprefix(":")
        if path.is_absolute() or ".." in path.parts or not path.name.endswith(".bzl"):
            raise ValueError("invalid local Starlark load: " + label)
        if not (root / path).is_file():
            raise ValueError("missing local Starlark load: " + path.as_posix())
        yield path.as_posix()


def declaration_closure(root, contracts):
    """Includes local loads needed when shared declarations gain new imports."""
    contracts = set(contracts)
    pending = list(contracts)
    while pending:
        filename = pending.pop()
        if not filename.endswith((".bzl", ".bazel")) and PurePosixPath(filename).name != "BUILD":
            continue
        for loaded in local_loads(root, filename):
            for name in [loaded, owning_build(root, loaded).as_posix()]:
                if name not in contracts:
                    contracts.add(name)
                    pending.append(name)
    return contracts


def inventory(root, targets, reports, declarations=()):
    contracts = {"MODULE.bazel", "MODULE.bazel.lock", *declarations}
    pending_modules = ["MODULE.bazel"]
    while pending_modules:
        filename = pending_modules.pop()
        for label in re.findall(r'include\("(//[^"\n]+)"\)', (root / filename).read_text()):
            package, name = label[2:].split(":", 1)
            included = PurePosixPath(package, name)
            if included.is_absolute() or ".." in included.parts or not name.endswith(".MODULE.bazel"):
                raise ValueError(f"invalid module include: {label}")
            path = included.as_posix()
            if path not in contracts:
                contracts.add(path)
                pending_modules.append(path)
            for build_name in ["BUILD.bazel", "BUILD"]:
                build = PurePosixPath(package, build_name).as_posix()
                if (root / build).is_file():
                    contracts.add(build)
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
            # Source-file labels still require their owning BUILD package,
            # even when that package contains only exports_files declarations.
            for directory in path.parents:
                build_files = [directory / name for name in ["BUILD.bazel", "BUILD"]]
                owned = [candidate.as_posix() for candidate in build_files if (root / candidate).is_file()]
                if owned:
                    contracts.update(owned)
                    break
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
    contracts = declaration_closure(root, contracts)
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
    parser.add_argument("--declarations", type=Path)
    options = parser.parse_args()
    events = [json.loads(line) for line in options.events.read_text().splitlines() if line]
    declarations = set()
    if options.declarations:
        for label in options.declarations.read_text().splitlines():
            if label.startswith("@@//"):
                label = label[2:]
            if not label.startswith("//"):
                continue
            package, name = label[2:].split(":", 1)
            path = PurePosixPath(package, name)
            if path.is_absolute() or ".." in path.parts or not (options.root / path).is_file():
                raise ValueError(f"invalid first-party declaration label: {label}")
            declarations.add(path.as_posix())
    result = inventory(options.root, options.targets, reports_from_events(events), declarations)
    if options.source_lock:
        result["contracts"]["MODULE.bazel.lock"] = hashlib.sha256(options.source_lock.read_bytes()).hexdigest()
    options.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
