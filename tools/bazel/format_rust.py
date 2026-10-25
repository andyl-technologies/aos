"""Formats first-party Rust sources using Bazel declarations and ownership.

Compilation rules supply explicit or inferred crate roots. Owned conventional
entry points also cover structural tests awaiting compilation migration. Neither
discovery nor formatting reads a Cargo manifest or invokes a Cargo driver.
"""

import argparse
from collections import defaultdict
import json
from pathlib import Path, PurePosixPath
import subprocess
import xml.etree.ElementTree as ET


RUST_RULES = {"rust_library", "rust_binary", "rust_proc_macro", "rust_test"}
EDITIONS = {"2015", "2018", "2021", "2024"}


def local_source(label, directory):
    """Requires a canonical file label beneath its declared source owner."""
    prefix = "//" + directory + ":"
    if not label.startswith(prefix):
        raise ValueError("Rust source label crosses package ownership: " + label)
    name = label.removeprefix(prefix)
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or path.as_posix() != name
            or ".." in path.parts or "\\" in name or path.suffix != ".rs"):
        raise ValueError("invalid owned Rust source: " + label)
    return directory + "/" + name


def conventional_root(relative):
    """Recognizes owned entry points independently of compilation migration."""
    parts = PurePosixPath(relative).parts
    return (
        relative in {"build.rs", "src/lib.rs", "src/main.rs"}
        or (parts[0] in {"tests", "examples", "benches"}
            and (len(parts) == 2 or (len(parts) == 3 and parts[-1] == "main.rs")))
        or (parts[:2] == ("src", "bin")
            and (len(parts) == 3 or (len(parts) == 4 and parts[-1] == "main.rs")))
    )


def inventory(query):
    """Rejects incomplete ownership, conflicting editions, and ambiguous roots."""
    document = ET.fromstring(query)
    if document.tag != "query" or document.get("version") != "2":
        raise ValueError("unsupported Bazel query document")
    rules = {}
    owners = {}
    identities = set()
    owned_sources = set()
    for rule in document:
        if rule.tag != "rule" or rule.get("class") not in RUST_RULES | {"_source_package"}:
            raise ValueError("unexpected Bazel formatting query entry")
        label = rule.get("name", "")
        if not label.startswith("//crates/") or label.count(":") != 1 or label in rules:
            raise ValueError("invalid or duplicate formatting target: " + label)
        rules[label] = rule
        if rule.get("class") != "_source_package":
            continue

        directory = label[2:].split(":")[0]
        path = PurePosixPath(directory)
        if path.as_posix() != directory or ".." in path.parts or "\\" in directory:
            raise ValueError("noncanonical source owner: " + directory)
        identity = json.loads(rule.find('string[@name="identity"]').get("value"))
        if directory in owners or identity["name"] in identities or identity["edition"] not in EDITIONS:
            raise ValueError("duplicate owner or unsupported Rust edition")
        sources = {local_source(item.get("value"), directory)
                   for item in rule.findall('list[@name="srcs"]/label')}
        if not sources or sources & owned_sources:
            raise ValueError("Rust source ownership is empty or overlaps another package")
        owners[directory] = {"name": identity["name"], "edition": identity["edition"], "sources": sources}
        identities.add(identity["name"])
        owned_sources.update(sources)
    if not owners:
        raise ValueError("formatting query contains no source ownership")

    roots = {}

    def resolve(label, visiting):
        if label not in rules or label in visiting:
            raise ValueError("missing or cyclic Rust crate target: " + label)
        rule = rules[label]
        directory = label[2:].split(":")[0]
        if directory not in owners:
            raise ValueError("Rust target has no source owner: " + label)
        owner = owners[directory]
        edition = rule.find('string[@name="edition"]')
        if edition is None or edition.get("value") != owner["edition"]:
            raise ValueError("Rust target edition differs from source ownership: " + label)
        source = rule.find('label[@name="crate_root"]')
        crate = rule.find('label[@name="crate"]')
        if source is not None:
            path = local_source(source.get("value"), directory)
        elif crate is not None:
            path = resolve(crate.get("value"), visiting | {label})
        else:
            sources = rule.findall('list[@name="srcs"]/label')
            if len(sources) != 1:
                raise ValueError("declare an explicit unambiguous Rust crate_root: " + label)
            path = local_source(sources[0].get("value"), directory)
        if path not in owner["sources"]:
            raise ValueError("Rust crate root is not an owned source: " + path)
        return path

    for label, rule in rules.items():
        if rule.get("class") in RUST_RULES:
            path = resolve(label, set())
            directory = label[2:].split(":")[0]
            roots[path] = {"edition": owners[directory]["edition"], "owner": directory}
    for directory, owner in owners.items():
        for path in owner["sources"]:
            if conventional_root(path.removeprefix(directory + "/")):
                roots[path] = {"edition": owner["edition"], "owner": directory}
        if not any(value["owner"] == directory for value in roots.values()):
            raise ValueError("Rust source owner contains no formatting root: " + directory)
    return {"schema_version": 1, "packages": len(owners), "roots": dict(sorted(roots.items()))}


def format_sources(root, metadata, rustfmt, check):
    """Validates all input paths before invoking the source-built formatter."""
    root = root.resolve()
    groups = defaultdict(list)
    for relative, item in metadata["roots"].items():
        path = root / relative
        if not path.is_file() or not path.resolve().is_relative_to(root):
            raise ValueError("Rust formatting source is absent or outside checkout: " + relative)
        groups[item["edition"]].append(str(path))

    status = 0
    for edition, paths in sorted(groups.items()):
        command = [str(rustfmt), "--edition", edition,
                   "--config-path", str(root / "tools/bazel/rules/rustfmt.toml")]
        if check:
            command.append("--check")
        result = subprocess.run(command + paths, cwd=root, check=False)
        if result.returncode:
            status = result.returncode
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--query", type=Path, required=True)
    parser.add_argument("--rustfmt", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--list", action="store_true", help="Export roots without running rustfmt.")
    parser.add_argument("--inventory-output", type=Path)
    options = parser.parse_args()
    if not options.list and options.rustfmt is None:
        parser.error("--rustfmt is required unless --list is selected")
    try:
        metadata = inventory(options.query.read_text())
        if options.inventory_output:
            options.inventory_output.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
        if not options.list:
            return format_sources(options.root, metadata, options.rustfmt, options.check)
    except (OSError, ValueError, ET.ParseError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
