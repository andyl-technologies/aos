"""Exports configured Rust package closures without reconstructing Cargo metadata.

Each input inventory must come from exactly one production compilation root.
The inventory aspect follows all configured attributes, including build-script
bridges and procedural macros. Its complete set of compilation reports defines
closure membership; projecting only edges between Rust rules would lose build
dependencies behind non-Rust bridge rules.

SDK source manifests supply external package identities and license expressions.
The unconfigured architecture query supplies first-party source ownership. This
exporter records those facts; consumers apply their existing license policies.
Native library and pinned build-tool license qualification remain separate.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath


RUST_RULES = {
    "rust_library", "rust_binary", "rust_proc_macro", "rust_shared_library", "rust_static_library",
}

# These exact rules_rust implementation tools are not application packages.
# Unknown tools fail closed instead of receiving a repository-wide exemption.
RULE_TOOLS = {
    "@@rules_rust+//cargo/private/cargo_build_script_runner:cargo_build_script_runner": "rust_library",
    "@@rules_rust+//cargo/private/cargo_build_script_runner:runner": "rust_binary",
    "@@rules_rust+//cargo/private:no_binary": "rust_binary",
    "@@rules_rust+//util/process_wrapper:process_wrapper": "rust_binary_without_process_wrapper",
    "@@rules_rust++i+rules_rust_tinyjson//:tinyjson": "rust_library_without_process_wrapper",
}


def digest(path):
    """Hashes one retained input without normalizing its serialized bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pinned_sources(directory):
    """Indexes package identities by the SDK's declared repository names."""
    sources = {}
    manifests = {}
    for path in sorted(directory.glob("*/sources.json")):
        document = json.loads(path.read_text())
        if document["schema_version"] != 1:
            raise ValueError("unsupported SDK source manifest")
        manifests[path.relative_to(directory).as_posix()] = digest(path)
        for repository, source in document["sources"].items():
            for field in ["name", "version", "license", "sha256"]:
                if not isinstance(source.get(field), str) or not source[field]:
                    raise ValueError("incomplete SDK license identity: " + repository)
            if len(source["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in source["sha256"]):
                raise ValueError("invalid SDK source digest: " + repository)
            identity = {key: source[key] for key in ["name", "version", "license", "sha256"]}
            if repository in sources and sources[repository] != identity:
                raise ValueError("conflicting SDK license identity: " + repository)
            sources[repository] = identity
    if not sources:
        raise ValueError("license closures require pinned SDK source manifests")
    return sources, manifests


def source_root(report, prefix):
    """Rejects compilation sources outside their declared source repository."""
    root = report["crate_root"]
    if not root.startswith(prefix):
        raise ValueError("compiled source escapes declared repository: " + report["label"])
    relative = root.removeprefix(prefix)
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != relative or not root.endswith(".rs"):
        raise ValueError("invalid compiled source root: " + report["label"])
    return relative


def archive_source_owner(report, architecture):
    """Validates roots for shared/static rules that omit CrateInfo providers."""
    declaration = architecture["compilation_targets"].get(report["label"])
    if declaration is None or declaration["kind"] != report["kind"]:
        raise ValueError("archive compilation has no matching source declaration")
    directory = report["label"].removeprefix("//").partition(":")[0]
    roots = declaration["crate_roots"]
    if not roots:
        raise ValueError("archive compilation omitted its declared source roots")
    for relative in roots:
        root = directory + "/" + relative
        source_root({"crate_root": root, "label": report["label"]}, directory + "/")
    if not any(directory + "/" + relative in report["sources"] for relative in roots):
        raise ValueError("archive compilation omitted its declared root from configured sources")


def export_closure(inventory, root, architecture, sources):
    """Projects every configured compilation onto an owned package identity."""
    if inventory["schema_version"] != 1 or inventory["targets"] != [root]:
        raise ValueError("license inventory requires exactly its declared production root")
    if architecture["schema_version"] != 1:
        raise ValueError("unsupported architecture source ownership")
    owners = {package["directory"]: package for package in architecture["packages"]}
    if len(owners) != len(architecture["packages"]):
        raise ValueError("duplicate license source ownership")
    root_declaration = architecture["compilation_targets"].get(root)
    if root_declaration is None or root_declaration["test_only"] or root_declaration["kind"] not in RUST_RULES:
        raise ValueError("license root is not a declared production compilation")

    packages = {}
    tools = {}
    root_seen = False
    for report in inventory["configured_targets"]:
        label = report["label"]
        kind = report["kind"]
        if report["schema_version"] != 1:
            raise ValueError("unsupported configured license report")
        if not report.get("crate_root"):
            if kind in {"rust_shared_library", "rust_static_library"} and not report["external"]:
                # Shared/static artifacts expose linking providers instead of
                # CrateInfo. Require their declared Rust root in actual inputs.
                archive_source_owner(report, architecture)
            elif kind in RUST_RULES or label in RULE_TOOLS:
                raise ValueError("compiled license report omitted its source root: " + label)
            else:
                continue
        if label in RULE_TOOLS:
            if kind != RULE_TOOLS[label] or not report["external"]:
                raise ValueError("pinned rule tool changed compilation kind: " + label)
            repository = label.removeprefix("@@").partition("//")[0]
            source_root(report, "../" + repository + "/")
            tools[label] = {"kind": kind, "crate_root": report["crate_root"]}
            continue
        if kind not in RUST_RULES:
            raise ValueError("unsupported compilation in license closure: " + label)

        if report["external"]:
            prefix = "@@+aos_tools_repository+"
            if not label.startswith(prefix):
                raise ValueError("unowned external Rust compilation: " + label)
            repository = label.removeprefix(prefix).partition("//")[0]
            if repository not in sources:
                raise ValueError("external compilation has no pinned license identity: " + label)
            identity = sources[repository]
            relative = source_root(report, "../+aos_tools_repository+" + repository + "/")
            # rules_rust's generated build-script program has a synthetic 0.0.0
            # version. The enclosing pinned crate archive still owns its source.
            build_program = kind == "rust_binary" and relative == "build.rs" and report["version"] == "0.0.0"
            if report["version"] != identity["version"] and not build_program:
                raise ValueError("compiled package version differs from pinned source: " + label)
            key = "sdk:" + repository
            package = {**identity, "source": "sdk", "repository": repository}
        else:
            if not label.startswith("//crates/"):
                raise ValueError("unowned first-party Rust compilation: " + label)
            directory = label.removeprefix("//").partition(":")[0]
            if directory not in owners:
                raise ValueError("compilation has no declared source owner: " + label)
            owner = owners[directory]
            declaration = architecture["compilation_targets"].get(label)
            if (declaration is None or declaration["test_only"] or declaration["kind"] != kind
                    or declaration["package"] != owner["name"]):
                raise ValueError("configured compilation differs from its production source declaration: " + label)
            if report["crate_root"]:
                relative = source_root(report, directory + "/")
                if relative not in declaration["crate_roots"]:
                    raise ValueError("configured source root differs from its declaration: " + label)
            if report["version"] != owner["version"]:
                raise ValueError("compiled first-party version differs from declared source: " + label)
            key = "local:" + directory
            package = {field: owner[field] for field in ["name", "version", "license"]}
            package.update(source="local", directory=directory)
        previous = packages.setdefault(key, {**package, "compilation_targets": set()})
        previous["compilation_targets"].add(label)
        if label == root:
            if report["external"] or package["name"] != root_declaration["package"] or kind != root_declaration["kind"]:
                raise ValueError("configured license root differs from its declaration")
            root_seen = True
    if not root_seen:
        raise ValueError("license inventory omitted its production compilation root")
    return {
        "root": root,
        "root_package": root_declaration["package"],
        "packages": [{**package, "compilation_targets": sorted(package["compilation_targets"])}
                     for _, package in sorted(packages.items())],
        "excluded_rule_tools": dict(sorted(tools.items())),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--architecture", type=Path, required=True)
    parser.add_argument("--sdk-directory", type=Path, required=True)
    parser.add_argument("--modules", type=Path, required=True)
    parser.add_argument("--rule-inputs", type=Path, required=True)
    parser.add_argument("--inventory", action="append", nargs=2, metavar=("ROOT", "PATH"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    architecture = json.loads(args.architecture.read_text())
    sources, manifests = pinned_sources(args.sdk_directory)
    closures = {}
    for root, filename in args.inventory:
        if root in closures:
            raise ValueError("duplicate license closure root")
        path = Path(filename)
        closures[root] = {**export_closure(json.loads(path.read_text()), root, architecture, sources),
                          "inventory_sha256": digest(path)}
    modules = json.loads(args.modules.read_text())
    rule_inputs = json.loads(args.rule_inputs.read_text())
    document = {
        "schema_version": 1,
        "selection": "configured Rust compilation closures, including build scripts and procedural macros",
        "architecture_sha256": digest(args.architecture),
        "sdk_manifest_sha256": manifests,
        "rule_tool_sources": {
            "rules_rust": modules["modules"]["rules_rust"],
            "rules_rust_tinyjson": rule_inputs["repositories"]["rules_rust++i+rules_rust_tinyjson"],
        },
        "closures": dict(sorted(closures.items())),
    }
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
