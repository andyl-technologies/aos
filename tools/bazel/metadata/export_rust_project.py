"""Exports rust-analyzer metadata from the current configured Bazel build.

The pinned rules_rust aspect owns Rust graph discovery, build-script outputs,
features, aliases, and proc macros. This adapter resolves its path placeholders
and dependency IDs without running a second build system or reading Cargo files.
"""

import argparse
import copy
import json
from pathlib import Path
import tempfile
from urllib.parse import unquote, urlparse


def current_specs(events):
    """Returns local spec files reachable from successful aspect output groups."""
    named_sets = {}
    roots = []
    finished = False
    for event in events:
        identity = event.get("id", {})
        if "namedSet" in identity:
            named_sets[identity["namedSet"]["id"]] = event["namedSetOfFiles"]
        if "buildFinished" in identity:
            exit_code = event["finished"].get("exitCode", {})
            finished = exit_code.get("name") == "SUCCESS" and exit_code.get("code", 0) == 0
        if "targetCompleted" not in identity:
            continue
        completed = event.get("completed", {})
        if not completed.get("success"):
            raise ValueError("cannot export an unsuccessful configured target")
        for group in completed.get("outputGroup", []):
            if group["name"] == "rust_analyzer_crate_spec":
                roots.extend(item["id"] for item in group.get("fileSets", []))
    if not finished:
        raise ValueError("rust-project export requires a successful completed build")

    visited = set()
    paths = set()
    while roots:
        identifier = roots.pop()
        if identifier in visited:
            continue
        visited.add(identifier)
        files = named_sets[identifier]
        roots.extend(item["id"] for item in files.get("fileSets", []))
        for item in files.get("files", []):
            if not item["name"].endswith(".rust_analyzer_crate_spec.json"):
                continue
            uri = urlparse(item["uri"])
            if uri.scheme != "file" or uri.netloc:
                raise ValueError("rust-project export requires local aspect outputs")
            paths.add(Path(unquote(uri.path)))
    if not paths:
        raise ValueError("the selected configured graph contains no Rust crates")
    return sorted(paths)


def assemble(specs, replacements, toolchain):
    """Resolves configured crate specs, rejecting ambiguous feature variants."""
    crates = {}
    for original in specs:
        spec = copy.deepcopy(original)
        identifier = spec["crate_id"]
        if identifier not in crates:
            crates[identifier] = spec
            continue
        previous = crates[identifier]
        # A libtest target and its library share a root and may add dev deps.
        # Distinct feature/toolchain/env variants need separate editor projects.
        for field in ["edition", "target", "env", "cfg"]:
            if previous.get(field) != spec.get(field):
                # The C++ archiver toolchain adds this environment entry to
                # rlib actions. A libtest editor view uses its own environment;
                # do not conflate this internal archive setting with Rust cfgs.
                if field == "env" and previous.get("is_test") != spec.get("is_test"):
                    changed = {
                        key for key in previous["env"].keys() | spec["env"].keys()
                        if previous["env"].get(key) != spec["env"].get(key)
                    }
                    if changed == {"ZERO_AR_DATE"} and all(
                        item["env"].get("ZERO_AR_DATE") in {None, "1"}
                        for item in [previous, spec]
                    ):
                        continue
                details = ""
                if field == "env":
                    details = ": " + ", ".join(sorted(
                        key for key in previous["env"].keys() | spec["env"].keys()
                        if previous["env"].get(key) != spec["env"].get(key)
                    ))
                raise ValueError(f"ambiguous configured Rust variant: {identifier}: {field}{details}")
        if previous["crate_type"] != spec["crate_type"]:
            if not any(item.get("is_test") and item["crate_type"] == "bin" for item in [previous, spec]):
                raise ValueError(f"ambiguous configured Rust crate type: {identifier}")
            if not spec.get("is_test"):
                previous["crate_type"] = spec["crate_type"]
        if "proc_macro_dylib_path" in spec:
            existing = previous.get("proc_macro_dylib_path")
            if existing and existing != spec["proc_macro_dylib_path"]:
                raise ValueError(f"ambiguous configured Rust proc macro: {identifier}")
            previous["proc_macro_dylib_path"] = spec["proc_macro_dylib_path"]
        for dependency, alias in spec.get("aliases", {}).items():
            if dependency in previous["aliases"] and previous["aliases"][dependency] != alias:
                raise ValueError(f"ambiguous configured Rust alias: {identifier}: {dependency}")
            previous["aliases"][dependency] = alias
        previous["deps"] = sorted(set(previous["deps"]) | set(spec["deps"]))
        if spec.get("is_test"):
            previous["build"] = spec.get("build")
            previous["is_test"] = True
            previous["env"] = spec["env"]

    identifiers = sorted(crates)
    indexes = {identifier: index for index, identifier in enumerate(identifiers)}

    def expand(value):
        if isinstance(value, str):
            value = value.replace("${pwd}", str(replacements["__EXEC_ROOT__/"]))
            for marker, path in replacements.items():
                value = value.replace(marker, str(path) + "/")
            if any(marker in value for marker in ["__WORKSPACE__", "__EXEC_ROOT__", "__OUTPUT_BASE__"]):
                raise ValueError(f"unresolved Rust metadata path: {value}")
        elif isinstance(value, list):
            return [expand(item) for item in value]
        elif isinstance(value, dict):
            return {key: expand(item) for key, item in value.items()}
        return value

    result = []
    for identifier in identifiers:
        spec = crates[identifier]
        crate = {key: spec[key] for key in [
            "display_name", "root_module", "edition", "is_workspace_member",
            "source", "cfg", "target", "env",
        ]}
        crate["deps"] = []
        for dependency in sorted(set(spec["deps"])):
            if dependency not in indexes:
                raise ValueError(f"missing configured Rust dependency: {dependency}")
            crate["deps"].append({
                "crate": indexes[dependency],
                "name": spec.get("aliases", {}).get(dependency, crates[dependency]["display_name"]),
            })
        crate["is_proc_macro"] = spec["crate_type"] == "proc-macro"
        if crate["is_proc_macro"]:
            crate["proc_macro_dylib_path"] = spec["proc_macro_dylib_path"]
        # Editor runnables are deliberately omitted: builds and tests must go
        # through aos-dev, whose launcher enforces the offline toolchain policy.
        result.append(expand(crate))
    return {
        "sysroot": str(toolchain),
        "sysroot_src": str(toolchain / "developer/rust-src/library"),
        "crates": result,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--execution-root", type=Path, required=True)
    parser.add_argument("--output-base", type=Path, required=True)
    parser.add_argument("--toolchain", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    events = [json.loads(line) for line in options.events.read_text().splitlines() if line]
    specs = [json.loads(path.read_text()) for path in current_specs(events)]
    replacements = {
        "__WORKSPACE__/": options.workspace.resolve(),
        "__EXEC_ROOT__/": options.execution_root.resolve(),
        "__OUTPUT_BASE__/": options.output_base.resolve(),
    }
    project = assemble(specs, replacements, options.toolchain)
    # Replace only after all metadata validates; a failed refresh leaves the
    # previous working editor project intact.
    # Different configurations can refresh one worktree concurrently. Each
    # writer owns its temporary file; the last successful rename wins.
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=options.output.parent,
        prefix="." + options.output.name + ".", suffix=".tmp", delete=False,
    ) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(project, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.close()
            temporary.replace(options.output)
        finally:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
