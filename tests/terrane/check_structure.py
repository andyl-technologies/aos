"""Checks T0 crate dependency direction and unsafe policy from Cargo metadata."""

import json
import pathlib
import re
import sys
import tomllib


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    gate, repository, metadata_path = sys.argv[1:]
    repository = pathlib.Path(repository)
    metadata = json.loads(pathlib.Path(metadata_path).read_text())
    packages = {package["name"]: package for package in metadata["packages"]}
    standalone = ["terrane-core", "terrane", "terrane-fs", "terrane-cli"]
    expected = {
        "terrane-core": set(),
        "terrane": {"terrane-core"},
        "terrane-fs": {"terrane"},
        "terrane-cli": {"terrane", "terrane-fs"},
        "aos-terrane": {"terrane"},
    }

    for name in [*standalone, "aos-terrane"]:
        check(name in packages, f"missing workspace crate: {name}")
        package = packages[name]
        check(package["id"] in metadata["workspace_members"], f"not a workspace member: {name}")
        check(package["edition"] == "2024", f"wrong edition: {name}")
        manifest_path = pathlib.Path(package["manifest_path"])
        manifest = tomllib.loads(manifest_path.read_text())
        check(manifest.get("lints", {}).get("workspace") is True, f"missing workspace lints: {name}")
        sources = list(manifest_path.parent.glob("src/**/*.rs"))
        check(sources, f"missing implementation source: {name}")
        for source in sources:
            text = source.read_text()
            check(text.startswith("//!"), f"missing module overview: {source}")

        if gate == "crate-graph":
            dependencies = {dependency["name"] for dependency in package["dependencies"]}
            internal = {dependency for dependency in dependencies if dependency.startswith("terrane")}
            check(internal == expected[name], f"invalid dependency direction: {name}: {internal}")
            if name in standalone:
                check(not any(dep.startswith(("aos-", "crucible-")) for dep in dependencies), f"host dependency in {name}")
            if name == "terrane-core":
                check(dependencies == {"blake3"}, "core dependency boundary changed; audit no_std support")
                root = (manifest_path.parent / "src/lib.rs").read_text()
                check("#![no_std]" in root and "extern crate alloc;" in root, "core must use no_std + alloc")
            if name == "terrane-cli":
                binaries = [target["name"] for target in package["targets"] if "bin" in target["kind"]]
                check(binaries == ["terrane"], f"unexpected binaries: {binaries}")
        elif gate == "unsafe-audit":
            root_path = manifest_path.parent / "src" / ("main.rs" if name == "terrane-cli" else "lib.rs")
            root = root_path.read_text()
            if name == "terrane-fs":
                check("#![deny(unsafe_op_in_unsafe_fn)]" in root, "fs must deny unchecked unsafe operations")
                check('cfg(not(target_os = "linux"))' in root and "compile_error!" in root, "fs must reject non-Linux builds")
            else:
                check("#![forbid(unsafe_code)]" in root, f"unsafe code not forbidden: {name}")
            # No kernel bindings exist at T0. Any future unsafe binding needs a
            # deliberate audit replacing this stricter foundation assertion.
            for source in sources:
                check(not re.search(r"\bunsafe\s*(?:\{|fn|impl|trait)", source.read_text()), f"unsafe implementation needs audit: {source}")
        else:
            raise AssertionError(f"unknown foundation gate: {gate}")

    print(f"{gate}: foundation crate policy passes")


if __name__ == "__main__":
    main()
