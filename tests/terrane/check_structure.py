"""Checks T0 crate dependency direction and unsafe policy from Cargo metadata."""

import hashlib
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
    standalone = ["terrane-format", "terrane-sdk", "terrane-linux", "terrane-cli"]
    expected = {
        "terrane-format": set(),
        "terrane-sdk": {"terrane-format"},
        "terrane-linux": {"terrane-sdk", "terrane-format"},
        "terrane-cli": {"terrane-sdk", "terrane-linux"},
        "aos-terrane-integration": {"terrane-sdk", "terrane-format", "terrane-linux"},
    }

    for name in [*standalone, "aos-terrane-integration"]:
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
            internal = {dependency for dependency in dependencies if dependency.startswith("terrane-")}
            check(internal == expected[name], f"invalid dependency direction: {name}: {internal}")
            if name in standalone:
                check(not any(dep.startswith(("aos-", "crucible-")) for dep in dependencies), f"host dependency in {name}")
            if name == "terrane-format":
                # The isolated core-no-std compilation is the semantic check.
                # New portable dependencies can land without changing this gate,
                # but enabling default or std features requires deliberate review.
                for dependency in package["dependencies"]:
                    check(not dependency["uses_default_features"], f"core dependency enables default features: {dependency['name']}")
                    check("std" not in dependency["features"], f"core dependency enables std: {dependency['name']}")
                root = (manifest_path.parent / "src/lib.rs").read_text()
                check("#![no_std]" in root and "extern crate alloc;" in root, "core must use no_std + alloc")
            if name == "terrane-cli":
                binaries = [target["name"] for target in package["targets"] if "bin" in target["kind"]]
                check(binaries == ["terrane"], f"unexpected binaries: {binaries}")
        elif gate == "unsafe-audit":
            root_path = manifest_path.parent / "src" / ("main.rs" if name == "terrane-cli" else "lib.rs")
            root = root_path.read_text()
            if name == "terrane-linux":
                check("#![deny(unsafe_op_in_unsafe_fn)]" in root, "fs must deny unchecked unsafe operations")
                check('cfg(not(target_os = "linux"))' in root and "compile_error!" in root, "fs must reject non-Linux builds")
            else:
                check("#![forbid(unsafe_code)]" in root, f"unsafe code not forbidden: {name}")
            # Native bindings added after T0 require a deliberate source audit.
            # These exact reviewed modules bind namespace and confinement ABIs;
            # any additional unsafe source or edit requires another review.
            audited_bindings = {
                "host_quota/namespace.rs": "288636e7b7c86422d0533ad6ddce4929dd1ff83d9285c442d9161185036a7a2b",
                "quota_confinement.rs": "210c63c0a88b8cd12c177725f0c84272e9d4e981a015af661dc50257f6a208f6",
                "quota_confinement/policy.rs": "94cadf8dcf69f044008c1becfca1c5ae0672195a6b9358343a97847e8a8779fe",
            }
            for source in sources:
                text = source.read_text()
                if not re.search(r"\bunsafe\s*(?:\{|fn|impl|trait)", text):
                    continue

                relative = source.relative_to(manifest_path.parent / "src").as_posix()
                check(name == "terrane-linux", f"unsafe outside Linux bindings: {source}")
                check(hashlib.sha256(source.read_bytes()).hexdigest() == audited_bindings.get(relative),
                      f"unsafe implementation needs audit: {source}")
        else:
            raise AssertionError(f"unknown foundation gate: {gate}")

    print(f"{gate}: foundation crate policy passes")


if __name__ == "__main__":
    main()
