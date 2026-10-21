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
            # Exact reviewed files cover quota/namespace UAPIs, verity, retained
            # descriptors, bounded ancillary custody and checked writer closure.
            # Any new unsafe source or edit requires another source review.
            audited_bindings = {
                "host_cache/owner/admission/io.rs": "5676814955e67914303eb28c8604268908591410376184fb949ad782019f6d9f",
                "host_cache/owner/index_io.rs": "7ae0c2fb8c279fbcbc82ba1ec8b0eed0397f252bebc6cac80d72ff31aef730a1",
                "host_cache/quota.rs": "ec5d74ccd8c5e4225c9dfa8a9a30283b9b3b34ab0fde4489ba7199882a78714b",
                "host_quota/claim.rs": "a657e81c4d3ebe255a29cd7f99cd632e9a7f9ea3e8396681c9c020900d48af8d",
                "host_quota/custody.rs": "14d975499b2766284f4d4e2f78433abf692296076ce58f12ee79e0efdbd96b48",
                "host_quota/guard.rs": "d0b9f99cb13475def9f5482aec416fc68b5beb2410e11435118585154ded3944",
                "host_quota/namespace.rs": "288636e7b7c86422d0533ad6ddce4929dd1ff83d9285c442d9161185036a7a2b",
                "host_quota/native.rs": "63d23cfcc0ee38daa738148ff736f08e1c1ff17609fddb5a877626ce579d1be9",
                "host_quota/socket.rs": "78a16b9580400da66c2876d72ea476684f3a0dc9539d71bacbdecc7c9102c2c3",
                "host_quota/socket_signal_tests.rs": "c4f041e5cb000943899f5ab4ac6a2b2b47a3d5ba02c6408a5d2f915ee4011cc6",
                "publisher_io/native.rs": "b4c8f4bdda791ee3a4a24e7400c886b238f4e9c6b08319456c5e867059de40b9",
                "publisher_local/socket.rs": "d6541c19be7f5c7b666a4dd528874cba9f0d1b793bafe36d287d852381f6212e",
                "quota_confinement/policy.rs": "ff28f14c265e324bd71aa19fe2f936a79c087b532b012a87d014a852e5a4334d",
                "quota_confinement.rs": "33b08c1dea03a09001087fc7246ff585c93a9b7925d5726ec614ced1529f0ca2",
                "verity/mod.rs": "2dde139b9d4a1743741973e5da21a3fd27e46af9e357ee845fd6d07446b01a4e",
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
