#!/usr/bin/env python3
"""Cargo workspace inheritance resolver.

Port of nixpkgs's replace-workspace-values.py, adapted for AOS to use only
the Python standard library — `tomllib` for reading, an inline TOML writer
matching the one in fetch-cargo-vendor-util.py for writing.

Implements the dependency-merging logic from
https://doc.rust-lang.org/cargo/reference/workspaces.html#the-package-table —
when a vendored crate's Cargo.toml has `version.workspace = true` (or similar
for other fields), look up the value in the workspace root's Cargo.toml and
inline it.

Usage: replace-workspace-values.py <crate_manifest> <workspace_root_manifest>
"""

import importlib.util
import sys
import tomllib
from pathlib import Path
from typing import Any

# fetch-cargo-vendor-util.py lives alongside us but its hyphenated filename
# can't be `import`-ed by name. Load it via spec_from_file_location to reuse
# the TOML writer.
_HERE = Path(__file__).resolve().parent
_util_spec = importlib.util.spec_from_file_location(
    "_fetch_cargo_vendor_util", _HERE / "fetch-cargo-vendor-util.py"
)
assert _util_spec is not None and _util_spec.loader is not None
_util = importlib.util.module_from_spec(_util_spec)
_util_spec.loader.exec_module(_util)
toml_dump = _util.toml_dump


def load_file(path: str) -> dict[str, Any]:
    with open(path, "rb") as f:
        return tomllib.load(f)


def replace_key(
    workspace_manifest: dict[str, Any],
    table: dict[str, Any],
    section: str,
    key: str,
) -> bool:
    if (
        isinstance(table[key], dict)
        and "workspace" in table[key]
        and table[key]["workspace"] is True
    ):
        print("replacing " + key)

        local_dep = table[key]
        del local_dep["workspace"]

        try:
            workspace_dep = workspace_manifest[section][key]
        except KeyError:
            # Key missing from workspace — mark for deletion
            table[key] = {}
            return True

        if section == "dependencies":
            if isinstance(workspace_dep, str):
                workspace_dep = {"version": workspace_dep}

            final: dict[str, Any] = workspace_dep.copy()

            merged_features = local_dep.pop("features", []) + workspace_dep.get(
                "features", []
            )
            if merged_features:
                final["features"] = merged_features

            local_default_features = local_dep.pop(
                "default-features", local_dep.pop("default_features", None)
            )
            workspace_default_features = workspace_dep.get(
                "default-features", workspace_dep.get("default_features")
            )

            if not workspace_default_features and local_default_features:
                final["default-features"] = True

            optional = local_dep.pop("optional", False)
            if optional:
                final["optional"] = True

            if "package" in local_dep:
                final["package"] = local_dep.pop("package")

            if local_dep:
                raise Exception(
                    f"Unhandled keys in inherited dependency {key}: {local_dep}"
                )

            table[key] = final
        elif section == "package":
            table[key] = workspace_dep

        return True

    return False


def replace_dependencies(
    workspace_manifest: dict[str, Any], root: dict[str, Any]
) -> bool:
    changed = False
    for key in ["dependencies", "dev-dependencies", "build-dependencies"]:
        if key in root:
            for k in root[key].keys():
                changed |= replace_key(workspace_manifest, root[key], "dependencies", k)
    return changed


def main() -> None:
    top_cargo_toml = load_file(sys.argv[2])

    if "workspace" not in top_cargo_toml:
        print(f"{sys.argv[2]} is not a workspace manifest, doing nothing.")
        return

    crate_manifest = load_file(sys.argv[1])
    workspace_manifest = top_cargo_toml["workspace"]

    if "workspace" in crate_manifest:
        return

    changed = False

    to_remove = []
    for key in crate_manifest.get("package", {}).keys():
        changed_key = replace_key(
            workspace_manifest, crate_manifest["package"], "package", key
        )
        if changed_key and crate_manifest["package"][key] == {}:
            to_remove.append(key)
        changed |= changed_key
    for key in to_remove:
        del crate_manifest["package"][key]

    changed |= replace_dependencies(workspace_manifest, crate_manifest)

    if "target" in crate_manifest:
        for key in crate_manifest["target"].keys():
            changed |= replace_dependencies(
                workspace_manifest, crate_manifest["target"][key]
            )

    if (
        "lints" in crate_manifest
        and "workspace" in crate_manifest["lints"]
        and crate_manifest["lints"]["workspace"] is True
    ):
        crate_manifest["lints"] = workspace_manifest["lints"]
        changed = True

    if not changed:
        return

    with open(sys.argv[1], "wb") as f:
        toml_dump(crate_manifest, f)


if __name__ == "__main__":
    main()
