"""Compares the public QEMU plugin's installed and admission contracts."""

import argparse
import json
from pathlib import Path

from installed_package import compare_installed, inventory, runtime_closures
from verify_cache import execution_events
from verify_package_evaluation_driver import production_profiles
from verify_protocol import compare_features
from verify_qemu_gpl import artifact, elf
from verify_qemu_installed import reject_metadata_drift


PLUGIN = "crucible-qemu-plugin"
BUILD_INFO = "nix-support/crucible-qemu-plugin-build-info"
PACKAGE_PATHS = {
    name: "crates/crucible/" + name
    for name in [PLUGIN, "crucible-qemu-protocol", "crucible-qemu-shmem"]
}


def metadata(root):
    """Reads the complete installed identity without accepting duplicate fields."""
    values = {}
    for line in (root / BUILD_INFO).read_text().splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or not value or key in values:
            raise ValueError("invalid installed QEMU plugin build information")
        values[key] = value
    return values


def checked_actions(build):
    """Requires fresh sandbox execution for every recorded build or test action."""
    actions = execution_events(build)
    if not actions or any(
        event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"]
        for event in actions
    ):
        raise ValueError("public QEMU plugin qualification requires fresh sandbox actions")
    return len(actions)


def verify(options):
    """Preserves installed files, licenses, ABI exports, closures and compiler units."""
    packages = json.loads(options.packages.read_text())
    if set(packages) != {"ordinary", "bazel"} or any(set(value) != {"out"} for value in packages.values()):
        raise ValueError("QEMU plugin comparison requires both public package outputs")
    roots = {driver: Path(outputs["out"]) for driver, outputs in packages.items()}
    closures = runtime_closures(packages, json.loads(options.closure_attributes.read_text()))
    if closures["changes"] != {"out": {"added": [], "removed": []}}:
        raise ValueError("public QEMU plugin runtime closure differs")

    identities = {driver: metadata(root) for driver, root in roots.items()}
    before, after = [dict(identities[driver]) for driver in ["ordinary", "bazel"]]
    if (before.pop("build_system") != "mkCargoPackage" or before.pop("cargo_deps") != "fetchCargoVendor"
            or after.pop("build_system") != "mkAosBazelBuild"
            or after.pop("rust_dependencies") != "locked-bazel-source-repositories" or before != after):
        raise ValueError("public QEMU plugin admission metadata differs")
    installed = {driver: inventory(outputs, options.readelf, options.loader)
                 for driver, outputs in packages.items()}
    # Only the two checked build-driver fields may differ. Everything else in
    # this file was compared above; retain the full observations in the report.
    comparison = {driver: {key: value for key, value in entries.items() if key != "out/" + BUILD_INFO}
                  for driver, entries in installed.items()}
    search_changes = compare_installed(comparison["ordinary"], comparison["bazel"])

    abi = json.loads((options.abi / "identity.json").read_text())
    observations = {}
    for driver, root in roots.items():
        library = root / "lib/libcrucible_qemu_plugin.so"
        observed = elf(library, options.readelf)
        version = [item for item in observed["exports"] if item["name"] == "qemu_plugin_version"]
        if len(version) != 1 or version[0]["kind"] != "OBJECT" or version[0]["size"] != 4:
            raise ValueError("public plugin QEMU version export has an invalid ABI")
        data = library.read_bytes()
        for key in ["qemu_build_id", "atomic_patch_sha256", "shmem_header_sha256"]:
            if abi[key].encode() not in data:
                raise ValueError("public plugin omitted its checked admission identity: " + key)
        if (root / "lib/qemu/plugins/crucible-qemu-plugin.so").readlink() != Path("../../libcrucible_qemu_plugin.so"):
            raise ValueError("public QEMU plugin installation symlink differs")
        licenses = root / "share/licenses" / PLUGIN
        for name, source in [("GPL-2.0.txt", options.gpl), ("MIT.txt", options.mit)]:
            if (licenses / name).read_bytes() != source.read_bytes():
                raise ValueError("public QEMU plugin changed a shipped license")
        observations[driver] = {key: value for key, value in observed.items() if key != "raw"}
    exports = [[(item["name"], item["kind"]) for item in observations[driver]["exports"]]
               for driver in ["ordinary", "bazel"]]
    if exports[0] != exports[1] or ("qemu_plugin_install", "FUNC") not in exports[0]:
        raise ValueError("public QEMU plugin export contracts differ")

    label = "//crates/crucible/crucible-qemu-plugin:compiler_artifact"
    if set(json.loads((options.build / "packages/index.json").read_text())) != {label}:
        raise ValueError("public QEMU plugin compilation includes another packaged component")
    artifact(options.build, PLUGIN, "lib/libcrucible_qemu_plugin.so")
    for workspace in [options.workspace, options.test_workspace, options.oracle_workspace]:
        if any(path.name in {"Cargo.toml", "Cargo.lock"} for path in workspace.rglob("Cargo.*")):
            raise ValueError("public QEMU plugin compilation retains Cargo metadata")
    messages = roots["ordinary"] / "nix-support/cargo-build-messages.jsonl"
    return {
        "schema_version": 1, "status": "PASS", "packages": packages,
        "runtime_closures": closures, "installed": installed,
        "library_search_changes": search_changes,
        "admission_metadata": identities, "elf": observations,
        "production_features": compare_features(
            options.build / "inventory.json", messages, PACKAGE_PATHS, required_packages=PACKAGE_PATHS,
        ),
        "production_profiles": production_profiles(options.build, messages, PACKAGE_PATHS),
        "fresh_linux_sandbox_actions": {
            "production": checked_actions(options.build),
            "release_tests": checked_actions(options.tests),
            "apache_oracle": checked_actions(options.oracle_build),
        },
        "rejected_admission_drift": reject_metadata_drift(
            options, roots["bazel"] / "lib/libcrucible_qemu_plugin.so", abi,
        ),
        "production_default_cutover": False,
        "foreign_execution_qualified": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in [
        "packages", "closure-attributes", "build", "tests", "oracle-build", "workspace",
        "test-workspace", "oracle-workspace", "abi", "qemu", "gpl", "mit",
        "readelf", "loader", "metadata-installer", "output",
    ]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--qemu-shmem-abi", required=True)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")
