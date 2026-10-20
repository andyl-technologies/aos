"""Installs source-bound surface test binaries without qualifying tests.

The shared native image helper owns genuine Cargo launch discovery and reachable
ELF runtime retention. Each consuming gate checks this image and runs its own
required cases; build-time discovery is deliberately limited to libtest --list.
"""

import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import sys
import tomllib


TARGETS = ["local_sdk", "surface_contract", "surface_runtime", "surface_lifecycle_contract",
           "configured_local_repository"]
FEATURES = ["send", "std", "surface-sdk", "tokio"]
CARGO_FLAGS = [
    "--frozen", "--offline", "-p", "terrane-sdk", "--no-default-features",
    "--features", "tokio,surface-sdk",
]


def require(condition, message):
    """Stops publication or execution when image identity is unproven."""
    if not condition:
        raise SystemExit(message)


def native_helper(path):
    """Loads the immutable common runtime installer without changing its file."""
    spec = importlib.util.spec_from_file_location("native_test_image", path)
    require(spec is not None and spec.loader is not None, "missing native image helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def selected_artifacts(workspace, target_dir, temporary):
    """Binds the exact Cargo artifacts to actual package, source and profile."""
    records = [json.loads(line) for line in
               (temporary / "surface-build.jsonl").read_text().splitlines()]
    packages = json.loads((temporary / "surface-packages.json").read_text())["packages"]
    selected = [package for package in packages
                if pathlib.Path(package["manifest_path"]) == workspace / "terrane/sdk/terrane-sdk/Cargo.toml"]
    require(len(selected) == 1 and selected[0]["name"] == "terrane-sdk",
            "surface test package does not belong to the selected source")
    manifest = tomllib.loads((workspace / "Cargo.toml").read_text())
    require(manifest.get("profile", {}).get("test", {}) == {"debug": 0, "opt-level": "s"},
            "surface test workspace profile mismatch")
    artifacts = {}
    for name in TARGETS:
        candidates = [record for record in records
                      if record.get("reason") == "compiler-artifact"
                      and record.get("target", {}).get("name") == name
                      and record.get("profile", {}).get("test") is True]
        require(len(candidates) == 1, f"expected one surface test artifact: {name}")
        artifact = candidates[0]
        profile = artifact["profile"]
        executable = pathlib.Path(artifact.get("executable") or "")
        require(artifact["package_id"] == selected[0]["id"]
                and artifact["target"]["kind"] == ["test"]
                and pathlib.Path(artifact["target"]["src_path"])
                == workspace / "terrane/sdk/terrane-sdk/tests" / f"{name}.rs"
                and sorted(artifact.get("features", [])) == FEATURES
                and profile.get("opt_level") == "s" and profile.get("debuginfo") == 0
                and executable.is_file() and os.access(executable, os.X_OK)
                and executable.resolve().is_relative_to(target_dir.resolve()),
                f"surface artifact package, source, feature, profile or executable mismatch: {name}")
        artifacts[name] = (artifact, executable)
    return artifacts


def verify_image(image, workspace, source, native):
    """Checks the source and actual retained binary before each independent gate."""
    identity = json.loads((image / "share/identity.json").read_text())
    require(identity.get("schema_version") == 1 and identity.get("source") == str(source)
            and identity.get("targets") == TARGETS,
            "surface test image source or target mismatch")
    hashes = native.source_hashes(workspace, source)
    for name in TARGETS:
        directory = image / "targets" / name
        target = json.loads((directory / "share/identity.json").read_text())
        profile = target.get("profile", {})
        artifact = identity.get("artifacts", {}).get(name, {})
        binary = directory / "libexec/terrane-native-sdk-tests"
        require(target.get("source") == str(source)
                and target.get("cargo_profile") == "test"
                and target.get("default_features") is False
                and target.get("requested_features") == ["tokio", "surface-sdk"]
                and target.get("features") == FEATURES
                and profile.get("test") is True and profile.get("opt_level") == "s"
                and profile.get("debuginfo") == 0
                and target.get("input_sha256") == hashes
                and target.get("working_directory") == "terrane/sdk/terrane-sdk"
                and binary.is_file() and os.access(binary, os.X_OK)
                and artifact.get("package_id") == target.get("package_id")
                and artifact.get("target_kind") == ["test"]
                and artifact.get("source") == f"terrane/sdk/terrane-sdk/tests/{name}.rs"
                and artifact.get("features") == FEATURES
                and artifact.get("profile") == profile
                and artifact.get("binary_sha256") == hashlib.sha256(binary.read_bytes()).hexdigest(),
                f"surface test image identity mismatch: {name}")


def install_image(workspace, source, output, temporary, target_dir, native):
    """Retains each executable's actual Cargo launch and reachable ELF closure."""
    artifacts = selected_artifacts(workspace, target_dir, temporary)
    hashes = native.source_hashes(workspace, source)
    target_libraries = pathlib.Path((temporary / "surface-target-libdir.txt").read_text().strip())
    require(target_libraries.is_dir() and target_libraries.is_relative_to("/nix/store"),
            "Rust target libraries are not immutable store inputs")
    (output / "targets").mkdir()
    (output / "share").mkdir()
    bound_artifacts = {}
    for name, (artifact, executable) in artifacts.items():
        discovery = temporary / f"surface-{name}"
        discovery.mkdir()
        shutil.copy2(temporary / "surface-build.jsonl", discovery / "native-sdk-build.jsonl")
        native.CARGO_FLAGS = [*CARGO_FLAGS, "--test", name]
        directories, working_directory = native.cargo_discovery(
            executable, target_dir, discovery, target_libraries, workspace)
        libraries, store_directories = native.runtime_closure(executable, directories, target_dir)
        destination = output / "targets" / name
        destination.mkdir()
        native.install_image(artifact, executable, source, destination, hashes, libraries,
                             store_directories, working_directory, discovery)
        bound_artifacts[name] = {
            "package_id": artifact["package_id"],
            "target_kind": artifact["target"]["kind"],
            "source": pathlib.Path(artifact["target"]["src_path"]).relative_to(workspace).as_posix(),
            "profile": artifact["profile"],
            "features": sorted(artifact["features"]),
            "binary_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        }
    require(hashes == native.source_hashes(workspace, source), "surface discovery changed inputs")
    identity = {"schema_version": 1, "source": str(source), "targets": TARGETS,
                "artifacts": bound_artifacts}
    (output / "share/identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    shutil.copy2(temporary / "surface-build.jsonl", output / "share/build.jsonl")
    verify_image(output, workspace, source, native)


def main():
    """Installs a compilation image or validates it for an independent gate."""
    native = native_helper(sys.argv[1])
    workspace = pathlib.Path.cwd()
    source = pathlib.Path(os.environ["src"])
    if len(sys.argv) == 4 and sys.argv[2] == "--verify":
        verify_image(pathlib.Path(sys.argv[3]), workspace, source, native)
        return
    require(len(sys.argv) == 2, "unexpected surface image arguments")
    install_image(workspace, source, pathlib.Path(os.environ["out"]),
                  pathlib.Path(os.environ["TMPDIR"]),
                  pathlib.Path(os.environ["CARGO_TARGET_DIR"]), native)


if __name__ == "__main__":
    main()
