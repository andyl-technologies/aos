"""Checks real WebAssembly library objects against immutable portable SDK inputs."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from native_sdk_test_image import source_hashes


def require(condition, message):
    """Refuses mismatched source, features, profiles or object formats."""
    if not condition:
        raise SystemExit(message)


output = Path(os.environ["out"])
source = Path(os.environ["src"])
workspace = Path.cwd()
target = Path(os.environ["CARGO_TARGET_DIR"]) / "wasm32-unknown-unknown" / "release"
inputs = source_hashes(workspace, source)
rows = [json.loads(line) for line in (output / "build.jsonl").read_text().splitlines()]
artifacts = [row for row in rows if row.get("reason") == "compiler-artifact"]
selected = {}
for name, directory, features in [
    ("terrane_format", "terrane-format", []),
    ("terrane_sdk", "terrane-sdk", ["wasm"]),
]:
    matching = [row for row in artifacts if row["target"]["name"] == name]
    require(len(matching) == 1, "ambiguous portable library artifact: " + name)
    artifact = matching[0]
    profile = artifact["profile"]
    require(artifact["target"]["kind"] == ["lib"]
            and artifact["target"]["crate_types"] == ["lib"]
            and Path(artifact["target"]["src_path"]) == workspace / "terrane/sdk" / directory / "src/lib.rs"
            and artifact["package_id"].startswith("path+file://" + str(workspace / "terrane/sdk" / directory))
            and artifact["features"] == features
            and profile["test"] is False and profile["opt_level"] == "3"
            and profile["debuginfo"] == 0 and profile["debug_assertions"] is False,
            "portable library source, features or profile mismatch: " + name)
    libraries = [Path(filename) for filename in artifact["filenames"] if filename.endswith(".rlib")]
    require(len(libraries) == 1 and libraries[0].resolve().is_relative_to(target.resolve()),
            "portable library was not built for the selected wasm32 target")
    library = libraries[0]
    command = os.environ["AR_wasm32_unknown_unknown"]
    members = subprocess.check_output([command, "t", str(library)], text=True).splitlines()
    objects = [member for member in members if member.endswith(".o")]
    require(objects and len(objects) == len(set(objects)), "missing or duplicate WebAssembly objects")
    for member in objects:
        body = subprocess.check_output([command, "p", str(library), member])
        require(body.startswith(b"\0asm\x01\0\0\0"), "non-WebAssembly library object: " + member)
    destination = output / (name + ".rlib")
    shutil.copyfile(library, destination)
    selected[name] = {
        "artifact": artifact,
        "library": destination.name,
        "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
        "wasm_object_members": objects,
    }

# Host-side code generators may have native dependencies. Only target artifacts
# describe what the portable library will require in a WebAssembly consumer.
target_dependencies = []
for artifact in artifacts:
    if not any(Path(filename).resolve().is_relative_to(target.resolve())
               for filename in artifact["filenames"]):
        continue
    target_dependencies.append(artifact)
    require(artifact["target"]["name"] not in {"xattr", "rustix", "errno", "libc", "tokio", "reqwest"},
            "native dependency entered the portable target")
    if artifact["target"]["name"] == "zstd_sys":
        require("zstdmt" not in artifact["features"], "portable Zstd requires native POSIX threads")

require(any(artifact["target"]["name"] == "zstd_sys" for artifact in target_dependencies),
        "portable codec target artifact is missing")
require(source_hashes(workspace, source) == inputs, "portable compilation inputs changed")
(output / "source-review.json").write_text(json.dumps({
    "source": str(source),
    "input_sha256": inputs,
    "target": "wasm32-unknown-unknown",
    "sdk_features": ["wasm"],
    "libraries": selected,
    "target_dependencies": target_dependencies,
    "compilation_only": True,
    "std_filesystem_profile": False,
}, indent=2) + "\n")
