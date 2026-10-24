# SPDX-License-Identifier: MIT
"""Binds an exact native gem5 product to its source-only public enrichment.

The source-built native producer remains a retained dependency. A public wrapper
does not become another compilation, execution source issuer or node capability.
"""

import hashlib
import json
from pathlib import Path
import stat
import sys


MAX_METADATA_BYTES = 4 * 1024 * 1024
MAX_NATIVE_FILES = 4096
MAX_NATIVE_BYTES = 8 * 1024 * 1024 * 1024
NATIVE_FILES = (
    "gem5-upstream.tar.gz", "gem5-patched-source.tar",
    "build/generated-headers.tar", "build/invoked-builder.sh",
    "build/stdenv-setup.sh", "build/native-compiler-inputs.json",
    "build/toolchain.json",
)


def document(path):
    with Path(path).open("rb") as stream:
        encoded = stream.read(MAX_METADATA_BYTES + 1)
    if not 0 < len(encoded) <= MAX_METADATA_BYTES:
        raise ValueError("source enrichment metadata exceeds its finite extent")
    result = json.loads(encoded)
    if type(result) is not dict:
        raise ValueError("source enrichment metadata is not an object")
    return result


def measure(path):
    """Streams a regular file with before/after byte-identity checks."""
    path = Path(path)
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_NATIVE_BYTES:
        raise ValueError("native source member is not a bounded regular file")
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
            count += len(block)
    after = path.stat(follow_symlinks=False)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("native source member changed during measurement")
    if count != before.st_size:
        raise ValueError("native source member extent differs")
    return {"bytes": count, "sha256": digest.hexdigest()}


def native_inventory(root):
    """Commits to the complete native source product before adding host sources."""
    rows = []
    pending = [Path(root)]
    total = 0
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            if len(rows) == MAX_NATIVE_FILES:
                raise ValueError("native source inventory exceeds its finite file allowance")
            relative = str(path.relative_to(root))
            mode = path.stat(follow_symlinks=False).st_mode
            if stat.S_ISDIR(mode):
                pending.append(path)
                rows.append({"path": relative, "kind": "directory"})
            elif stat.S_ISREG(mode):
                binding = measure(path)
                total += binding["bytes"]
                if total > MAX_NATIVE_BYTES:
                    raise ValueError("native source product exceeds its finite byte allowance")
                rows.append({"path": relative, "kind": "file", **binding})
            else:
                raise ValueError("native source inventory contains an unsupported member")
    return sorted(rows, key=lambda row: row["path"])


def write_document(path, value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if len(encoded) > MAX_METADATA_BYTES:
        raise ValueError("source enrichment output exceeds its finite metadata extent")
    with Path(path).open("xb") as stream:
        stream.write(encoded)


def host_inventory(inputs, source_path):
    """Checks retained host sources without treating them as native inputs."""
    if (inputs["public_recipe"]["name"] != "gem5.nix"
            or inputs["public_recipe"] not in inputs["host_recipes"]):
        raise ValueError("public recipe is not the retained gem5 recipe row")
    controls = native_inventory(Path(inputs["host_controls"]))
    if native_inventory(source_path / "build/controls") != controls:
        raise ValueError("retained host controls differ from their source input")
    names = set()
    for recipe in inputs["host_recipes"]:
        name = recipe["name"]
        if Path(name).name != name or name in (".", "..") or name in names:
            raise ValueError("retained host recipe has an invalid or duplicate name")
        names.add(name)
        if measure(source_path / "build/recipes" / name)["sha256"] != recipe["sha256"]:
            raise ValueError("retained host recipe differs from its source input")
    for field, name in (
        ("source_enrichment_recipe", "source-enrichment.nix"),
        ("source_enrichment_writer", "source-enrichment.py"),
        ("source_enrichment_check", "source-enrichment-check.py"),
    ):
        if measure(source_path / "build" / name) != measure(Path(inputs[field])):
            raise ValueError("retained enrichment source differs from its input")
    return controls


def bind(inputs_path, out_path, source_path, verify=False):
    """Records or rechecks an exact native producer and its public mirror."""
    inputs_path, out_path, source_path = map(Path, (inputs_path, out_path, source_path))
    inputs = document(inputs_path)
    if (inputs["schema"] != "crucible.gem5.native-wrapper-inputs.v1"
            or inputs["node_authority_qualified"] is not False):
        raise ValueError("unsupported native wrapper inputs or authority claim")
    native = Path(inputs["native_output"])
    native_source = Path(inputs["native_source"])
    original = measure(native / "bin/gem5")
    native_manifest = measure(native / "share/gem5/source-manifest.json")
    if measure(source_path / "build/native-source-manifest.json") != native_manifest:
        raise ValueError("retained original native source manifest differs")
    if measure(out_path / "bin/gem5") != original:
        raise ValueError("public wrapper changed the original native ELF bytes")
    for name in NATIVE_FILES:
        if measure(source_path / name) != measure(native_source / name):
            raise ValueError("source enrichment changed native corresponding source: " + name)
    if (source_path / "native-corresponding-source").readlink() != native_source:
        raise ValueError("public source does not retain the exact native source producer")
    controls = host_inventory(inputs, source_path)
    enrichment_builder = measure(source_path / "build/invoked-enrichment-builder.sh")
    origin_path = out_path / "share/gem5/native-origin.json"
    if verify:
        origin = document(origin_path)
        if (origin["schema"] != "crucible.gem5.native-wrapper-origin.v1"
                or origin["wrapper_compiled_native_program"] is not False
                or origin["node_authority_qualified"] is not False
                or origin["enrichment_builder"] != enrichment_builder
                or origin["native_source_manifest"] != native_manifest
                or origin["native_elf"] != original or origin["inputs"] != inputs):
            raise ValueError("native wrapper origin changed before final fixup")
        if document(source_path / "build/native-origin.json") != origin:
            raise ValueError("public native/source origins differ")
        manifest = document(out_path / "share/gem5/source-manifest.json")
        if manifest["recipeSha256"] != inputs["public_recipe"]["sha256"]:
            raise ValueError("public manifest recipe does not match its retained public source")
        if manifest["nativeCompilerOrigin"] != manifest_binding(inputs, original, origin_path):
            raise ValueError("public source manifest lost its native producer binding")
        return

    origin = {
        "schema": "crucible.gem5.native-wrapper-origin.v1",
        "inputs": inputs,
        "native_elf": original,
        "native_source_manifest": native_manifest,
        "native_source_inventory": native_inventory(native_source),
        "host_source_inventory": controls,
        "enrichment_builder": enrichment_builder,
        "wrapper_compiled_native_program": False,
        "node_authority_qualified": False,
    }
    write_document(origin_path, origin)
    write_document(source_path / "build/native-origin.json", origin)
    manifest_path = out_path / "share/gem5/source-manifest.json"
    manifest = document(manifest_path)
    # Existing source/profile hashes now include the actual producer/wrapper
    # relationship. The complete original native source remains independently
    # retained; this observation grants no native SourceReady authority.
    # Legacy closed-profile consumers bind the public recipe. Preserve native
    # recipe identity in the independently retained original manifest and origin.
    manifest["recipeSha256"] = inputs["public_recipe"]["sha256"]
    manifest["nativeCompilerOrigin"] = manifest_binding(inputs, original, origin_path)
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if len(encoded) > MAX_METADATA_BYTES:
        raise ValueError("public source manifest exceeds its finite metadata extent")
    manifest_path.write_bytes(encoded)


def manifest_binding(inputs, original, origin_path):
    """Includes the native/wrapper relationship in existing source identity."""
    return {
        "schema": "crucible.gem5.native-wrapper-origin.v1",
        "native_output": inputs["native_output"],
        "native_source": inputs["native_source"],
        "native_derivation": inputs["native_derivation"],
        "native_elf": original,
        "origin": measure(origin_path),
    }


def main():
    if len(sys.argv) not in (4, 5) or (len(sys.argv) == 5 and sys.argv[4] != "verify"):
        raise ValueError("expected wrapper-inputs public-output public-source [verify]")
    bind(*sys.argv[1:4], verify=len(sys.argv) == 5)


if __name__ == "__main__":
    main()
