"""Retain exact patched kernel source inputs for native component fixtures.

Only the regular files touched by the ordered patches are extracted from the
pinned archive. Every patch must apply without offset or fuzz. This constructs
source inputs; it neither builds nor installs a kernel or qualifies hardware.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile


MAXIMUM_FILES = 128
MAXIMUM_FILE_BYTES = 16 * 1024 * 1024
MAXIMUM_TOTAL_BYTES = 64 * 1024 * 1024
PREFIX = "linux-7.2.3/"


def patch_paths(patch):
    """Select checked native source names from actual unified file headers."""
    result = set()
    for line in patch.read_text().splitlines():
        if not line.startswith(("--- a/", "+++ b/")):
            continue
        relative = line[6:].split("\t", 1)[0]
        name = PurePosixPath(relative)
        if name.is_absolute() or ".." in name.parts or str(name) != relative:
            raise ValueError(f"noncanonical kernel source path: {relative}")
        result.add(relative)
    if not result:
        raise ValueError(f"patch has no checked source paths: {patch.name}")
    return result


def identity(data):
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def materialize(archive, output, patches, patch_tool):
    """Create a finite source tree and preserve actual ordered application logs."""
    if output.exists():
        raise ValueError("kernel source output already exists")
    paths = set().union(*(patch_paths(patch) for patch in patches))
    if len(paths) > MAXIMUM_FILES:
        raise ValueError("kernel source file reservation exceeds its bound")
    output.mkdir(parents=True)

    extracted = set()
    total_bytes = 0
    with tarfile.open(archive, "r:xz") as source:
        for member in source:
            if not member.name.startswith(PREFIX):
                continue
            relative = member.name[len(PREFIX):]
            if relative not in paths:
                continue
            if (not member.isfile() or relative in extracted or member.size < 0
                    or member.size > MAXIMUM_FILE_BYTES):
                raise ValueError(f"invalid kernel source member: {relative}")
            total_bytes += member.size
            if total_bytes > MAXIMUM_TOTAL_BYTES:
                raise ValueError("kernel source byte reservation exceeds its bound")

            stream = source.extractfile(member)
            if stream is None:
                raise ValueError(f"kernel source member has no bytes: {relative}")
            with stream:
                data = stream.read(member.size + 1)
            if len(data) != member.size:
                raise ValueError(f"kernel source member length changed: {relative}")
            target = output / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            extracted.add(relative)

    rows = []
    stage6_inventory = []
    for index, patch in enumerate(patches, start=1):
        if index == 7:
            # Older caller proofs use authentic stage-six native functions;
            # the byte bridge separately consumes the final stage-seven tree.
            snapshot = output / "stage6"
            for relative in sorted(paths):
                source = output / relative
                if source.is_file():
                    target = snapshot / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, target)
                    stage6_inventory.append({"path": relative, **identity(source.read_bytes())})

        result = subprocess.run(
            [str(patch_tool), "--batch", "--fuzz=0", "-p1", "-i", str(patch.resolve())],
            cwd=output, capture_output=True, timeout=30,
        )
        log = result.stdout + result.stderr
        (output / f"stage{index}-apply.log").write_bytes(log)
        if result.returncode != 0 or re.search(rb"\b(?:offset|fuzz)\b", log, re.I):
            raise ValueError(f"kernel stage{index} failed exact source application")
        rows.append({"name": patch.name, **identity(patch.read_bytes())})

    inventory = []
    for relative in sorted(paths):
        target = output / relative
        if not target.is_file():
            raise ValueError(f"patched source closure is incomplete: {relative}")
        inventory.append({"path": relative, **identity(target.read_bytes())})
    (output / "component-source-inputs.json").write_text(json.dumps({
        "schema": "crucible-kvm-component-source-inputs/v1",
        "kernel_release": "7.2.3", "ordered_patches": rows,
        "stage6_files": stage6_inventory,
        "files": inventory, "hardware_qualification": False,
    }, indent=2) + "\n")
    print(f"Retained {len(inventory)} actual kernel source files; seven exact stages, no hardware qualification")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("patch_tool", type=Path)
    parser.add_argument("patches", type=Path, nargs=7)
    arguments = parser.parse_args()
    materialize(arguments.archive, arguments.output, arguments.patches, arguments.patch_tool)


if __name__ == "__main__":
    main()
