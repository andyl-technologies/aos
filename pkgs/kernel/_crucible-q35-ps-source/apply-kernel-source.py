"""Apply the selected PS kernel chain using exact native source identities.

The compact inventory stores one complete roster and sparse stage changes.
Every role is reconstructed and checked before and after every actual patch;
compact storage does not narrow the source application policy.
"""

from pathlib import Path, PurePosixPath
import hashlib
import json
import re
import subprocess
import sys


def identity(path):
    data = path.read_bytes()
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def canonical_role(value):
    role = PurePosixPath(value)
    if role.is_absolute() or ".." in role.parts or str(role) != value or not role.parts:
        raise ValueError("Noncanonical native source role")
    return role


def validate_identity(value):
    if value is None:
        return
    if (set(value) != {"bytes", "sha256"} or type(value["bytes"]) is not int or
            value["bytes"] < 0 or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"])):
        raise ValueError("Invalid native source identity")


def reconstruct(inventory):
    if inventory["edition"] != 2:
        raise ValueError("Unsupported selected source inventory")
    for name in ["maximum_files", "maximum_source_bytes"]:
        if type(inventory[name]) is not int or inventory[name] <= 0:
            raise ValueError("Invalid selected source bound")

    current = {}
    for row in inventory["initial"]:
        role = str(canonical_role(row["path"]))
        if role in current:
            raise ValueError("Repeated initial native source role")
        validate_identity(row["identity"])
        current[role] = row["identity"]
    if not current or len(current) > inventory["maximum_files"]:
        raise ValueError("Native source role bound exceeded")

    stages = []
    for step in inventory["steps"]:
        validate_identity(step["patch"])
        if step["patch"] is None:
            raise ValueError("Missing selected patch identity")
        before = current.copy()
        changed = set()
        for row in step["changes"]:
            role = str(canonical_role(row["path"]))
            if role not in current or role in changed:
                raise ValueError("Unrostered or repeated native stage change")
            changed.add(role)
            validate_identity(row["before"])
            validate_identity(row["after"])
            if row["before"] != current[role] or row["before"] == row["after"]:
                raise ValueError("Broken exact native source ancestry")
            current[role] = row["after"]
        stages.append((before, current.copy()))
    return stages


def verify(root, roles, inventory):
    total = 0
    for role, expected in roles.items():
        path = root / role
        relative = Path(role)
        if any((root / parent).is_symlink() for parent in [relative, *relative.parents]):
            raise ValueError("Native source alias refused: " + role)
        if expected is None:
            if path.exists():
                raise ValueError("Native source existed before its original addition")
        elif (not path.is_file() or path.stat().st_size != expected["bytes"] or
              identity(path) != expected):
            raise ValueError("Changed exact native source: " + role)
        else:
            total += expected["bytes"]
    if total > inventory["maximum_source_bytes"]:
        raise ValueError("Native source byte bound exceeded")


def main():
    if sys.flags.optimize:
        raise RuntimeError("Optimized source verification refused")
    root = Path(sys.argv[1]).resolve()
    inventory_path = Path(__file__).resolve().parent / "kernel-patch-inventory.json"
    inventory = json.loads(inventory_path.read_text())
    stages = reconstruct(inventory)
    patches = [Path(value) for value in sys.argv[3:]]
    if len(patches) != len(stages):
        raise ValueError("Selected source patch count changed")

    # All ancestry and immutable patch bodies are admitted before source effects.
    for patch, step in zip(patches, inventory["steps"], strict=True):
        if (patch.is_symlink() or not patch.is_file() or
                patch.stat().st_size != step["patch"]["bytes"] or
                identity(patch) != step["patch"]):
            raise ValueError("Selected source patch bytes changed: " + step["name"])

    for patch, step, (before, after) in zip(patches, inventory["steps"], stages, strict=True):
        verify(root, before, inventory)
        result = subprocess.run(
            [sys.argv[2], "--batch", "--fuzz=0", "-p1", "-i", str(patch)],
            cwd=root, capture_output=True, timeout=30,
        )
        sys.stdout.buffer.write(result.stdout)
        sys.stderr.buffer.write(result.stderr)
        if result.returncode or re.search(rb"\b(offset|fuzz)\b", result.stdout + result.stderr, re.I):
            raise ValueError("Selected native source patch was not exact: " + step["name"])
        verify(root, after, inventory)
    print("Exact selected PS kernel source retained; link/guest/RUN/Ready unqualified")


if __name__ == "__main__":
    main()
