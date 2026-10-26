"""Compares installed files and immutable native runtime contracts across builders."""

import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess


def normalize(text, outputs):
    """Replaces only the package's own output identities in installed text."""
    for name, path in sorted(outputs.items(), key=lambda item: len(item[1]), reverse=True):
        text = text.replace(path, "@output:" + name + "@")
    return text


def elf_contract(path, readelf, loader):
    """Inspects actual dynamic imports and resolves them with the AOS loader."""
    dynamic = subprocess.check_output([str(readelf), "-d", str(path)], text=True)
    headers = subprocess.check_output([str(readelf), "-l", str(path)], text=True)
    loaded = subprocess.run([str(loader), "--list", str(path)], capture_output=True, text=True, timeout=30, check=True)
    if "not found" in loaded.stdout:
        raise ValueError("installed program has an unresolved library: " + str(path))
    libraries = sorted(re.findall(r" => (/[^ ]+)", loaded.stdout))
    if not libraries or any(not name.startswith("/nix/store/") for name in libraries):
        raise ValueError("installed program resolves a library outside the store: " + str(path))
    return {
        "needed": sorted(re.findall(r"\(NEEDED\).*\[(.+)\]", dynamic)),
        "interpreter": re.findall(r"Requesting program interpreter: (.+)\]", headers),
        "rpath_directories": sorted(directory for value in re.findall(r"\((?:RUNPATH|RPATH)\).*\[(.+)\]", dynamic)
                                    for directory in value.split(":")),
        "resolved_libraries": libraries,
    }


def inventory(outputs, readelf, loader):
    """Reads every installed entry except Cargo's driver-specific diagnostics."""
    result = {}
    for output, root in outputs.items():
        for path in sorted(Path(root).rglob("*")):
            relative = str(path.relative_to(root))
            if output == "out" and relative == "nix-support/cargo-build-messages.jsonl":
                continue
            key = output + "/" + relative
            if path.is_symlink():
                result[key] = {"kind": "symlink", "target": normalize(str(path.readlink()), outputs)}
            elif path.is_dir():
                result[key] = {"kind": "directory", "mode": stat.S_IMODE(path.stat().st_mode)}
            elif path.is_file():
                data = path.read_bytes()
                record = {"mode": stat.S_IMODE(path.stat().st_mode)}
                if data.startswith(b"\x7fELF"):
                    record.update(kind="elf", contract=elf_contract(path, readelf, loader))
                else:
                    record.update(kind="file", sha256=hashlib.sha256(normalize(data.decode(), outputs).encode()).hexdigest())
                result[key] = record
    if not result:
        raise ValueError("installed package has no files")
    return result


def runtime_closures(packages, attributes):
    """Requires complete realized graphs and rejects added runtime dependencies."""
    closures = {}
    for driver, outputs in packages.items():
        closures[driver] = {}
        for name, root in outputs.items():
            graph = attributes[driver + "_" + name]
            paths = {entry["path"] for entry in graph}
            if root not in paths or len(paths) != len(graph):
                raise ValueError("runtime graph has a missing root or duplicate nodes")
            if any(reference not in paths for entry in graph for reference in entry["references"]):
                raise ValueError("runtime graph omits a referenced store path")
            closures[driver][name] = sorted(normalize(path, outputs) for path in paths)

    changes = {}
    for name in packages["ordinary"]:
        before, after = [set(closures[driver][name]) for driver in ("ordinary", "bazel")]
        changes[name] = {"added": sorted(after - before), "removed": sorted(before - after)}
        if changes[name]["added"]:
            raise ValueError("Package output adds runtime dependencies: " + name + ": " + repr(changes[name]["added"]))
    return {"closures": closures, "changes": changes}


def compare_installed(before, after):
    """Allows only unused search-directory removal from otherwise equal contracts."""
    if before.keys() != after.keys():
        raise ValueError("installed package paths differ: " + repr(sorted(before.keys() ^ after.keys())))
    search_changes = {}
    for name, expected in before.items():
        actual = after[name]
        if expected.get("kind") == "elf" and actual.get("kind") == "elf":
            old_paths = set(expected["contract"]["rpath_directories"])
            new_paths = set(actual["contract"]["rpath_directories"])
            if new_paths - old_paths:
                raise ValueError("installed package adds library search directories: " + name)
            if any(not path.startswith("/nix/store/") or not Path(path).is_dir() for path in new_paths):
                raise ValueError("installed package has a nonimmutable library search directory: " + name)
            if old_paths != new_paths:
                search_changes[name] = {"removed": sorted(old_paths - new_paths), "added": []}
            # The same AOS loader must still select exactly the same libraries.
            # Keep both complete RPATH lists in the report for review.
            expected = {**expected, "contract": {key: value for key, value in expected["contract"].items()
                                                  if key != "rpath_directories"}}
            actual = {**actual, "contract": {key: value for key, value in actual["contract"].items()
                                              if key != "rpath_directories"}}
        if expected != actual:
            raise ValueError("installed package contract differs: " + name)
    return search_changes
