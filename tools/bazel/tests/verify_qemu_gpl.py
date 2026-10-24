"""Compares retained GPL production artifacts with the source-built Cargo baseline.

ELF identity, dynamic dependency names, plugin exports, embedded admission
identities, and gateway argument rejection are independent of the remaining
live QEMU, process-harness, and complete installed-closure qualifications.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def artifact(build, component, destination):
    """Selects a completed, digest-checked artifact by its declared package label."""
    label = f"//crates/crucible/qemu/{component}:compiler_artifact"
    identifier = json.loads((build / "packages/index.json").read_text())[label]
    if identifier != hashlib.sha256(label.encode()).hexdigest():
        raise ValueError("invalid compiler artifact package identity")
    directory = build / "packages" / identifier
    manifest = json.loads((directory / "manifest.json").read_text())
    if (manifest["label"], manifest["name"], manifest["license"], manifest["license_domain"]) != (
        label, component, "GPL-2.0-only", "gpl-qemu",
    ):
        raise ValueError("compiler artifact has an unexpected GPL package identity")
    entries = [entry for entry in manifest["artifacts"] if entry["destination"] == destination]
    if len(entries) != 1:
        raise ValueError("compiler artifact must have one declared destination")
    path = directory / "files" / destination
    if hashlib.sha256(path.read_bytes()).hexdigest() != entries[0]["sha256"]:
        raise ValueError("compiler artifact bytes differ from their completed export")
    return path


def elf(path, readelf):
    """Retains raw ELF observations and extracts comparison fields."""
    raw = {
        name: subprocess.check_output([str(readelf), flag, str(path)], text=True)
        for name, flag in [
            ("header", "-h"), ("program_headers", "-lW"),
            ("dynamic", "-dW"),
        ]
    }
    # Wide output is required for exact exported Rust and QEMU symbol names.
    raw["symbols"] = subprocess.check_output(
        [str(readelf), "--dyn-syms", "--wide", str(path)], text=True,
    )
    identity = {}
    for field in ["Class", "Data", "OS/ABI", "Type", "Machine"]:
        match = re.search(r"^\s*" + re.escape(field) + r":\s+(.+)$", raw["header"], re.MULTILINE)
        if match is None:
            raise ValueError("ELF header omitted " + field)
        identity[field] = match[1]
    needed = re.findall(r"\(NEEDED\).*?\[([^]]+)\]", raw["dynamic"])
    if len(needed) != len(set(needed)):
        raise ValueError("ELF dynamic dependencies contain duplicates")
    exports = []
    for line in raw["symbols"].splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].endswith(":"):
            _, _, size, kind, binding, visibility, section, name = fields[:8]
            if binding == "GLOBAL" and visibility == "DEFAULT" and section not in {"UND", "ABS"}:
                exports.append({"name": name, "kind": kind, "size": int(size, 0)})
    return {
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "identity": identity, "needed": sorted(needed),
        "interpreter": re.findall(r"Requesting program interpreter: ([^]]+)", raw["program_headers"]),
        "runtime_search_paths": re.findall(r"\((?:RPATH|RUNPATH)\).*?\[([^]]+)\]", raw["dynamic"]),
        "exports": sorted(exports, key=lambda entry: entry["name"]), "raw": raw,
    }


def verify(build, cargo, abi, readelf):
    """Checks ELF comparisons and actual argument-rejection behavior."""
    paths = {
        "plugin": artifact(build, "crucible-qemu-plugin", "lib/libcrucible_qemu_plugin.so"),
        "gateway": artifact(build, "crucible-qemu-debug-gateway", "bin/crucible-debug-gateway"),
    }
    baseline = {
        "plugin": cargo / "artifacts/libcrucible_qemu_plugin.so",
        "gateway": cargo / "artifacts/crucible-debug-gateway",
    }
    identities = json.loads((abi / "identity.json").read_text())
    artifacts = {}
    for name in paths:
        actual, expected = elf(paths[name], readelf), elf(baseline[name], readelf)
        for field in ["identity", "needed", "interpreter"]:
            if actual[field] != expected[field]:
                raise ValueError(f"{name} ELF {field} differs from Cargo")
        artifacts[name] = {"bazel": actual, "cargo": expected}

    plugin, reference = artifacts["plugin"]["bazel"], artifacts["plugin"]["cargo"]
    if not plugin["identity"]["Type"].startswith("DYN ") or plugin["interpreter"]:
        raise ValueError("plugin must be a shared object without an executable interpreter")
    # Function sizes change with code layout; their exported names and kinds
    # are the ABI surface. Keep actual sizes in the retained observations.
    def export_identity(value):
        return [(entry["name"], entry["kind"]) for entry in value["exports"]]

    if export_identity(plugin) != export_identity(reference):
        raise ValueError("plugin dynamic exports differ from Cargo")
    exported = {entry["name"]: entry for entry in plugin["exports"]}
    if (exported.get("qemu_plugin_install", {}).get("kind") != "FUNC"
            or exported.get("qemu_plugin_version", {}).get("size") != 4):
        raise ValueError("plugin omitted a required QEMU entry point")
    for name, path in [("bazel", paths["plugin"]), ("cargo", baseline["plugin"])]:
        contents = path.read_bytes()
        for key in ["qemu_build_id", "atomic_patch_sha256", "shmem_header_sha256"]:
            if identities[key].encode() not in contents:
                raise ValueError(f"{name} plugin omitted checked admission identity: {key}")

    cases = []
    # Usage includes argv[0]; invoke each retained executable with the same
    # public command name so differing store paths do not change the fixture.
    for arguments in [[], ["--help"], ["--control-socket", "relative"],
                      ["--control-socket", "/unused-control", "--owner-gdb-socket", "relative"]]:
        actual, expected = [subprocess.run(
            ["crucible-debug-gateway", *arguments], executable=str(path),
            capture_output=True, text=True, timeout=10,
        ) for path in [paths["gateway"], baseline["gateway"]]]
        if (actual.returncode, actual.stdout, actual.stderr) != (expected.returncode, expected.stdout, expected.stderr):
            raise ValueError("gateway argument rejection differs from Cargo: " + repr(arguments))
        if actual.returncode == 0:
            raise ValueError("gateway accepted invalid arguments")
        cases.append({"arguments": arguments, "exit_code": actual.returncode,
                      "stdout": actual.stdout, "stderr": actual.stderr})
    return {
        "schema_version": 1,
        "build": str(build), "cargo": str(cargo), "abi_bundle": str(abi),
        "readelf": str(readelf),
        "status": "PASS: ELF identity, dynamic dependencies, plugin exports and admission identities, gateway argument rejection",
        "artifacts": artifacts, "abi": identities, "gateway_cases": cases,
        "limits": [
            "Runtime search paths are retained separately and are not required to be identical.",
            "Live QEMU loading, protocol lifecycle tests, complete installed closures, and production cutover remain independent gates.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["build", "cargo", "abi", "readelf", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    result = verify(options.build, options.cargo, options.abi, options.readelf)
    options.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
