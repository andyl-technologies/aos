"""Retains and compares actual controller ring build-script products."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from verify_cache import execution_events, require_action


RING_REPOSITORY = "+aos_tools_repository+aos_controller_tests_crates__ring-0.17.14"
RING_LABEL = f"@@{RING_REPOSITORY}//:ring"
NATIVE_DIRECTORY = f"bazel-out/k8-fastbuild/bin/external/{RING_REPOSITORY}/_bs.out_dir"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def retain(execution_root, output):
    """Copies native products before the private action tree is removed."""
    source = execution_root / NATIVE_DIRECTORY
    if not source.is_dir():
        raise ValueError("actual ring build-script output directory is absent")
    files = {}
    for path in sorted(source.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(source)
        destination = output / "native-inputs" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        files[str(relative)] = sha256(destination)
    if len(files) != 32:
        raise ValueError(f"expected 32 ring native products, got {len(files)}")
    (output / "native-inputs.json").write_text(json.dumps(files, indent=2, sort_keys=True) + "\n")


def inspect(build, readelf, mapped):
    """Binds retained bytes to an uncached, sandboxed ring compiler action."""
    events = execution_events(build)
    action = require_action(events, RING_LABEL, "Rustc", hit=False)
    if action["runner"] != "linux-sandbox":
        raise ValueError("ring compiler action did not use linux-sandbox")
    build_script = require_action(events, f"@@{RING_REPOSITORY}//:_bs", "CargoBuildScriptRun", hit=False)
    if build_script["runner"] != "linux-sandbox":
        raise ValueError("ring build script did not use linux-sandbox")
    event = next(row for row in events if row["targetLabel"] == RING_LABEL and row["mnemonic"] == "Rustc")
    files = json.loads((build / "native-inputs.json").read_text())
    if len(files) != 32:
        raise ValueError("incomplete ring native product inventory")
    inputs = {row["path"]: row for row in event["inputs"]}
    for name, digest in files.items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("native product escapes the retained directory")
        path = build / "native-inputs" / relative
        if sha256(path) != digest:
            raise ValueError(f"retained native product changed: {name}")
        if inputs[f"{NATIVE_DIRECTORY}/{name}"]["digest"]["hash"] != digest:
            raise ValueError(f"retained product differs from actual Rustc input: {name}")
    archives = [row for row in event["actualOutputs"] if row["path"].endswith(".rlib")]
    if len(archives) != 1:
        raise ValueError("expected one actual ring Rust library output")
    archive = archives[0]["digest"]
    if archive["hashFunctionName"] not in ["SHA256", "SHA-256"] or int(archive["sizeBytes"]) <= 0:
        raise ValueError("ring output digest is not a nonempty SHA-256 artifact")

    dwarf = subprocess.run(
        [str(readelf), "--debug-dump=info", str(build / "native-inputs/0f1e39740815ef8c-mem.o")],
        check=True, capture_output=True, text=True,
    ).stdout
    locations = [line.strip() for line in dwarf.splitlines() if "DW_AT_name" in line or "DW_AT_comp_dir" in line]
    private_locations = [line for line in locations if "/sandbox/linux-sandbox/" in line]
    if mapped:
        if private_locations or not any("./bazel-out/" in line for line in locations):
            raise ValueError("mapped native object retains a private path or omits relative source locations")
    elif not private_locations:
        raise ValueError("ordinary compiler negative control did not expose a private sandbox path")
    return {
        "output": str(build), "native_inputs": files, "ring_rlib": archive,
        "compiler_action": action, "build_script_action": build_script,
        "dwarf_locations": locations,
        "execution_sha256": sha256(build / "evidence/execution.json"),
    }


def compare(builds, readelf):
    """Requires a failing ordinary control and identical mapped intermediates."""
    if len(set(builds.values())) != 4:
        raise ValueError("native qualification requires four distinct Nix outputs")
    records = {name: inspect(path, readelf, name.startswith("mapped")) for name, path in builds.items()}
    differences = {}
    for mode in ["ordinary", "mapped"]:
        first, second = [records[f"{mode}_{variant}"] for variant in ["strict", "conservative"]]
        if first["native_inputs"].keys() != second["native_inputs"].keys():
            raise ValueError("native product sets differ across inventory selections")
        changed = [name for name, digest in first["native_inputs"].items() if second["native_inputs"][name] != digest]
        same_archive = first["ring_rlib"] == second["ring_rlib"]
        if mode == "ordinary" and (len(changed) != 32 or same_archive):
            raise ValueError("ordinary compiler negative control did not reproduce all 33 intermediate differences")
        if mode == "mapped" and (changed or not same_archive or first["compiler_action"] != second["compiler_action"]):
            raise ValueError("mapped native products, Rust library, or compiler action identity differ")
        differences[mode] = changed
    return {
        "schema_version": 1, "status": "PASS", "builds": records,
        "differing_native_inputs": differences,
        "mapped_native_products_equal": True, "mapped_ring_rlib_equal": True,
        "mapped_ring_compiler_action_equal": True,
        "limits": [
            "Actual controller ring dependency only, built under deliberately different private output bases.",
            "No shared cache is mounted; byte and action identity do not prove a cache hit.",
            "This does not qualify full controller execution, whole-graph action parity, or production cutover.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    retain_parser = commands.add_parser("retain")
    retain_parser.add_argument("--execution-root", type=Path, required=True)
    retain_parser.add_argument("--output", type=Path, required=True)
    verify_parser = commands.add_parser("verify")
    names = [f"{mode}_{variant}" for mode in ["ordinary", "mapped"] for variant in ["strict", "conservative"]]
    for name in names:
        verify_parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    verify_parser.add_argument("--readelf", type=Path, required=True)
    verify_parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    if options.command == "retain":
        retain(options.execution_root, options.output)
    else:
        evidence = compare({name: getattr(options, name) for name in names}, options.readelf)
        options.output.mkdir(parents=True, exist_ok=True)
        (options.output / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
