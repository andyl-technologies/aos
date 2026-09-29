"""Builds bounded, nonauthorizing normal-Root image/startup evidence.

The existing production checker must already have succeeded on the exact input
policy. This producer reuses the authenticated-runtime manifest's closure and
ELF resolution helpers; it does not invent a second SELinux or loader checker.
The selected unit replaces only its own profile OpenFile pathname with the
fixed placeholder, avoiding a derivation self-reference without omitting other
unit bytes. Runtime equality is a prerequisite, not client/read authority.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


MAXIMUM_PROFILE_BYTES = 1024 * 1024
MAXIMUM_RUNTIME_FILES = 512
PROFILE_PLACEHOLDER = "@AOS_NORMAL_ROOT_PROFILE@"
UNIT = "aos-sandbox-policy-authorityd.service"
CONTEXT = "system_u:system_r:aos_sandbox_policy_authority_t"


def load_runtime_helpers(path: Path):
    spec = importlib.util.spec_from_file_location("aos_runtime_manifest", path)
    if spec is None or spec.loader is None:
        raise ValueError("runtime-manifest helper cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pin(path: Path) -> dict:
    path = path.resolve(strict=True)
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").digest()
    return {"path": str(path), "sha256": list(digest)}


def runtime_files(helpers, paths, executable, patchelf, readelf):
    """Resolves actual DT_NEEDED edges with the existing exact closure helpers."""
    closure = {str(path) for path in paths}
    inventory = helpers.validate_dlopen_inventory(paths, patchelf, [])
    loader = Path(helpers.validate_elf_closure(paths, executable, patchelf, readelf))
    pending = [(executable.resolve(strict=True), ())]
    visited = set()
    files = {loader}
    while pending:
        elf, inherited = pending.pop()
        if (elf, inherited) in visited:
            continue
        visited.add((elf, inherited))
        files.add(elf)
        if len(files) > MAXIMUM_RUNTIME_FILES:
            raise ValueError("normal Root runtime exceeds the fixed file bound")
        needed = helpers.run_patchelf(patchelf, "--print-needed", elf)
        rpath = helpers.run_patchelf(patchelf, "--print-rpath", elf)
        if needed is None or rpath is None or len(rpath) > 1:
            raise ValueError("normal Root link member cannot be inspected")
        has_rpath, has_runpath = helpers.dynamic_search_tags(readelf, elf)
        if has_rpath and has_runpath:
            raise ValueError("normal Root link member has competing search tags")
        own = helpers.validate_search_directories(
            rpath[0].split(":") if rpath and rpath[0] else [], elf, closure
        )
        search = list(dict.fromkeys([*own, *inherited]))
        child = tuple(search) if has_rpath else inherited
        for soname in needed:
            resolved = helpers.resolve_needed_dso(elf, soname, search, closure, inventory)
            pending.append((resolved, child))
    return loader, [pin(path) for path in sorted(files)]


def normalize_unit(unit: bytes, profile_path: str) -> bytes:
    original = f"OpenFile={profile_path}:aos-normal-root-profile:read-only\n".encode()
    replacement = f"OpenFile={PROFILE_PLACEHOLDER}:aos-normal-root-profile:read-only\n".encode()
    lines = unit.splitlines(keepends=True)
    if lines.count(original) != 1:
        raise ValueError("unit must contain exactly its one profile OpenFile entry")
    return b"".join(replacement if line == original else line for line in lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("attrs", "helpers", "executable", "pid1", "canonical-policy",
                 "source-policy", "effective-matrix", "unit-contract", "identities",
                 "patchelf", "readelf", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    helpers = load_runtime_helpers(args.helpers)
    paths = helpers.graph_paths(args.attrs, "normalRootRuntimeClosure")
    helpers.validate_symlinks(paths)
    if helpers.closure_owner(str(args.executable), {str(path) for path in paths}) is None:
        raise ValueError("Root executable is outside the actual exported closure")
    loader, files = runtime_files(helpers, paths, args.executable, args.patchelf, args.readelf)

    # The canonical package must be the same production-policy input whose
    # actual all-source checker output this derivation retains.
    provenance = dict(line.split("=", 1) for line in
                      (args.canonical_policy.parent / "provenance").read_text().splitlines())
    source_pin = pin(args.source_policy)
    canonical_pin = pin(args.canonical_policy)
    if provenance.get("source_policy_sha256") != bytes(source_pin["sha256"]).hex():
        raise ValueError("canonical policy was generated from another input policy")
    if provenance.get("readback_sha256") != bytes(canonical_pin["sha256"]).hex():
        raise ValueError("canonical readback differs from its actual producer evidence")
    if args.effective_matrix.stat().st_size == 0:
        raise ValueError("actual effective-policy checker output is empty")
    identities = json.loads(args.identities.read_text())
    if len(identities) != 4 or any(not isinstance(value, int) or isinstance(value, bool)
                                  or not 0 <= value <= 0xFFFFFFFF for value in identities):
        raise ValueError("configured identities are not four exact uint32 values")
    if identities[0] == 0 or identities[1] == 0:
        raise ValueError("normal Root Controller identity cannot be root")
    unit = args.unit_contract.read_bytes()
    expected = f"OpenFile={PROFILE_PLACEHOLDER}:aos-normal-root-profile:read-only\n".encode()
    if unit.splitlines(keepends=True).count(expected) != 1 or len(unit) > 64 * 1024:
        raise ValueError("normalized unit contract is absent or oversized")

    profile = {"format": "AOS_NORMAL_ROOT_STARTUP_1", "unit": UNIT, "context": CONTEXT,
               "identities": identities, "executable": pin(args.executable),
               "pid1": pin(args.pid1), "loader": pin(loader), "runtime_files": files,
               "closure_roots": [str(path) for path in paths],
               "canonical_policy": canonical_pin, "source_policy": source_pin,
               "effective_matrix": pin(args.effective_matrix),
               "unit_sha256": list(hashlib.sha256(unit).digest())}
    data = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if len(data) > MAXIMUM_PROFILE_BYTES:
        raise ValueError("normal Root startup profile exceeds its exact bound")
    args.output.write_bytes(data)


if __name__ == "__main__":
    main()
