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
from collections import deque
import hashlib
import importlib.util
import json
import re
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
    loader_sonames = helpers.run_patchelf(patchelf, "--print-soname", loader)
    if loader_sonames is None or len(loader_sonames) > 1:
        raise ValueError("normal Root interpreter identity cannot be inspected")
    loader_soname = loader_sonames[0] if loader_sonames else None
    loaded = {}
    if loader_soname:
        expected = inventory.get(loader_soname)
        if expected is None or expected.resolve(strict=True) != loader:
            raise ValueError("normal Root interpreter differs from the unique inventory")
        loaded[loader_soname] = loader

    # glibc maps each object's immediate dependencies before walking their
    # children. Later edges reuse already mapped SONAMEs before searching.
    pending = deque([(executable.resolve(strict=True), ())])
    visited = set()
    files = {loader}
    while pending:
        elf, inherited = pending.popleft()
        if elf in visited:
            continue
        visited.add(elf)
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
        search = list(dict.fromkeys(own if has_runpath else [*own, *inherited]))
        child = tuple(search) if has_rpath else inherited
        for soname in needed:
            if soname in loaded:
                continue
            resolved = helpers.resolve_needed_dso(elf, soname, search, closure, inventory)
            loaded[soname] = resolved
            resolved_sonames = helpers.run_patchelf(patchelf, "--print-soname", resolved)
            if resolved_sonames is None or len(resolved_sonames) > 1:
                raise ValueError("normal Root dependency identity cannot be inspected")
            if resolved_sonames and resolved_sonames[0]:
                resolved_soname = resolved_sonames[0]
                expected = inventory.get(resolved_soname)
                if expected is None or expected.resolve(strict=True) != resolved:
                    raise ValueError("normal Root dependency differs from the unique inventory")
                loaded[resolved_soname] = resolved
            pending.append((resolved, child))
    return loader, [pin(path) for path in sorted(files)]


def normalize_unit(unit: bytes, profile_path: str) -> bytes:
    original = f"OpenFile={profile_path}:aos-normal-root-profile:read-only\n".encode()
    replacement = f"OpenFile={PROFILE_PLACEHOLDER}:aos-normal-root-profile:read-only\n".encode()
    lines = unit.splitlines(keepends=True)
    if lines.count(original) != 1:
        raise ValueError("unit must contain exactly its one profile OpenFile entry")
    return b"".join(replacement if line == original else line for line in lines)


def require_configured_identities(identities: object, cache_signer_gid: object) -> None:
    """Checks exact configured integers and the optional signer's UID/GID pair."""

    def uint32(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFFFFFFFF

    if not isinstance(identities, list) or len(identities) != 4 or not all(map(uint32, identities)):
        raise ValueError("configured identities are not four exact uint32 values")
    if identities[0] == 0 or identities[1] == 0:
        raise ValueError("normal Root Controller identity cannot be root")
    if not uint32(cache_signer_gid) or (identities[2] == 0) != (cache_signer_gid == 0):
        raise ValueError("Cache signer UID and GID must both be enabled or both be zero")


def require_environment_provision_binding(root: Path, unit: bytes) -> None:
    """Requires canonical selected-package DATA and one exact read-only unit pin."""
    if (len(root.parts) != 4 or root.parts[:3] != ("/", "nix", "store")
            or re.fullmatch(r"[0-9abcdfghijklmnpqrsvwxyz]{32}-aos-environment-provision-1", root.name) is None):
        raise ValueError("Environment provision is not its canonical immutable package root")
    binding = f"ReadOnlyPaths={root}\n".encode()
    if unit.splitlines(keepends=True).count(binding) != 1:
        raise ValueError("Environment provision differs from the selected Root binding")


def environment_provision_pin(root: Path, unit: bytes) -> dict:
    """Pins the actual selected rooted artifact and its exact unit binding."""
    root = root.resolve(strict=True)
    require_environment_provision_binding(root, unit)
    instruction = root / "instruction-v1"
    if instruction.is_symlink() or not instruction.is_file():
        raise ValueError("Environment instruction must be a fixed regular package file")
    return {"root": str(root), "instruction": pin(instruction)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("attrs", "helpers", "executable", "pid1", "canonical-policy",
                 "source-policy", "effective-matrix", "unit-contract", "identities",
                 "patchelf", "readelf", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--cache-signer-gid", type=int, required=True)
    parser.add_argument("--environment-provision-root", type=Path)
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
    require_configured_identities(identities, args.cache_signer_gid)
    unit = args.unit_contract.read_bytes()
    expected = f"OpenFile={PROFILE_PLACEHOLDER}:aos-normal-root-profile:read-only\n".encode()
    if unit.splitlines(keepends=True).count(expected) != 1 or len(unit) > 64 * 1024:
        raise ValueError("normalized unit contract is absent or oversized")

    profile = {"format": "AOS_NORMAL_ROOT_STARTUP_2", "unit": UNIT, "context": CONTEXT,
               "identities": identities, "cache_signer_gid": args.cache_signer_gid,
               "executable": pin(args.executable),
               "pid1": pin(args.pid1), "loader": pin(loader), "runtime_files": files,
               "closure_roots": [str(path) for path in paths],
               "canonical_policy": canonical_pin, "source_policy": source_pin,
               "effective_matrix": pin(args.effective_matrix),
               "unit_sha256": list(hashlib.sha256(unit).digest())}
    if args.environment_provision_root is not None:
        profile["format"] = "AOS_NORMAL_ROOT_STARTUP_3"
        profile["environment_provision"] = environment_provision_pin(args.environment_provision_root, unit)
    data = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if len(data) > MAXIMUM_PROFILE_BYTES:
        raise ValueError("normal Root startup profile exceeds its exact bound")
    args.output.write_bytes(data)


if __name__ == "__main__":
    main()
