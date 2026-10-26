"""Produces immutable comparison DATA for the two manual METHOD46 purposes.

The existing runtime manifest and normal Root profile helpers own ELF closure
resolution and file pinning. This producer joins their actual outputs to the
selected unit contracts and policy provenance. It creates no credentials,
approval, journal, TPM state or startup authority.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


MAXIMUM_PROFILE_BYTES = 1024 * 1024
MAXIMUM_RUNTIME_FILES = 512
PROFILE_PLACEHOLDER = "@AOS_METHOD46_INITIAL_STARTUP_PROFILE@"
PROFILE_FD = "aos-method46-initial-startup-profile"
PURPOSES = {
    "controller": (
        "aos-sandbox-controller-floor-initialize",
        "system_u:system_r:aos_method46_controller_initial_t",
        "aos-sandboxd",
    ),
    "storage": (
        "aos-sandbox-storage-floor-initialize",
        "system_u:system_r:aos_method46_storage_initial_t",
        "aos-storaged",
    ),
}


def load_helpers(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    if spec is None or spec.loader is None:
        raise ValueError("profile helper cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require_parameters(purpose, executable, normal_executable, uid, gid, approval, argv):
    """Checks bounded configuration DATA before traversing either closure."""
    initial_name, _, normal_name = PURPOSES[purpose]
    if executable.name != initial_name or normal_executable.name != normal_name:
        raise ValueError("selected executable differs from the fixed purpose")
    for identity in (uid, gid):
        if type(identity) is not int or not 0 < identity <= 0xFFFFFFFF:
            raise ValueError("Controller UID/GID must be nonzero exact uint32 values")
    if (not isinstance(approval, list) or len(approval) != 32
            or any(type(byte) is not int or not 0 <= byte <= 255 for byte in approval)
            or not any(approval)):
        raise ValueError("approval public key must contain exactly 32 public bytes")
    # The Rust consumer additionally decodes and rejects weak Ed25519 keys.
    # No private seed or index authentication enters this producer.
    if (not isinstance(argv, list) or not 1 <= len(argv) <= 128
            or any(not isinstance(argument, str) or "\0" in argument
                   or len(argument.encode()) > 1024 for argument in argv)
            or sum(len(argument.encode()) for argument in argv) > 32 * 1024
            or argv[0] != str(normal_executable)):
        raise ValueError("normal command exceeds its exact argument contract")


def require_unit_contract(unit: bytes) -> None:
    """Requires the exact normalized self-pin without discarding other bytes."""
    expected = f"OpenFile={PROFILE_PLACEHOLDER}:{PROFILE_FD}:read-only\n".encode()
    unit.decode("utf-8", errors="strict")
    if (not unit or len(unit) > 64 * 1024 or b"\0" in unit
            or unit.splitlines(keepends=True).count(expected) != 1):
        raise ValueError("normalized initializer unit is absent, ambiguous or oversized")


def require_policy_provenance(canonical: Path, source_pin: dict, canonical_pin: dict):
    entries = (canonical.parent / "provenance").read_text().splitlines()
    provenance = {}
    for entry in entries:
        key, value = entry.split("=", 1)
        if key in provenance:
            raise ValueError("canonical policy provenance repeats a field")
        provenance[key] = value
    if (provenance.get("source_policy_sha256") != bytes(source_pin["sha256"]).hex()
            or provenance.get("readback_sha256") != bytes(canonical_pin["sha256"]).hex()):
        raise ValueError("canonical policy differs from the selected source/readback")


def image_inventory(runtime, helpers, attrs, graph, executable, patchelf, readelf):
    paths = helpers.graph_paths(attrs, graph)
    if len(paths) > MAXIMUM_RUNTIME_FILES:
        raise ValueError("runtime closure exceeds the consumer's fixed bound")
    helpers.validate_symlinks(paths)
    if helpers.closure_owner(str(executable), {str(path) for path in paths}) is None:
        raise ValueError("selected executable is outside its exported closure")
    loader, files = runtime.runtime_files(helpers, paths, executable, patchelf, readelf)
    return {
        "executable": runtime.pin(executable),
        "loader": runtime.pin(loader),
        "runtime_files": files,
        "closure_roots": [str(path) for path in paths],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--purpose", choices=PURPOSES, required=True)
    for name in ("attrs", "runtime-profile-helpers", "elf-helpers", "executable",
                 "normal-executable", "normal-unit", "normal-argv", "pid1",
                 "canonical-policy", "source-policy", "effective-matrix",
                 "unit-contract", "approval-public-key", "patchelf", "readelf", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--controller-uid", type=int, required=True)
    parser.add_argument("--controller-gid", type=int, required=True)
    args = parser.parse_args()

    approval = json.loads(args.approval_public_key.read_text())
    argv = json.loads(args.normal_argv.read_text())
    require_parameters(args.purpose, args.executable, args.normal_executable,
                       args.controller_uid, args.controller_gid, approval, argv)
    unit = args.unit_contract.read_bytes()
    require_unit_contract(unit)
    initial_name, context, normal_name = PURPOSES[args.purpose]
    if args.normal_unit.name != f"{normal_name}.service":
        raise ValueError("normal unit fragment differs from the selected purpose")

    runtime = load_helpers(args.runtime_profile_helpers)
    helpers = load_helpers(args.elf_helpers)
    initial = image_inventory(runtime, helpers, args.attrs, "initialRuntimeClosure",
                              args.executable, args.patchelf, args.readelf)
    normal = image_inventory(runtime, helpers, args.attrs, "normalRuntimeClosure",
                             args.normal_executable, args.patchelf, args.readelf)
    require_parameters(args.purpose, Path(initial["executable"]["path"]),
                       Path(normal["executable"]["path"]), args.controller_uid,
                       args.controller_gid, approval, argv)
    source = runtime.pin(args.source_policy)
    canonical = runtime.pin(args.canonical_policy)
    require_policy_provenance(args.canonical_policy, source, canonical)
    if args.effective_matrix.stat().st_size == 0:
        raise ValueError("actual effective-policy checker output is empty")

    profile = {
        "format": "AOS_METHOD46_INITIAL_STARTUP_3",
        "unit": f"{initial_name}.service",
        "owner_context": context,
        **initial,
        "pid1": runtime.pin(args.pid1),
        "canonical_policy": canonical,
        "source_policy": source,
        "effective_matrix": runtime.pin(args.effective_matrix),
        "unit_sha256": list(hashlib.sha256(unit).digest()),
        "normal_unit_fragment": runtime.pin(args.normal_unit),
        "normal_image": {**normal, "argv": argv},
        "controller_uid": args.controller_uid,
        "controller_gid": args.controller_gid,
        "approval_public_key": approval,
    }
    data = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if len(data) > MAXIMUM_PROFILE_BYTES:
        raise ValueError("initial startup profile exceeds its exact byte bound")
    args.output.write_bytes(data)


if __name__ == "__main__":
    main()
