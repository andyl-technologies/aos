# SPDX-License-Identifier: MIT
"""Binds a source-owned x86 root constructor without qualification promotion.

The fixed recipe selects every helper and original Linux asset. This writer
checks complete original files and loader/configuration data; it executes no
simulator and supplies no live process, common Ready or capture certificate.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys


MAX_DOCUMENT = 4 * 1024 * 1024
MAX_ARTIFACT = 2 * 1024 * 1024 * 1024
ROLES = {
    "native_executable", "controller", "entrypoint", "model", "board_model",
    "publication_model", "asset_checker", "loader", "auditor", "auditor_core",
    "python", "kernel", "initramfs", "image_guard", "dmtcp_launch",
    "dmtcp_restart", "mtcp_restart", "assets_manifest", "assets_verifier",
    "profile_writer", "profile_recipe", "native_source_manifest", "root_model_check",
    "mechanism_evidence", "witness", "image_witness", "proof_recipe",
}
QUALIFICATION = {
    "opaque_capture_mechanism_verified": True, "execution_admission_qualified": False,
    "full_system_admission_qualified": False, "device_parity_qualified": False,
    "guest_readiness_qualified": False, "cpu_timing_qualified": False,
}
ASSET_ROLES = {
    "native_executable": "native_executable", "controller": "controller",
    "board_model": "model", "publication_model": "publication_model",
    "asset_checker": "asset_checker", "loader": "loader", "kernel": "kernel",
    "initramfs": "initramfs", "native_source_manifest": "native_source_manifest",
}

RUNTIME_HELPER_ROLES = {
    "native-controller.py": "controller", "native-controller-models.py": "publication_model",
    "native-controller-x86-root.py": "entrypoint", "native-controller-x86-model.py": "board_model",
    "native-controller-x86-root-model.py": "model", "native-controller-x86-root-model-check.py": "root_model_check",
    "native-controller-x86-root-check.py": "witness", "native-controller-image-check.py": "image_witness",
    "native-model-assets.py": "asset_checker", "process-image-audit-core.py": "auditor_core",
    "x86-root-process-image-audit.py": "auditor", "x86-linux-loader.py": "loader",
}

QUALIFICATION_ROLES = {"source_manifest", "temporary_root_check"}
TEMPORARY_ROOT_CHECK = "native-controller-temporary-root-check.py"


def validate_qualification_document(source, controller_sha256, check_sha256):
    """Checks executed build inputs separately from native runtime artifacts."""
    if (type(source) is not dict
            or set(source) != {"schema", "controller_sha256", "checks"}
            or source["schema"] != "crucible.gem5.root-qualification-sources.v1"
            or source["controller_sha256"] != controller_sha256
            or source["checks"] != {TEMPORARY_ROOT_CHECK: check_sha256}):
        raise ValueError("Root qualification source receipt differs from installed inputs")


def qualification_inputs(selected, artifacts):
    """Measures the closed source-only inputs and checks their controller binding."""
    if type(selected) is not dict or set(selected) != QUALIFICATION_ROLES:
        raise ValueError("Root qualification input roles are incomplete or unknown")
    inputs = {role: measure(path) for role, path in selected.items()}
    source = read_document(inputs["source_manifest"]["path"])
    validate_qualification_document(
        source, artifacts["controller"]["sha256"],
        inputs["temporary_root_check"]["sha256"],
    )
    return inputs


def validate_helper_bindings(bindings, artifacts):
    """Requires every native runtime helper hash and refuses extra build inputs."""
    expected = {name: artifacts[role]["sha256"] for name, role in RUNTIME_HELPER_ROLES.items()}
    if bindings != expected:
        raise ValueError("x86 root proof helpers differ from installed constructor/auditor")


def fingerprint(metadata):
    return tuple(getattr(metadata, name) for name in (
        "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_nlink"))


def measure(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path or not str(path).startswith("/nix/store/"):
        raise ValueError("x86 root artifact lacks canonical installed custody")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_mode & 0o222 or not 0 < before.st_size <= MAX_ARTIFACT):
            raise ValueError("x86 root artifact exceeds immutable finite custody")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            part = stream.read(min(1024 * 1024, remaining))
            if not part:
                raise ValueError("x86 root artifact shrank during measurement")
            remaining -= len(part)
            digest.update(part)
        if stream.read(1) or fingerprint(before) != fingerprint(os.fstat(stream.fileno())):
            raise ValueError("x86 root artifact changed during measurement")
    return {"path": str(path), "length": str(before.st_size), "sha256": digest.hexdigest()}


def read_document(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_DOCUMENT:
            raise ValueError("x86 root document exceeds finite credit")
        data = stream.read(before.st_size + 1)
        if len(data) != before.st_size or fingerprint(before) != fingerprint(os.fstat(stream.fileno())):
            raise ValueError("x86 root document changed during read")
    return json.loads(data)


def load(name, path):
    if name in sys.modules:
        raise ValueError("x86 root helper was already loaded")
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def validate_witness(witness, artifacts, original):
    """Requires actual source-gone/twin recapture data bound to all original inputs."""
    if (type(witness) is not dict
            or witness.get("schema") != "crucible.gem5.shared-controller-x86-linux-root-mechanism.v1"
            or any(witness.get(name) is not True for name in (
                "original_linux_serial_birth_retained", "exclusive_full_position_stop",
                "original_retry_unchanged", "native_uart_birth_preserved", "source_group_reclaimed"))
            or any(witness.get(name) is not False for name in (
                "full_system_qualified", "complete_process_closure_qualified",
                "guest_readiness_qualified", "cpu_timing_qualified"))):
        raise ValueError("x86 root lacks its actual original source-gone mechanism witness")
    branches = witness.get("fresh_branches")
    if (type(branches) is not list or len(branches) != 2
            or {row.get("branch") for row in branches} != {"child-a", "child-b"}):
        raise ValueError("x86 root lacks two independent reconstructed owners")
    for row in branches:
        if any(row.get(name) is not True for name in (
                "fresh_capture_byte_closure", "original_held_receipt_unchanged",
                "exact_suffix", "source_namespace_absent", "group_reclaimed",
                "coexisting_fresh_groups_checked")):
            raise ValueError("x86 root fresh reconstruction mechanism is incomplete")
    anchors = branches[0].get("coexisting_kernel_anchors")
    if (type(anchors) is not list or len(anchors) != 2
            or branches[1].get("coexisting_kernel_anchors") != anchors
            or [row.get("fresh_kernel_anchor") for row in sorted(branches, key=lambda row: row["branch"])] != anchors):
        raise ValueError("x86 root proof lacks the same two simultaneously live kernel anchors")
    for anchor in anchors:
        if type(anchor) is not dict or set(anchor) != {"pid", "group", "start_ticks"}:
            raise ValueError("x86 root proof kernel anchor has unknown fields")
        for field in ("pid", "group", "start_ticks"):
            value = anchor[field]
            if (type(value) is not str or not value.isascii() or not value.isdecimal()
                    or len(value) > 20 or str(int(value)) != value or not 0 <= int(value) < 1 << 64
                    or (field != "start_ticks" and int(value) == 0)):
                raise ValueError("x86 root proof kernel anchor is not finite original data")
        if anchor["pid"] != anchor["group"]:
            raise ValueError("x86 root proof fresh owner has no private group")
    if anchors[0]["pid"] == anchors[1]["pid"]:
        raise ValueError("x86 root proof reused one native group for two branches")
    roles = ("native_executable", "image_guard", "dmtcp_launch", "dmtcp_restart", "mtcp_restart", "python")
    if witness.get("implementation_bindings") != {role: artifacts[role]["sha256"] for role in roles}:
        raise ValueError("x86 root proof used another native/tool implementation")
    validate_helper_bindings(witness.get("helper_bindings"), artifacts)
    scope = witness.get("model_scope")
    if (type(scope) is not dict or scope.get("model_id") != "x86-linux-pc-atomic-root-functional-v1"
            or scope.get("full_system") is not True
            or scope.get("configuration_tree") != original["configuration"]["binding"]
            or scope.get("loader") != original["loader_geometry"]
            or scope.get("guest_assets") != {
                role: {"bytes": artifacts[role]["length"], "sha256": artifacts[role]["sha256"]}
                for role in ("kernel", "initramfs")}
            or any(scope.get(name) is not False for name in (
                "complete_process_closure_qualified", "cpu_timing_qualified",
                "guest_readiness_qualified", "device_parity_qualified"))):
        raise ValueError("x86 root proof names another realized guest/model/loader scope")
    publications = witness.get("publications")
    if type(publications) is not list or len(publications) != 1:
        raise ValueError("x86 root proof omits its first held native byte")
    publication = publications[0]
    if (type(publication) is not dict or set(publication) != {
                "output_id", "tick", "event_ordinal", "tick_ordinal", "causal_parent", "facet", "terminal", "payload"}
            or publication["output_id"] != "1" or publication["causal_parent"] != "0"
            or publication["facet"] != "serial" or publication["terminal"] != "system.pc.com_1.device"
            or type(publication["payload"]) is not list or len(publication["payload"]) != 1
            or type(publication["payload"][0]) is not int or not 0 <= publication["payload"][0] <= 255):
        raise ValueError("x86 root proof changed its original UART/FIFO lineage")
    for field in ("tick", "event_ordinal", "tick_ordinal"):
        value = publication[field]
        if (type(value) is not str or not value.isascii() or not value.isdecimal()
                or len(value) > 20 or str(int(value)) != value or int(value) >= 1 << 64
                or (field != "tick" and int(value) == 0)):
            raise ValueError("x86 root proof has no finite original birth")
    if int(publication["tick_ordinal"]) > 500000:
        raise ValueError("x86 root proof exceeds installed superdense credit")


def manifest(specification):
    if type(specification) is not dict or set(specification) != {"artifacts", "qualification_inputs"}:
        raise ValueError("x86 root profile specification differs")
    selected = specification["artifacts"]
    if type(selected) is not dict or set(selected) != ROLES:
        raise ValueError("x86 root profile roles are missing or unknown")
    artifacts = {role: measure(path) for role, path in selected.items()}
    checks = qualification_inputs(specification["qualification_inputs"], artifacts)
    original = read_document(artifacts["assets_manifest"]["path"])
    verifier = load("crucible_x86_root_assets_verifier", artifacts["assets_verifier"]["path"])
    verifier.verify_data(original)
    for role, prior in ASSET_ROLES.items():
        row = artifacts[role]
        source = original["artifacts"][prior]
        if row != {"path": source["path"], "length": source["bytes"], "sha256": source["sha256"]}:
            raise ValueError("x86 root substituted an original Linux role: " + role)
    loader = load("crucible_x86_root_profile_loader", artifacts["loader"]["path"])
    geometry = loader.validate_loader(artifacts["kernel"]["path"], artifacts["initramfs"]["path"]).describe()
    if geometry != original["loader_geometry"]:
        raise ValueError("x86 root loader differs from the original Linux bundle")
    witness = read_document(artifacts["mechanism_evidence"]["path"])
    validate_witness(witness, artifacts, original)
    return {
        "schema": "crucible.gem5.installed-x86-root-profile-mechanism.v2",
        "policy_id": "x86-linux-pc-atomic-root-functional-v1",
        "native_dialect": "crucible.gem5.x86-linux-native/1",
        "host_abi": {"os": "linux", "architecture": "x86_64", "endian": "little",
                     "pointer_bits": "64", "page_bytes": "4096", "image_format": "dmtcp-4.2.0/mtcp"},
        "clock": {"native_tick_ps": "1", "mapping_id": "gem5/even-reaction-odd-publication-v1",
                  "maximum_microsteps": "1000000", "cpu_clock_hz": "100000000"},
        "model": {"board": "PC", "guest_isa": "x86_64", "cpu": "X86AtomicSimpleCPU",
                  "width": "16", "memory_bytes": "268435456", "memory": "SimpleMemory",
                  "configuration_tree": original["configuration"]["binding"], "loader_geometry": geometry,
                  "exposed_facets": [{"kind": "serial", "terminal": "system.pc.com_1.device",
                                       "direction": "output", "causal_parent": "0"}]},
        "configuration_root": original["configuration"]["root"],
        "qualification": dict(QUALIFICATION), "artifacts": artifacts,
        "qualification_inputs": checks,
    }


def main():
    if len(sys.argv) != 3:
        raise ValueError("expected fixed specification and manifest output")
    output = manifest(read_document(sys.argv[1]))
    path = Path(sys.argv[2])
    with path.open("x") as stream:
        stream.write(json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n")
    path.chmod(0o444)


if __name__ == "__main__":
    main()
