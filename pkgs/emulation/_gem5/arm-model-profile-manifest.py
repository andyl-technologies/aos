# SPDX-License-Identifier: MIT
"""Binds a source-built ARM mechanism bundle without granting public admission.

The build recipe supplies fixed installed artifacts and an actually executed
native witness. A consumer must independently authenticate the installed package
and live native capture before any exact-preservation authority can be issued.
"""

import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys


MAX_FILE_BYTES = 2 * 1024**3
MAX_DOCUMENT_BYTES = 4 * 1024**2
ARTIFACT_ROLES = {
    "native_executable", "controller", "entrypoint", "model", "publication_model",
    "asset_checker", "auditor", "auditor_core", "image_guard", "dmtcp_launch",
    "dmtcp_restart", "mtcp_restart", "python", "kernel", "initramfs", "firmware",
    "source_manifest", "source_recipe", "witness", "image_witness", "image_custody_check",
    "asset_check", "auditor_check", "native_source_manifest", "mechanism_evidence",
    "profile_writer", "profile_recipe",
    "terminal_runtime_manifest", "terminal_inventory_patch", "terminal_runtime_recipe",
    "terminal_inventory_witness",
}

SOURCE_ROLES = {
    "controller": "native-controller.py", "entrypoint": "native-controller-arm.py",
    "model": "native-controller-arm-model.py", "publication_model": "native-controller-models.py",
    "asset_checker": "native-model-assets.py", "asset_check": "native-model-assets-check.py",
    "auditor": "full-system-process-image-audit.py", "auditor_core": "process-image-audit-core.py",
    "auditor_check": "full-system-process-image-audit-check.py",
    "witness": "native-controller-arm-check.py", "image_witness": "native-controller-image-check.py",
    "image_custody_check": "native-controller-image-custody-check.py",
}


def fingerprint(metadata):
    return tuple(getattr(metadata, field) for field in (
        "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink", "st_mode"
    ))


def measure(path, allow_empty=False, maximum=MAX_FILE_BYTES):
    """Measures one immutable installed regular artifact through a stable FD."""
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path or not str(path).startswith("/nix/store/"):
        raise ValueError("ARM profile artifact is not an immutable installed path")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as reader:
        before = os.fstat(reader.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_mode & 0o222 or not 0 <= before.st_size <= maximum
                or (not allow_empty and before.st_size == 0)):
            raise ValueError("ARM profile artifact exceeds immutable finite custody")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            part = reader.read(min(1024**2, remaining))
            if not part:
                raise ValueError("ARM profile artifact shrank during measurement")
            remaining -= len(part)
            digest.update(part)
        after = os.fstat(reader.fileno())
        if reader.read(1) or fingerprint(before) != fingerprint(after):
            raise ValueError("ARM profile artifact changed during measurement")
    return {"path": str(path), "length": str(before.st_size), "sha256": digest.hexdigest()}


def read_document(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as reader:
        before = os.fstat(reader.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 0 < before.st_size <= MAX_DOCUMENT_BYTES):
            raise ValueError("ARM profile document exceeds finite credit")
        raw = reader.read(before.st_size + 1)
        if len(raw) != before.st_size or fingerprint(os.fstat(reader.fileno())) != fingerprint(before):
            raise ValueError("ARM profile document changed during read")
    return json.loads(raw)


def configuration_tree(root):
    """Measures the source-owned immutable directory using the native row codec."""
    root = Path(root)
    if root.resolve() != root or not str(root).startswith("/nix/store/"):
        raise ValueError("ARM board configuration lacks immutable source custody")
    rows = []
    total = 0
    pending = [(root, 0)]
    directories = 0
    while pending:
        directory, depth = pending.pop()
        directories += 1
        metadata = directory.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o222
                or depth > 32 or directories + len(rows) > 4096):
            raise ValueError("ARM configuration tree exceeds immutable finite custody")
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    pending.append((path, depth + 1))
                    if len(pending) > 4096:
                        raise ValueError("ARM configuration directory credit exhausted")
                    continue
                if directories + len(rows) >= 4096:
                    raise ValueError("ARM configuration file credit exhausted")
                observed = measure(path, allow_empty=True, maximum=64 * 1024**2 - total)
                total += int(observed["length"])
                if total > 64 * 1024**2:
                    raise ValueError("ARM configuration byte credit exhausted")
                rows.append({"path": str(path.relative_to(root)), "bytes": observed["length"],
                             "sha256": observed["sha256"]})
    rows.sort(key=lambda row: row["path"])
    body = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return {"files": str(len(rows)), "bytes": str(total),
            "sha256": hashlib.sha256(body).hexdigest()}


def validate_witness(witness):
    """Requires real source-gone twin evidence, keeping admission claims absent."""
    if (witness.get("schema") != "crucible.gem5.shared-controller-arm-linux-mechanism.v1"
            or witness.get("source_group_reclaimed") is not True
            or witness.get("original_linux_serial_birth_retained") is not True
            or witness.get("exclusive_full_position_stop") is not True
            or witness.get("original_retry_unchanged") is not True
            or witness.get("native_uart_birth_preserved") is not True):
        raise ValueError("ARM model lacks its actual stopped original-source witness")
    for key in ("full_system_qualified", "complete_process_closure_qualified",
                "guest_readiness_qualified", "cpu_timing_qualified"):
        if witness.get(key) is not False:
            raise ValueError("ARM mechanism witness overclaims installed admission")
    branches = witness.get("fresh_branches")
    if (not isinstance(branches, list) or len(branches) != 2
            or {branch.get("branch") for branch in branches} != {"child-a", "child-b"}):
        raise ValueError("ARM model lacks two independent reconstruction witnesses")
    for branch in branches:
        for key in ("fresh_capture_byte_closure", "original_held_receipt_unchanged",
                    "exact_suffix", "source_namespace_absent", "group_reclaimed"):
            if branch.get(key) is not True:
                raise ValueError("ARM fresh reconstruction witness is incomplete")
    publications = witness.get("publications")
    if (not isinstance(publications, list) or len(publications) != 1
            or publications[0].get("facet") != "serial"
            or publications[0].get("terminal") != "system.terminal"
            or publications[0].get("payload") != [91]
            or "guest_fd" in publications[0] or "guest_pid" in publications[0]):
        raise ValueError("ARM native serial birth was retagged or changed")
    publication = publications[0]
    if set(publication) != {
        "output_id", "tick", "event_ordinal", "tick_ordinal", "causal_parent",
        "facet", "terminal", "payload"
    }:
        raise ValueError("ARM original serial birth has unknown or missing fields")
    for key in ("output_id", "tick", "event_ordinal", "tick_ordinal", "causal_parent"):
        value = publication[key]
        if (not isinstance(value, str) or not value.isascii() or not value.isdecimal()
                or value.startswith("0") or len(value) > 20 or int(value) >= 2**64):
            raise ValueError("ARM original serial birth has no finite positive position")
    if int(publication["tick_ordinal"]) > 500000:
        raise ValueError("ARM original serial birth exceeds superdense mapping credit")


def manifest(specification):
    if (set(specification) != {"artifacts", "configuration_tree"}
            or set(specification["artifacts"]) != ARTIFACT_ROLES):
        raise ValueError("ARM installed artifact roles are incomplete or unknown")
    artifacts = {role: measure(path) for role, path in specification["artifacts"].items()}
    witness = read_document(artifacts["mechanism_evidence"]["path"])
    validate_witness(witness)
    source = read_document(artifacts["source_manifest"]["path"])
    if (source.get("schema") != "crucible.gem5.arm-controller-proof-source.v1"
            or source.get("execution_admission_qualified") is not False
            or source.get("full_system_admission_qualified") is not False
            or source.get("recipe_sha256") != artifacts["source_recipe"]["sha256"]
            or set(source.get("helpers", {})) != set(SOURCE_ROLES.values())):
        raise ValueError("ARM installed proof source inventory differs")
    for role, name in SOURCE_ROLES.items():
        if artifacts[role]["sha256"] != source["helpers"][name]:
            raise ValueError("ARM installed proof helper differs from executed source")
    runtime = read_document(artifacts["terminal_runtime_manifest"]["path"])
    if (runtime.get("schema") != "crucible.gem5.terminal-runtime-source.v1"
            or runtime.get("fullSystemQualified") is not False
            or runtime.get("patchSha256") != artifacts["terminal_inventory_patch"]["sha256"]
            or runtime.get("recipeSha256") != artifacts["terminal_runtime_recipe"]["sha256"]
            or runtime.get("witnessSha256") != artifacts["terminal_inventory_witness"]["sha256"]):
        raise ValueError("ARM native Terminal source extension differs from installed inventory")
    scope = witness["model_scope"]
    if (scope.get("model_id") != "arm-linux-vexpress-atomic-functional-v1"
            or scope.get("full_system") is not True):
        raise ValueError("ARM mechanism model identity differs")
    for role in ("kernel", "initramfs", "firmware"):
        if scope["guest_assets"][role] != {
            "bytes": artifacts[role]["length"], "sha256": artifacts[role]["sha256"]
        }:
            raise ValueError("ARM installed guest asset differs from actual model witness")
    configuration = configuration_tree(specification["configuration_tree"])
    if configuration != scope["configuration_tree"]:
        raise ValueError("ARM installed board configuration differs from actual witness")
    if (sys.byteorder != "little" or struct.calcsize("P") != 8
            or os.uname().sysname != "Linux" or os.uname().machine != "x86_64"
            or os.sysconf("SC_PAGE_SIZE") != 4096):
        raise ValueError("ARM native process image requires its fixed source-built host ABI")
    return {
        "schema": "crucible.gem5.installed-arm-profile-mechanism.v1",
        "policy_id": "arm-linux-vexpress-atomic-functional-v1",
        "native_dialect": "crucible.gem5.arm-linux-native/1",
        "host_abi": {"os": "linux", "architecture": "x86_64", "endian": "little",
                     "pointer_bits": "64", "page_bytes": "4096", "image_format": "dmtcp-4.2.0/mtcp"},
        "clock": {"native_tick_ps": "1", "mapping_id": "gem5/even-reaction-odd-publication-v1",
                  "maximum_microsteps": "1000000", "cpu_clock_hz": "100000000"},
        "model": {"board": "VExpress_GEM5_V2", "guest_isa": "aarch64",
                  "cpu": "ArmAtomicSimpleCPU", "width": "16", "memory_bytes": "268435456",
                  "memory": "SimpleMemory", "configuration_tree": scope["configuration_tree"],
                  "exposed_facets": [{"kind": "serial", "terminal": "system.terminal",
                                      "direction": "output"}]},
        "artifacts": artifacts,
        "configuration_root": specification["configuration_tree"],
        "witness": witness,
        "qualification": {"opaque_capture_mechanism_verified": True,
                          "execution_admission_qualified": False,
                          "full_system_admission_qualified": False,
                          "device_parity_qualified": False,
                          "guest_readiness_qualified": False, "cpu_timing_qualified": False},
    }


def main():
    specification = read_document(sys.argv[1])
    document = json.dumps(manifest(specification), sort_keys=True, separators=(",", ":")).encode()
    if len(document) > MAX_DOCUMENT_BYTES:
        raise ValueError("ARM installed profile exceeds finite metadata credit")
    destination = Path(sys.argv[2])
    with destination.open("xb") as output:
        output.write(document + b"\n")
        output.flush()
        os.fsync(output.fileno())


if __name__ == "__main__":
    main()
