"""Capture a new, empty emulator persistence root before runtime startup.

The report records filesystem and installed configuration facts for independent
pre-authority review. It does not enumerate a running namespace, establish
provider behavior, or grant storage admission. Authenticated deployment identity
and live executable observations are collected separately after startup.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat


def hash_file(path):
    """Hash a stable regular artifact without retaining its contents."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("namespace artifact is not a regular file")
        digest = hashlib.sha256()
        size = 0
        while block := source.read(1024 * 1024):
            digest.update(block)
            size += len(block)
        after = os.fstat(source.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise ValueError("namespace artifact changed during observation")
    if size != before.st_size:
        raise ValueError("namespace artifact length changed during observation")
    return {"sha256": digest.hexdigest(), "byteSize": str(size)}


def observe_new_root(options):
    """Create and capture an empty root selected by the actual runtime config."""
    started = datetime.now(timezone.utc).isoformat()
    configuration_bytes = options.configuration_file.read_bytes()
    if len(configuration_bytes) > 1024 * 1024:
        raise ValueError("namespace configuration exceeds bounds")
    configuration = json.loads(configuration_bytes)
    root = options.persistence_root
    if not root.is_absolute() or str(root) != configuration["resourcePersistencePath"]:
        raise ValueError("namespace root differs from installed configuration")
    guard = configuration["durableObjects"]["HYBRID_OBJECT_GUARD"]
    if guard != {"className": "HybridObjectGuard", "useSQLite": True}:
        raise ValueError("guard binding differs from the reviewed fixture class")
    parent = root.parent
    parent_stat = parent.lstat()
    if (not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != os.getuid()
            or parent_stat.st_mode & 0o077 or parent.resolve() != parent):
        raise ValueError("namespace parent is not an owner-private directory")

    artifacts = {
        name: hash_file(getattr(options, name + "_file"))
        for name in ("source_nar", "distribution_nar", "wasm", "shim", "runner", "runtime")
    }
    configuration = hash_file(options.configuration_file)
    if configuration["sha256"] != hashlib.sha256(configuration_bytes).hexdigest():
        raise ValueError("namespace configuration changed during observation")
    source_path = str(options.source_store_path)
    if not source_path.startswith("/nix/store/") or not options.source_store_path.is_dir():
        raise ValueError("namespace source is not a realized store directory")
    # The package sets AOS_HUB_WORKER_SOURCE_DIGEST from the source store path.
    # This is a build-input observation until protected discovery confirms it.
    compiled_source = hashlib.sha256(os.fsencode(source_path)).hexdigest()

    os.mkdir(root, 0o700)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        entries = os.listdir(descriptor)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_mtime_ns", "st_ctime_ns")
        if entries or any(getattr(before, field) != getattr(after, field) for field in fields):
            raise ValueError("new namespace root changed during capture")
        if after.st_uid != os.getuid() or stat.S_IMODE(after.st_mode) != 0o700:
            raise ValueError("new namespace root has unexpected ownership or permissions")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

    return {
        "version": 1,
        "observationScope": "filesystem_before_runtime_start",
        "startedAt": started,
        "finishedAt": datetime.now(timezone.utc).isoformat(),
        "persistenceRoot": str(root),
        "directory": {
            "device": str(after.st_dev), "inode": str(after.st_ino),
            "ownerUid": str(after.st_uid), "permissions": "0700", "entries": entries,
            "mtimeNs": str(after.st_mtime_ns), "ctimeNs": str(after.st_ctime_ns),
        },
        "guardBinding": {"binding": "HYBRID_OBJECT_GUARD", **guard},
        "runtimeConfiguration": configuration,
        "sourceStorePath": source_path,
        "buildDerivedSourceDigest": compiled_source,
        "buildDerivedScriptVersion": "emulated-" + compiled_source,
        "artifacts": artifacts,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "configuration-file", "persistence-root", "source-store-path", "source-nar-file",
        "distribution-nar-file", "wasm-file", "shim-file", "runner-file", "runtime-file",
        "report-file",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    report = observe_new_root(options)
    descriptor = os.open(options.report_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(report, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise SystemExit("new emulator namespace observation failed") from None
