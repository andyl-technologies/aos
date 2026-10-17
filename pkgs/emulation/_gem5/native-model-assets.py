# SPDX-License-Identifier: MIT
"""Measures finite private model assets before realizing any native device.

The returned hashes bind data custody, not execution authority. Admission also
requires an independently trusted source-owned model and installed asset policy.
"""

import hashlib
import json
import os
from pathlib import Path
import stat


MAX_ASSET_BYTES = 1024 * 1024 * 1024
MAX_CONFIG_BYTES = 64 * 1024 * 1024
MAX_CONFIG_FILES = 4096
MAX_CONFIG_DEPTH = 32


def decimal(value):
    if (not isinstance(value, str) or not value.isascii() or not value.isdecimal()
            or (len(value) > 1 and value.startswith("0"))):
        raise ValueError("model extent is not a canonical decimal string")
    return int(value)


def digest_file(path, maximum, allow_empty=False):
    """Hashes one finite private regular file through one unchanged descriptor."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid() or before.st_mode & 0o077
                or not 0 <= before.st_size <= maximum
                or (before.st_size == 0 and not allow_empty)):
            raise ValueError("model asset has nonprivate, shared or unbounded custody")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            body = stream.read(min(remaining, 1024 * 1024))
            if not body:
                raise ValueError("model asset was truncated during its finite read")
            digest.update(body)
            remaining -= len(body)
        if stream.read(1):
            raise ValueError("model asset grew beyond its preflight extent")
        after = os.fstat(stream.fileno())
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")
        if any(getattr(before, name) != getattr(after, name) for name in fields):
            raise ValueError("model asset changed while its bytes were measured")
        return {"bytes": str(before.st_size), "sha256": digest.hexdigest()}


def verify_asset(root, record, expected_name):
    """Verifies an exact source-owned asset role under the canonical owner root."""
    if not isinstance(record, dict) or set(record) != {"file", "bytes", "sha256"}:
        raise ValueError("model asset role has unknown or missing fields")
    if record["file"] != expected_name:
        raise ValueError("model asset role differs from its source-owned filename")
    expected_size = decimal(record["bytes"])
    if not 0 < expected_size <= MAX_ASSET_BYTES:
        raise ValueError("model asset extent exceeds its finite role budget")
    observed = digest_file(root / expected_name, expected_size)
    if observed != {"bytes": record["bytes"], "sha256": record["sha256"]}:
        raise ValueError("model asset body differs from its original data binding")
    return observed


def configuration_tree(root):
    """Measures a bounded Python configuration tree without symbolic aliases."""
    root = Path(root)
    rows = []
    total = 0
    directories = 0
    pending = [(root, 0)]
    while pending:
        directory, depth = pending.pop()
        directories += 1
        if directories + len(rows) > MAX_CONFIG_FILES:
            raise ValueError("model configuration total member census exceeds finite credit")
        metadata = directory.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077 or directory.resolve() != directory):
            raise ValueError("model configuration directory lacks canonical private custody")
        if depth > MAX_CONFIG_DEPTH:
            raise ValueError("model configuration depth exceeds finite credit")
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    pending.append((path, depth + 1))
                    if len(pending) > MAX_CONFIG_FILES:
                        raise ValueError("model configuration directory census exceeds credit")
                    continue
                if directories + len(rows) >= MAX_CONFIG_FILES:
                    raise ValueError("model configuration file census exceeds finite credit")
                observed = digest_file(path, MAX_CONFIG_BYTES - total, allow_empty=True)
                total += decimal(observed["bytes"])
                rows.append({"path": str(path.relative_to(root)), **observed})
    rows.sort(key=lambda row: row["path"])
    body = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return {"sha256": hashlib.sha256(body).hexdigest(), "bytes": str(total),
            "files": str(len(rows))}
