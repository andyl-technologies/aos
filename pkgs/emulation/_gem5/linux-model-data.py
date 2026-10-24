# SPDX-License-Identifier: MIT
"""Measures bounded installed Linux model data without executing a simulator.

Custody and configuration primitives retain the accepted x86 bundle rules.
Architecture-specific manifests and ELF geometry remain in their own helpers.
"""

from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys


MAX_FILE = 1024 * 1024 * 1024
MAX_DOCUMENT = 4 * 1024 * 1024
MAX_CONFIG_FILES = 4096
MAX_CONFIG_BYTES = 64 * 1024 * 1024
MAX_DEPTH = 32
QUALIFICATION = {
    "native_construction": False, "linux_boot": False, "device_parity": False,
    "exact_capture": False, "restored_continuation": False,
    "source_ready": False, "cpu_timing": False,
}


def identity(metadata):
    return tuple(getattr(metadata, name) for name in (
        "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
        "st_mode", "st_nlink",
    ))


def closed(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise ValueError("Linux bundle record has an unknown or missing field")
    return value


def decimal(value, maximum):
    if (type(value) is not str or not value.isascii() or not value.isdecimal()
            or (len(value) > 1 and value[0] == "0") or int(value) > maximum):
        raise ValueError("Linux bundle extent is not a bounded canonical decimal")
    return int(value)


def unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Linux bundle object repeats a key")
        result[key] = value
    return result


def read_json(path):
    path = Path(path)
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_DOCUMENT:
            raise ValueError("Linux bundle document exceeds its data bound")
        body = stream.read(before.st_size + 1)
        if len(body) != before.st_size or identity(before) != identity(os.fstat(stream.fileno())):
            raise ValueError("Linux bundle document changed during its read")
    return json.loads(body, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite bundle data")))


def source_file(path, maximum=MAX_FILE, allow_empty=False):
    """Opens canonical readonly regular data; it grants no source authority."""
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("Linux bundle file has a symbolic or relative route")
    stream = os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb")
    before = os.fstat(stream.fileno())
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_mode & 0o222 or not 0 <= before.st_size <= maximum
            or (not allow_empty and not before.st_size)):
        stream.close()
        raise ValueError("Linux bundle file lacks finite readonly regular storage")
    return stream


def measure(path, maximum=MAX_FILE, allow_empty=False):
    with source_file(path, maximum, allow_empty) as stream:
        before = os.fstat(stream.fileno())
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            part = stream.read(min(1024 * 1024, remaining))
            if not part:
                raise ValueError("Linux bundle file shrank during measurement")
            digest.update(part)
            remaining -= len(part)
        if stream.read(1) or identity(before) != identity(os.fstat(stream.fileno())):
            raise ValueError("Linux bundle file changed during measurement")
    return {"path": str(path), "bytes": str(before.st_size), "sha256": digest.hexdigest()}


def relative_name(name):
    if type(name) is not str:
        raise ValueError("Linux configuration name must be a string")
    path = PurePosixPath(name)
    if (not name or not path.parts or path.is_absolute()
            or str(path) != name or any(part in (".", "..") for part in path.parts)
            or len(path.parts) > MAX_DEPTH):
        raise ValueError("Linux configuration name is not bounded and relative")
    return path


def configuration(root):
    root = Path(root)
    if not root.is_absolute() or root.resolve() != root:
        raise ValueError("Linux configuration root is not canonical")
    pending = [(root, 0)]
    directory_names = []
    rows = []
    total = directories = 0
    while pending:
        directory, depth = pending.pop()
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or depth > MAX_DEPTH:
            raise ValueError("Linux configuration has a non-directory or excessive depth")
        directories += 1
        if directories + len(rows) > MAX_CONFIG_FILES:
            raise ValueError("Linux configuration member bound exceeded")
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    pending.append((path, depth + 1))
                    directory_names.append(str(path.relative_to(root)))
                    if directories + len(rows) + len(pending) > MAX_CONFIG_FILES:
                        raise ValueError("Linux configuration directory bound exceeded")
                    continue
                if directories + len(rows) >= MAX_CONFIG_FILES:
                    raise ValueError("Linux configuration file bound exceeded")
                row = measure(path, MAX_CONFIG_BYTES - total, allow_empty=True)
                total += int(row["bytes"])
                name = str(path.relative_to(root))
                relative_name(name)
                rows.append({"path": name, "bytes": row["bytes"], "sha256": row["sha256"]})
    rows.sort(key=lambda row: row["path"])
    encoded = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return {"root": str(root), "directories": sorted(directory_names), "files": rows, "binding": {
        "sha256": hashlib.sha256(encoded).hexdigest(), "bytes": str(total), "files": str(len(rows)),
    }}


def load_helper(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    if name in sys.modules:
        raise ValueError("Linux bundle helper module is already loaded")
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def copy_file(row, target_directory, basename):
    """Writes one final private copy without a whole-asset transient allocation."""
    expected = decimal(row["bytes"], MAX_FILE)
    with source_file(row["path"], expected, allow_empty=True) as source:
        before = os.fstat(source.fileno())
        if before.st_size != expected:
            raise ValueError("Linux source extent changed before copy")
        descriptor = os.open(basename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=target_directory)
        with os.fdopen(descriptor, "wb") as target:
            digest = hashlib.sha256()
            remaining = expected
            while remaining:
                part = source.read(min(1024 * 1024, remaining))
                if not part:
                    raise ValueError("Linux source shrank during copy")
                digest.update(part)
                target.write(part)
                remaining -= len(part)
            if (source.read(1) or identity(before) != identity(os.fstat(source.fileno()))
                    or digest.hexdigest() != row["sha256"]):
                raise ValueError("Linux original source changed during copy")
    return {"file": basename, "bytes": row["bytes"], "sha256": row["sha256"]}


def write_document(document, destination):
    """Bounds serialized data before creating its exclusive final document."""
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if not 0 < len(encoded) <= MAX_DOCUMENT:
        raise ValueError("Linux bundle encoded document exceeds its readback bound")
    with Path(destination).open("xb") as stream:
        stream.write(encoded)

