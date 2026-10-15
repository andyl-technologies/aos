# SPDX-License-Identifier: MIT
"""Binds installed x86 model data and materializes a private native resource tree.

This helper never executes an emulator or issues a live source/capture permit.
The package wrapper fixes the installed manifest. A host must independently
join that source selection to its original child, channel and native issuer.
Partial preparation leaves the original output tree occupied and cannot retry.
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
ROLES = {
    "native_executable", "native_source_manifest", "controller", "entrypoint",
    "model", "publication_model", "asset_checker", "loader", "loader_check", "component_manifest",
    "kernel", "kernel_configuration", "pid1", "initramfs", "pid1_checker",
}
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
        raise ValueError("x86 bundle record has an unknown or missing field")
    return value


def decimal(value, maximum):
    if (type(value) is not str or not value.isascii() or not value.isdecimal()
            or (len(value) > 1 and value[0] == "0") or int(value) > maximum):
        raise ValueError("x86 bundle extent is not a bounded canonical decimal")
    return int(value)


def unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("x86 bundle object repeats a key")
        result[key] = value
    return result


def read_json(path):
    path = Path(path)
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_DOCUMENT:
            raise ValueError("x86 bundle document exceeds its data bound")
        body = stream.read(before.st_size + 1)
        if len(body) != before.st_size or identity(before) != identity(os.fstat(stream.fileno())):
            raise ValueError("x86 bundle document changed during its read")
    return json.loads(body, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite bundle data")))


def source_file(path, maximum=MAX_FILE, allow_empty=False):
    """Opens canonical readonly regular data; it grants no source authority."""
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("x86 bundle file has a symbolic or relative route")
    stream = os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb")
    before = os.fstat(stream.fileno())
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_mode & 0o222 or not 0 <= before.st_size <= maximum
            or (not allow_empty and not before.st_size)):
        stream.close()
        raise ValueError("x86 bundle file lacks finite readonly regular storage")
    return stream


def measure(path, maximum=MAX_FILE, allow_empty=False):
    with source_file(path, maximum, allow_empty) as stream:
        before = os.fstat(stream.fileno())
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            part = stream.read(min(1024 * 1024, remaining))
            if not part:
                raise ValueError("x86 bundle file shrank during measurement")
            digest.update(part)
            remaining -= len(part)
        if stream.read(1) or identity(before) != identity(os.fstat(stream.fileno())):
            raise ValueError("x86 bundle file changed during measurement")
    return {"path": str(path), "bytes": str(before.st_size), "sha256": digest.hexdigest()}


def relative_name(name):
    if type(name) is not str:
        raise ValueError("x86 configuration name must be a string")
    path = PurePosixPath(name)
    if (not name or not path.parts or path.is_absolute()
            or str(path) != name or any(part in (".", "..") for part in path.parts)
            or len(path.parts) > MAX_DEPTH):
        raise ValueError("x86 configuration name is not bounded and relative")
    return path


def configuration(root):
    root = Path(root)
    if not root.is_absolute() or root.resolve() != root:
        raise ValueError("x86 configuration root is not canonical")
    pending = [(root, 0)]
    directory_names = []
    rows = []
    total = directories = 0
    while pending:
        directory, depth = pending.pop()
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or depth > MAX_DEPTH:
            raise ValueError("x86 configuration has a non-directory or excessive depth")
        directories += 1
        if directories + len(rows) > MAX_CONFIG_FILES:
            raise ValueError("x86 configuration member bound exceeded")
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    pending.append((path, depth + 1))
                    directory_names.append(str(path.relative_to(root)))
                    if directories + len(rows) + len(pending) > MAX_CONFIG_FILES:
                        raise ValueError("x86 configuration directory bound exceeded")
                    continue
                if directories + len(rows) >= MAX_CONFIG_FILES:
                    raise ValueError("x86 configuration file bound exceeded")
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
        raise ValueError("x86 bundle helper module is already loaded")
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def build(specification):
    closed(specification, {"artifacts", "configuration_root"})
    closed(specification["artifacts"], ROLES)
    artifacts = {role: measure(path) for role, path in specification["artifacts"].items()}
    configs = configuration(specification["configuration_root"])
    components = read_json(artifacts["component_manifest"]["path"])
    if (components.get("schema") != "crucible.gem5.x86-model-components.v1"
            or components.get("model_id") != "x86-linux-pc-atomic-functional-v1"
            or components.get("native_dialect") != "crucible.gem5.x86-linux-native/1"
            or components.get("native_executable") != artifacts["native_executable"]["path"]
            or components.get("loader_component_check") != artifacts["loader_check"]["path"]):
        raise ValueError("x86 installed component producer bindings differ")
    for role, basename in (("controller", "native-controller.py"),
                           ("entrypoint", "native-controller-x86.py"),
                           ("model", "native-controller-x86-model.py"),
                           ("publication_model", "native-controller-models.py"),
                           ("asset_checker", "native-model-assets.py"),
                           ("loader", "x86-linux-loader.py")):
        if components.get("helper_hashes", {}).get(basename) != artifacts[role]["sha256"]:
            raise ValueError("x86 source-installed helper differs from its component: " + role)
    # These actual data validators precede any native construction. Their results
    # do not imply that the selected emulator has booted or captured this model.
    loader = load_helper("crucible_x86_bundle_loader", artifacts["loader"]["path"])
    plan = loader.validate_loader(Path(artifacts["kernel"]["path"]), Path(artifacts["initramfs"]["path"]))
    checker = load_helper("crucible_x86_bundle_pid1", artifacts["pid1_checker"]["path"])
    pid1 = checker.bounded_bytes(Path(artifacts["pid1"]["path"]), checker.MAXIMUM_INIT_BYTES)
    initramfs = checker.bounded_bytes(Path(artifacts["initramfs"]["path"]), checker.MAXIMUM_INIT_BYTES + 4096)
    checker.elf("x86_64", pid1)
    checker.archive(initramfs, pid1)
    return {"schema": "crucible.gem5.installed-x86-linux-assets.v1",
            "model_id": "x86-linux-pc-atomic-functional-v1",
            "native_dialect": "crucible.gem5.x86-linux-native/1",
            "artifacts": artifacts, "configuration": configs,
            "loader_geometry": plan.describe(), "qualification": dict(QUALIFICATION)}


def verify_data(document):
    closed(document, {"schema", "model_id", "native_dialect", "artifacts", "configuration", "loader_geometry", "qualification"})
    if (document["schema"] != "crucible.gem5.installed-x86-linux-assets.v1"
            or document["model_id"] != "x86-linux-pc-atomic-functional-v1"
            or document["native_dialect"] != "crucible.gem5.x86-linux-native/1"
            or document["qualification"] != QUALIFICATION
            or any(type(flag) is not bool for flag in document["qualification"].values())):
        raise ValueError("x86 installed asset model/dialect or qualification differs")
    closed(document["artifacts"], ROLES)
    for role, row in document["artifacts"].items():
        closed(row, {"path", "bytes", "sha256"})
        decimal(row["bytes"], MAX_FILE)
        if measure(row["path"]) != row:
            raise ValueError("x86 installed artifact bytes differ: " + role)
    original = document["configuration"]
    closed(original, {"root", "directories", "files", "binding"})
    if configuration(original["root"]) != original:
        raise ValueError("x86 installed configuration census or bytes differ")
    return document


def copy_file(row, target_directory, basename):
    """Writes one final private copy without a whole-asset transient allocation."""
    expected = decimal(row["bytes"], MAX_FILE)
    with source_file(row["path"], expected, allow_empty=True) as source:
        before = os.fstat(source.fileno())
        if before.st_size != expected:
            raise ValueError("x86 source extent changed before copy")
        descriptor = os.open(basename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=target_directory)
        with os.fdopen(descriptor, "wb") as target:
            digest = hashlib.sha256()
            remaining = expected
            while remaining:
                part = source.read(min(1024 * 1024, remaining))
                if not part:
                    raise ValueError("x86 source shrank during copy")
                digest.update(part)
                target.write(part)
                remaining -= len(part)
            if (source.read(1) or identity(before) != identity(os.fstat(source.fileno()))
                    or digest.hexdigest() != row["sha256"]):
                raise ValueError("x86 original source changed during copy")
    return {"file": basename, "bytes": row["bytes"], "sha256": row["sha256"]}


def prepare(document, resource_root):
    """Copies the fixed model data; a failed root stays occupied without retry."""
    verify_data(document)
    root = Path(resource_root)
    if not root.is_absolute() or root.resolve() != root:
        raise ValueError("x86 private resource root is not canonical")
    with ExitStack() as stack:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, root_fd)
        before = os.fstat(root_fd)
        if (before.st_uid != os.getuid() or before.st_mode & 0o077
                or not stat.S_ISDIR(before.st_mode)):
            raise ValueError("x86 private resource root is not private")
        # One observed entry is enough to refuse an occupied root. Enumerating
        # all caller-owned names would allocate scratch before this refusal.
        with os.scandir(root_fd) as entries:
            if next(entries, None) is not None:
                raise ValueError("x86 private resource root is occupied")
        assets = {}
        for role, basename in (("kernel", "kernel.elf"), ("initramfs", "initrd.img")):
            assets[role] = copy_file(document["artifacts"][role], root_fd, basename)
        os.mkdir("configs", mode=0o700, dir_fd=root_fd)
        for name in document["configuration"]["directories"]:
            relative = relative_name(name)
            with ExitStack() as directories:
                current = os.open("configs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
                directories.callback(os.close, current)
                for component in relative.parts:
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=current)
                    except FileExistsError:
                        pass
                    current = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                    directories.callback(os.close, current)
        for row in document["configuration"]["files"]:
            relative = relative_name(row["path"])
            with ExitStack() as directories:
                current = os.open("configs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
                directories.callback(os.close, current)
                for component in relative.parts[:-1]:
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=current)
                    except FileExistsError:
                        pass
                    current = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                    directories.callback(os.close, current)
                source = Path(document["configuration"]["root"]) / relative
                copy_file({**row, "path": str(source)}, current, relative.name)
        after = os.stat(root, follow_symlinks=False)
        if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                or after.st_uid != os.getuid() or after.st_mode & 0o077):
            raise ValueError("x86 private root changed during preparation")
    # Source data is checked again after the full copy; no original executable,
    # module or configuration mutation becomes an implicit launch selection.
    verify_data(document)
    artifacts = document["artifacts"]
    return {"schema": "crucible.gem5.x86-linux-prepared-data.v1",
            "resource_root": str(root),
            "model": {"schema": "crucible.gem5.x86-linux-model.v1", "assets": assets,
                      "configs": document["configuration"]["binding"]},
            "argv": [artifacts["native_executable"]["path"], "--listener-mode=off",
                     "--outdir=" + str(root), artifacts["entrypoint"]["path"]],
            "qualification": dict(QUALIFICATION)}


def write_document(document, destination):
    """Bounds serialized data before creating its exclusive final document."""
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if not 0 < len(encoded) <= MAX_DOCUMENT:
        raise ValueError("x86 bundle encoded document exceeds its readback bound")
    with Path(destination).open("xb") as stream:
        stream.write(encoded)


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "build":
        result = build(read_json(sys.argv[2]))
        write_document(result, sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == "inspect":
        verify_data(read_json(sys.argv[2]))
    elif len(sys.argv) == 4 and sys.argv[1] == "prepare":
        print(json.dumps(prepare(read_json(sys.argv[2]), sys.argv[3]), sort_keys=True, separators=(",", ":")))
    else:
        raise ValueError("expected build specification output or prepare installed-manifest private-root")


if __name__ == "__main__":
    main()
