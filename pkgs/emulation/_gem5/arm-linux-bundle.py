# SPDX-License-Identifier: MIT
"""Binds ARM Linux data and prepares one private VExpress resource tree.

The complete sibling helper directory is retained by the producer. Preparation
does not launch a native simulator or issue common-node admission authority.
"""

from contextlib import ExitStack
import importlib.util
import os
from pathlib import Path
import stat
import sys
import json


specification = importlib.util.spec_from_file_location(
    "crucible_linux_asset_data", Path(__file__).with_name("linux-model-data.py"))
data = importlib.util.module_from_spec(specification)
specification.loader.exec_module(data)
closed = data.closed
read_json = data.read_json
write_document = data.write_document
ROLES = {"native_executable", "native_source_manifest", "entrypoint", "controller",
         "model", "publication_model", "asset_checker", "loader", "kernel",
         "kernel_configuration", "firmware", "firmware_source", "firmware_makefile",
         "pid1", "initramfs", "pid1_checker"}
HELPERS = {"controller": "native-controller.py", "entrypoint": "native-controller-arm.py",
           "model": "native-controller-arm-model.py", "publication_model": "native-controller-models.py",
           "asset_checker": "native-model-assets.py", "loader": "arm-linux-loader.py"}
REQUIRED_KERNEL = ("ARM64", "ARCH_VEXPRESS", "ARM_GIC_V3", "ARM_ARCH_TIMER", "OF",
                   "BLK_DEV_INITRD", "DEVTMPFS", "PROC_FS", "SYSFS", "BINFMT_ELF",
                   "SERIAL_AMBA_PL011", "SERIAL_AMBA_PL011_CONSOLE")


def validate_kernel_configuration(path):
    with Path(path).open("rb") as stream:
        body = stream.read(data.MAX_DOCUMENT + 1)
    if not body or len(body) > data.MAX_DOCUMENT:
        raise ValueError("ARM kernel configuration exceeds its finite bound")
    lines = set(body.decode("ascii").splitlines())
    if any("CONFIG_" + name + "=y" not in lines for name in REQUIRED_KERNEL):
        raise ValueError("ARM kernel lacks a required built-in boot dependency")


def build(selection):
    closed(selection, {"artifacts", "configuration_root", "helper_hashes"})
    closed(selection["artifacts"], ROLES)
    closed(selection["helper_hashes"], HELPERS.values())
    artifacts = {name: data.measure(path) for name, path in selection["artifacts"].items()}
    for role, filename in HELPERS.items():
        if artifacts[role]["sha256"] != selection["helper_hashes"][filename]:
            raise ValueError("ARM installed helper differs from selected source: " + role)
    validate_kernel_configuration(artifacts["kernel_configuration"]["path"])
    loader = data.load_helper("crucible_arm_bundle_loader", artifacts["loader"]["path"])
    geometry = loader.validate_loader(*(Path(artifacts[name]["path"])
                                       for name in ("kernel", "initramfs", "firmware")))
    checker = data.load_helper("crucible_arm_bundle_pid1", artifacts["pid1_checker"]["path"])
    pid1 = checker.bounded_bytes(Path(artifacts["pid1"]["path"]), checker.MAXIMUM_INIT_BYTES)
    initramfs = checker.bounded_bytes(Path(artifacts["initramfs"]["path"]), checker.MAXIMUM_INIT_BYTES + 4096)
    checker.elf("aarch64", pid1)
    checker.archive(initramfs, pid1)
    return {"schema": "crucible.gem5.installed-arm-linux-assets.v1",
            "model_id": "arm-linux-vexpress-atomic-functional-v1",
            "native_dialect": "crucible.gem5.arm-linux-native/1", "artifacts": artifacts,
            "configuration": data.configuration(selection["configuration_root"]),
            "loader_geometry": geometry, "qualification": dict(data.QUALIFICATION)}


def verify_data(document):
    closed(document, {"schema", "model_id", "native_dialect", "artifacts", "configuration",
                      "loader_geometry", "qualification"})
    if (document["schema"] != "crucible.gem5.installed-arm-linux-assets.v1"
            or document["model_id"] != "arm-linux-vexpress-atomic-functional-v1"
            or document["native_dialect"] != "crucible.gem5.arm-linux-native/1"
            or document["qualification"] != data.QUALIFICATION
            or any(type(value) is not bool for value in document["qualification"].values())):
        raise ValueError("ARM installed bundle has a foreign model or authority claim")
    closed(document["artifacts"], ROLES)
    for role, row in document["artifacts"].items():
        closed(row, {"path", "bytes", "sha256"})
        data.decimal(row["bytes"], data.MAX_FILE)
        if data.measure(row["path"]) != row:
            raise ValueError("ARM installed source body differs: " + role)
    original = document["configuration"]
    closed(original, {"root", "directories", "files", "binding"})
    if data.configuration(original["root"]) != original:
        raise ValueError("ARM installed configuration census differs")
    return document


def prepare(document, resource_root):
    """Copies original bound data once; a partial root cannot be retried."""
    verify_data(document)
    root = Path(resource_root)
    if not root.is_absolute() or root.resolve() != root:
        raise ValueError("ARM resource root is not canonical")
    with ExitStack() as stack:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, root_fd)
        before = os.fstat(root_fd)
        if (before.st_uid != os.getuid() or before.st_mode & 0o077
                or not stat.S_ISDIR(before.st_mode)):
            raise ValueError("ARM resource root is not private")
        with os.scandir(root_fd) as entries:
            if next(entries, None) is not None:
                raise ValueError("ARM resource root is already occupied")
        assets = {role: data.copy_file(document["artifacts"][role], root_fd, filename)
                  for role, filename in (("kernel", "kernel.elf"), ("initramfs", "initrd.img"),
                                         ("firmware", "boot_v2.arm64"))}
        # The unchanged ARM model emits its native DTB in this private child.
        os.mkdir("output", mode=0o700, dir_fd=root_fd)
        os.mkdir("configs", mode=0o700, dir_fd=root_fd)
        for name in document["configuration"]["directories"]:
            relative = data.relative_name(name)
            with ExitStack() as directories:
                current = os.open("configs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
                directories.callback(os.close, current)
                for part in relative.parts:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=current)
                    except FileExistsError:
                        pass
                    current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                    directories.callback(os.close, current)
        for row in document["configuration"]["files"]:
            relative = data.relative_name(row["path"])
            with ExitStack() as directories:
                current = os.open("configs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
                directories.callback(os.close, current)
                for part in relative.parts[:-1]:
                    current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                    directories.callback(os.close, current)
                data.copy_file({**row, "path": str(Path(document["configuration"]["root"]) / relative)},
                               current, relative.name)
        after = root.lstat()
        if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                or after.st_uid != os.getuid() or after.st_mode & 0o077):
            raise ValueError("ARM resource root changed during preparation")
    verify_data(document)
    return {"schema": "crucible.gem5.arm-linux-prepared-data.v1", "resource_root": str(root),
            "model": {"schema": "crucible.gem5.arm-linux-model.v1", "assets": assets,
                      "configs": document["configuration"]["binding"]},
            "argv": [document["artifacts"]["native_executable"]["path"], "--listener-mode=off",
                     "--outdir=" + str(root), document["artifacts"]["entrypoint"]["path"]],
            "qualification": dict(data.QUALIFICATION)}


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "build":
        write_document(build(read_json(sys.argv[2])), sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == "inspect":
        verify_data(read_json(sys.argv[2]))
    elif len(sys.argv) == 4 and sys.argv[1] == "prepare":
        print(json.dumps(prepare(read_json(sys.argv[2]), sys.argv[3]), sort_keys=True, separators=(",", ":")))
    else:
        raise ValueError("expected build selection output, inspect manifest, or prepare manifest root")


if __name__ == "__main__":
    main()
