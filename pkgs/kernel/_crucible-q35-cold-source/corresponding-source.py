"""Retain the selected kernel's same-build corresponding source.

The original patched tree is captured before generated keys or object files.
Final config, generated interfaces and actual Kbuild command records are kept
separately. Source retention is not a runtime or node-readiness qualification.
"""

from pathlib import Path
import hashlib
import json
import os
import shutil
import stat
import sys


def file_identity(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while body := stream.read(1024 * 1024):
            digest.update(body)
            size += len(body)
    return {"bytes": size, "sha256": digest.hexdigest()}


def write_json(path, value):
    if path.exists():
        raise ValueError("Source record cannot be renewed: " + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def source_roster(root):
    rows = []
    for path in sorted(root.rglob("*")):
        mode = path.lstat().st_mode
        role = str(path.relative_to(root))
        if stat.S_ISLNK(mode):
            rows.append({"path": role, "kind": "symlink", "target": os.readlink(path)})
        elif stat.S_ISREG(mode):
            rows.append({"path": role, "kind": "file", "mode": stat.S_IMODE(mode),
                         **file_identity(path)})
        elif not stat.S_ISDIR(mode):
            raise ValueError("Non-source filesystem object refused: " + role)
    return rows


def copy_original(source, destination):
    if not source.is_dir() or source.is_symlink() or destination.exists():
        raise ValueError("Original source tree must be independent and uncreated")
    shutil.copytree(source, destination, symlinks=True)


def verify_original_inputs(kernel, companion):
    rows = json.loads((companion / "patched-source.json").read_text())["native"]
    for row in rows:
        path = kernel / row["path"]
        if row["kind"] == "symlink":
            if not path.is_symlink() or os.readlink(path) != row["target"]:
                raise ValueError("Original source alias changed: " + row["path"])
        elif (path.is_symlink() or not path.is_file() or
              file_identity(path) != {name: row[name] for name in ["sha256", "bytes"]}):
            raise ValueError("Original source changed during Kbuild: " + row["path"])


def prepare(kernel, companion, aos_source, source_archive, fixtures):
    companion.mkdir(parents=True)
    copy_original(kernel, companion / "native")
    copy_original(aos_source, companion / "build/aos")
    shutil.copyfile(source_archive, companion / "upstream.tar.xz")
    shutil.copytree(fixtures, companion / "patches", symlinks=True)
    write_json(companion / "patched-source.json", {
        "edition": 1,
        "upstream": file_identity(source_archive),
        "native": source_roster(companion / "native"),
        "aos_build_source": source_roster(companion / "build/aos"),
    })


def configured(kernel, companion):
    destination = companion / "configured"
    destination.mkdir()
    shutil.copyfile(kernel / ".config", destination / "config")
    if (kernel / ".extra-config").exists():
        shutil.copyfile(kernel / ".extra-config", destination / "extra-config")
    for role in ["include/generated", "include/config", "arch/x86/include/generated",
                 "arch/arm64/include/generated"]:
        path = kernel / role
        if path.is_dir():
            target = destination / role
            target.parent.mkdir(parents=True, exist_ok=True)
            copy_original(path, target)
    write_json(destination / "configuration.json", {
        "config": file_identity(kernel / ".config"),
        "tools": {name: os.environ.get(name, "") for name in
                  ["CC", "CXX", "LD", "AR", "NM", "STRIP", "CONFIG_SHELL", "NIX_BUILD_CORES"]},
        "signing": "Private signing keys are not corresponding-source inputs; separately supply authorized signing material when rebuilding signed artifacts.",
    })


def built(kernel, companion):
    verify_original_inputs(kernel, companion)
    destination = companion / "kbuild"
    destination.mkdir()
    commands = []
    for path in sorted(kernel.rglob("*.cmd")):
        if not path.is_file() or path.is_symlink():
            raise ValueError("Kbuild command must be an original regular file")
        role = str(path.relative_to(kernel))
        target = destination / role
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        commands.append({"path": role, **file_identity(path)})
    if not commands:
        raise ValueError("Actual Kbuild commands are missing")
    for role in ["Module.symvers", "modules.order", "modules.builtin",
                 "modules.builtin.modinfo", "System.map"]:
        path = kernel / role
        if path.is_file():
            shutil.copyfile(path, destination / role)
    for role in ["include/generated", "include/config", "arch/x86/include/generated",
                 "arch/arm64/include/generated"]:
        path = kernel / role
        if path.is_dir():
            target = destination / "generated" / role
            target.parent.mkdir(parents=True, exist_ok=True)
            copy_original(path, target)
    write_json(destination / "commands.json", commands)


def finish(companion, runtime, development, vmlinux, source_output):
    configs = sorted((runtime / "boot").glob("config-*"))
    if len(configs) != 1:
        raise ValueError("Exactly one published kernel config is required")
    config = configs[0]
    if file_identity(config) != file_identity(companion / "configured/config"):
        raise ValueError("Published kernel config differs from retained build config")
    images = sorted((runtime / "boot").glob("vmlinuz-*"))
    elfs = sorted((vmlinux / "boot").glob("vmlinux-*"))
    modules = sorted((runtime / "lib/modules").rglob("*.ko"))
    if len(images) != 1 or len(elfs) != 1 or not modules:
        raise ValueError("Complete image, ELF and module outputs are required")
    records = [{"output": "out", "path": str(path.relative_to(runtime)), **file_identity(path)}
               for path in [*images, config, *modules]]
    records += [{"output": "vmlinux", "path": str(path.relative_to(vmlinux)), **file_identity(path)}
                for path in elfs]
    write_json(companion / "SOURCE-MANIFEST.json", {
        "edition": 1,
        "scope": "Complete same-build selected Q35 constructor kernel corresponding source; active execution and Ready remain unsupported.",
        "patched_source_record": file_identity(companion / "patched-source.json"),
        "configuration_record": file_identity(companion / "configured/configuration.json"),
        "kbuild_commands": file_identity(companion / "kbuild/commands.json"),
        "artifacts": records,
    })
    for output in [runtime, development, vmlinux]:
        support = output / "nix-support"
        support.mkdir(exist_ok=True)
        (support / "linux-crucible-corresponding-source").write_text(str(source_output) + "\n")
        (support / "linux-crucible-build-info").write_text(
            "package=linux-controller-q35-cold-kernel\n"
            "corresponding_source_required=true\n"
            "source_manifest=share/aos/linux-controller-corresponding-source/SOURCE-MANIFEST.json\n"
            "active_execution_supported=false\n")


def main():
    operation = sys.argv[1]
    paths = [Path(value).absolute() for value in sys.argv[2:]]
    if operation == "prepare" and len(paths) == 5:
        prepare(*paths)
    elif operation == "configured" and len(paths) == 2:
        configured(*paths)
    elif operation == "built" and len(paths) == 2:
        built(*paths)
    elif operation == "finish" and len(paths) == 5:
        finish(*paths)
    else:
        raise ValueError("Exact corresponding-source operation/shape required")


if __name__ == "__main__":
    main()
