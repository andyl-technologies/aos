# SPDX-License-Identifier: GPL-2.0-or-later
"""Records ordinary package source/generated/sysroot inputs after GNU success.

The producer's original builder controls execution. These body correlations
describe a reproducible host-target context and grant no process permission.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

GENERATED = ("auto-host.h", "tconfig.h", "tm.h", "options.h", "insn-constants.h", "insn-modes.h")
LINKED = ("unwind.h", "md-unwind-def.h", "md-unwind-support.h", "gthr-default.h")
FILE_LIMIT = 4 * 1024**3
TOTAL_LIMIT = 8 * 1024**3
ENTRY_LIMIT = 1000000


def decimal_macro(path, name):
    """Reads one literal GNU configuration value without preprocessing it."""
    matches = re.findall(r"^[ \t]*#[ \t]*define[ \t]+" + re.escape(name)
                         + r"[ \t]+([0-9]+)[ \t]*$", path.read_text(), re.MULTILINE)
    if len(matches) != 1:
        raise ValueError("A target libc/configuration version is not one literal macro")
    return int(matches[0])


class Recorder:
    """Charges each newly read body and retains raw symbolic-link geometry."""

    def __init__(self, roots):
        self.roots = roots
        self.records = {}
        self.body_bytes = 0
        self.entries = 0

    def pin(self, path):
        resolved = path.resolve(strict=True)
        if not any(resolved == root or root in resolved.parents for root in self.roots):
            raise ValueError("A package input escapes its declared source/tool roots")
        if resolved in self.records:
            return {**self.records[resolved], "path": str(path)}
        before = resolved.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > FILE_LIMIT:
            raise ValueError("A declared body is not a bounded regular file")
        self.body_bytes += before.st_size
        if self.body_bytes > TOTAL_LIMIT:
            raise ValueError("The context body-read ceiling was exceeded")
        digest = hashlib.sha256()
        with resolved.open("rb") as stream:
            for body in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(body)
        after = resolved.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("An input body changed during the inventory")
        row = {"path": str(resolved), "bytes": before.st_size, "sha256": digest.hexdigest()}
        self.records[resolved] = row
        return {**row, "path": str(path)}

    def inventory(self, root):
        rows = []
        stack = [(root, ".")]
        while stack:
            path, relative = stack.pop()
            self.entries += 1
            if self.entries > ENTRY_LIMIT:
                raise ValueError("The complete context entry ceiling was exceeded")
            mode = path.lstat().st_mode
            row = {"relative_path": relative, "mode": stat.S_IMODE(mode)}
            if stat.S_ISLNK(mode):
                row.update(type="symlink", raw_target=os.readlink(path))
                resolved = path.resolve(strict=True)
                if resolved.is_file():
                    row["resolved_body"] = self.pin(path)
            elif stat.S_ISDIR(mode):
                row["type"] = "directory"
                with os.scandir(path) as entries:
                    children = sorted(entries, key=lambda entry: entry.name, reverse=True)
                for entry in children:
                    name = entry.name if relative == "." else relative + "/" + entry.name
                    stack.append((Path(entry.path), name))
            elif stat.S_ISREG(mode):
                row.update(type="regular", **{key: value for key, value in self.pin(path).items() if key != "path"})
            else:
                raise ValueError("A special object entered the complete context")
            rows.append(row)
        return {"root": str(root), "rows": rows}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--binutils", type=Path, required=True)
    parser.add_argument("--dependency-root", type=Path, action="append", required=True)
    parser.add_argument("--configure-script", type=Path, required=True)
    parser.add_argument("--build", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--elf-machine", type=int, required=True)
    parser.add_argument("--build-word-bytes", type=int, choices=(4, 8), required=True)
    args = parser.parse_args()
    output = args.output.resolve(strict=True)
    source_output = args.source.resolve(strict=True)
    source = source_output / "gcc-16.2.0"
    # Generated source data owns its original paths. Metadata may reference
    # this source output; the source output must never reference metadata.
    generated_root = source_output / "generated-context"
    generated = generated_root / "build/gcc"
    local = generated_root / "build" / args.target / "libgcc"
    sysroot = generated_root / "target-sysroot"
    dependencies = [root.resolve(strict=True) for root in args.dependency_root]
    compiler = args.compiler.resolve(strict=True)
    recorder = Recorder([output, source_output, *dependencies])

    for name in GENERATED:
        if not (generated / name).is_file() or not (generated / name).stat().st_size:
            raise ValueError("A named GNU header was not generated")
    expected_machine = {"x86_64-unknown-linux-gnu": 62, "aarch64-unknown-linux-gnu": 183}
    if expected_machine.get(args.target) != args.elf_machine or not args.build.endswith("-linux-gnu"):
        raise ValueError("The GNU build/host target declaration is unsupported")
    linked = {}
    for name in LINKED:
        path = local / name
        resolved = path.resolve(strict=True)
        if not path.is_symlink() or source / "libgcc" not in resolved.parents:
            raise ValueError("A configured GNU header does not resolve into its actual source")
        linked[name] = str(resolved.relative_to(source))
    if not (local / "auto-target.h").stat().st_size:
        raise ValueError("The actual libgcc configure header is absent")
    member_plan = json.loads((local / "member-commands.json").read_bytes())
    if (member_plan.get("schema") != "crucible.libgcc.configured-commands.v1"
            or member_plan.get("target") != args.target
            or member_plan.get("elf_machine") != args.elf_machine
            or Path(member_plan["compiler_executable"]).resolve(strict=True) != compiler):
        raise ValueError("The actual GNU Make command tuple differs")
    probe = generated_root / "target-abi.o"
    header = probe.read_bytes()[:64]
    if (len(header) != 64 or header[:6] != b"\x7fELF\x02\x01"
            or struct.unpack_from("<H", header, 18)[0] != args.elf_machine):
        raise ValueError("The member compiler produced a different target ELF")
    if not (local / "libgcc_tm.h").stat().st_size:
        raise ValueError("The original mkheader output is absent")
    if ("#define SIZEOF_VOID_P " + str(args.build_word_bytes)) not in (generated / "auto-host.h").read_text():
        raise ValueError("The generated build-machine pointer ABI differs")
    # GNU's auto-host.h also records target-header-derived libc features.
    # Build ABI equality does not establish this separate target input role.
    features = sysroot / "usr/include/features.h"
    target_libc_version = [decimal_macro(features, name) for name in ("__GLIBC__", "__GLIBC_MINOR__")]
    configured_libc_version = [decimal_macro(generated / "auto-host.h", name)
                               for name in ("TARGET_GLIBC_MAJOR", "TARGET_GLIBC_MINOR")]
    if target_libc_version != configured_libc_version:
        raise ValueError("GNU target libc probes differ from the original target sysroot")
    if any(not (source / name).is_file() for name in ("COPYING3", "COPYING.RUNTIME")):
        raise ValueError("Complete GNU source notices are required")

    support = output / "share/qom-private-unwind"

    def emit(name, value):
        path = support / name
        path.write_text(json.dumps(value, indent=2) + "\n")
        return recorder.pin(path)

    source_inventory = emit("source-inventory.json", recorder.inventory(source_output))
    generated_inventory = emit("generated-inventory.json", recorder.inventory(generated_root))
    sysroot_inventory = emit("sysroot-inventory.json", recorder.inventory(sysroot))
    # Follow each raw sysroot entry to its actual complete source-built input.
    targets = {path.resolve(strict=True) for path in sysroot.rglob("*") if path.is_symlink()}
    target_inventories = []
    for target in sorted(targets):
        target_inventories.append(recorder.inventory(target) if target.is_dir() else recorder.pin(target))
    sysroot_targets = emit("sysroot-targets.json", {"targets": target_inventories})
    compiler_root = compiler.parent.parent
    for name in ("include", "include-fixed"):
        directory = compiler_root / "lib/gcc" / args.target / "16.2.0" / name
        if directory.is_dir():
            recorder.inventory(directory)
    compiler_record = recorder.pin(compiler)
    binutils = args.binutils.resolve(strict=True)
    binutils_records = {name: recorder.pin(binutils / name) for name in ("ar", "nm", "objcopy")}
    commands = emit("configure-commands.json", {
        "script": recorder.pin(args.configure_script),
        "stdout": recorder.pin(support / "configure.stdout"),
        "stderr": recorder.pin(support / "configure.stderr"),
        "generator_records": generated_inventory,
        "actual_member_plan": recorder.pin(local / "member-commands.json"),
        "target_abi_probe": recorder.pin(probe),
        "scope": "Original ordinary package phase returned zero before context serialization; named source/header targets only",
    })
    context = {
        "schema": "crucible.libgcc.fresh-member-context.v2", "status": "FreshConfigured",
        "build": args.build, "build_word_bytes": args.build_word_bytes, "target": args.target, "elf_machine": args.elf_machine,
        "target_libc_version": target_libc_version,
        "gcc_version": "16.2.0", "compiler": str(compiler),
        "compiler_executable": str(args.compiler),
        "binutils": str(binutils), "binutils_records": binutils_records,
        "linked_headers": linked, "member_commands": recorder.pin(local / "member-commands.json"),
        "target_abi_probe": recorder.pin(probe),
        "source_root": str(source), "gcc_build_root": str(generated), "libgcc_context_root": str(local),
        "sysroot": str(sysroot), "dependency_roots": [str(root) for root in dependencies],
        "records": list(recorder.records.values()), "source_inventory": source_inventory,
        "generated_inventory": generated_inventory, "configure_commands": commands,
        "sysroot_inventory": sysroot_inventory, "sysroot_targets": sysroot_targets,
        "compiler_body": compiler_record,
        "scope": "Actual host-target configuration/geometry only; no full compiler bootstrap/member/QOM graph or target process permission",
    }
    emit("context.json", context)


if __name__ == "__main__":
    main()
