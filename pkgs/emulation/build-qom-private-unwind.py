# SPDX-License-Identifier: GPL-2.0-or-later
"""Builds two GNU runtime members in a separately generated source context.

This runs only inside the ordinary source-built package builder. The context
producer supplies real generated headers and complete corresponding source.
Context records correlate build inputs; they grant no native execution permit.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import struct

MEMBERS = ("unwind-dw2.o", "unwind-dw2-fde-dip.o")
GENERATED = (
    "auto-host.h", "tconfig.h", "tm.h", "options.h",
    "insn-constants.h", "insn-modes.h",
)
LINKED = ("unwind.h", "md-unwind-def.h", "md-unwind-support.h", "gthr-default.h")
TARGET_MACHINES = {"x86_64-unknown-linux-gnu": 62, "aarch64-unknown-linux-gnu": 183}


def require_target_elf(path, machine):
    with path.open("rb") as stream:
        header = stream.read(64)
    if (len(header) != 64 or header[:6] != b"\x7fELF\x02\x01"
            or struct.unpack_from("<H", header, 16)[0] != 1
            or struct.unpack_from("<H", header, 18)[0] != machine):
        raise ValueError("A member object differs from its configured ELF target")


def source_atomic_imports(context):
    # GNU config/aarch64/t-lse enumerates these exact five memory models and
    # sizes. Preserve outlined atomics instead of changing target codegen.
    if context["target"] != "aarch64-unknown-linux-gnu":
        return set()
    models = ("relax", "acq", "rel", "acq_rel", "sync")
    shapes = [("cas", size) for size in (1, 2, 4, 8, 16)]
    shapes += [(op, size) for op in ("swp", "ldadd", "ldclr", "ldeor", "ldset") for size in (1, 2, 4, 8)]
    return {"__aarch64_" + op + str(size) + "_" + model for op, size in shapes for model in models}


def digest(path):
    checksum = hashlib.sha256()
    extent = 0
    with path.open("rb") as stream:
        for body in iter(lambda: stream.read(1024 * 1024), b""):
            extent += len(body)
            checksum.update(body)
    return {"bytes": extent, "sha256": checksum.hexdigest()}


def contained(path, roots):
    resolved = path.resolve(strict=True)
    if not any(resolved == root or root in resolved.parents for root in roots):
        raise ValueError("An input escapes the declared source/tool context")
    return resolved


def verify_context(args):
    # Authenticate the mandatory fixed tuple before invoking any compiler.
    source_root = args.source_root.resolve(strict=True)
    context_root = args.context_root.resolve(strict=True)
    compiler_root = args.compiler.parent.parent.resolve(strict=True)
    context = json.loads(args.context.read_text())
    if context.get("schema") != "crucible.libgcc.fresh-member-context.v2":
        raise ValueError("A generated package context is required")
    if context.get("status") != "FreshConfigured":
        raise ValueError("Prepared contexts cannot produce an observer")
    if TARGET_MACHINES.get(context.get("target")) != context.get("elf_machine"):
        raise ValueError("The generated target geometry is unsupported")
    if context.get("gcc_version") != "16.2.0":
        raise ValueError("The generated compiler version changed")
    if (Path(context["compiler"]).resolve(strict=True) != args.compiler.resolve(strict=True)
            or Path(context["compiler_executable"]).resolve(strict=True) != args.compiler.resolve(strict=True)):
        raise ValueError("The context and selected compiler differ")
    if Path(context["binutils"]).resolve(strict=True) != args.binutils.resolve(strict=True):
        raise ValueError("The context and selected target binutils differ")

    # Generated headers and sysroot belong to complete corresponding source.
    # The separate metadata output references them in one direction only.
    generated_roots = [source_root]
    gcc_build = contained(Path(context["gcc_build_root"]), generated_roots)
    local = contained(Path(context["libgcc_context_root"]), generated_roots)
    sysroot = contained(Path(context["sysroot"]), generated_roots)
    source = contained(Path(context["source_root"]), [source_root])
    expected = [gcc_build / name for name in GENERATED]
    expected += [local / "libgcc_tm.h", local / "auto-target.h", *[local / name for name in LINKED]]
    expected += [source / "libgcc" / name for name in
                 ("unwind-dw2.c", "unwind-dw2-fde-dip.c", "gthr.h")]
    expected += [source / "COPYING3", source / "COPYING.RUNTIME"]
    dependency_roots = [Path(root).resolve(strict=True) for root in context["dependency_roots"]]
    allowed = [source_root, context_root, compiler_root, *dependency_roots]
    rows = {}
    for row in context["records"]:
        path = Path(row["path"])
        actual = digest(path)
        if actual != {"bytes": row["bytes"], "sha256": row["sha256"]}:
            raise ValueError("A generated/source input changed")
        resolved = contained(path, allowed)
        if resolved in rows:
            # Distinct header links may resolve to the same actual source.
            if rows[resolved] != actual:
                raise ValueError("Conflicting records for the same input")
        rows[resolved] = actual
    for path in expected:
        if path.resolve(strict=True) not in rows:
            raise ValueError("A required generated/source input lacks a body record")
    if set(context["binutils_records"]) != {"ar", "nm", "objcopy"}:
        raise ValueError("The target inspector roster changed")
    for name, record in context["binutils_records"].items():
        path = args.binutils / name
        if (Path(record["path"]).resolve(strict=True) != path.resolve(strict=True)
                or path.resolve(strict=True) not in rows
                or digest(path) != {key: record[key] for key in ("bytes", "sha256")}):
            raise ValueError("A target binutils executable differs from its original context")
    if set(context["linked_headers"]) != set(LINKED):
        raise ValueError("The configured GNU linked-header roster changed")
    for name, target in context["linked_headers"].items():
        path = local / name
        resolved = (source / target).resolve(strict=True)
        if (source / "libgcc" not in resolved.parents or not path.is_symlink()
                or path.resolve(strict=True) != resolved):
            raise ValueError("An actual target-configured GNU link changed")
    for member in MEMBERS:
        if "GCC Runtime Library Exception" not in (source / "libgcc" / (member[:-2] + ".c")).read_text():
            raise ValueError("The original GNU source notice is missing")
    required_ancestry = ("source_inventory", "generated_inventory", "configure_commands", "member_commands", "target_abi_probe")
    for name in required_ancestry:
        record = context[name]
        path = contained(Path(record["path"]), [context_root, source_root])
        if digest(path) != {"bytes": record["bytes"], "sha256": record["sha256"]}:
            raise ValueError("A complete context inventory or generator record changed")
    # The context producer independently qualifies complete source/inventory
    # coverage. These correlations do not establish that producer's history.
    # Actual .d files below join every consumed generated/source/system header.
    return context, source, gcc_build, local, sysroot, rows, compiler_root


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--context-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--binutils", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    context, source, gcc_build, local, sysroot, records, compiler_root = verify_context(args)
    if args.validate_only:
        return
    args.output.mkdir()  # A caller may not recycle an earlier build directory.
    receipts = []

    def run(name, command):
        # Nix's original builder owns this child and its finite build policy.
        # This recipe is not an independently qualified host flight operator.
        completed = subprocess.run(command, cwd=local, capture_output=True, check=False)
        (args.output / (name + ".stdout")).write_bytes(completed.stdout)
        (args.output / (name + ".stderr")).write_bytes(completed.stderr)
        receipts.append({"name": name, "argv": [str(value) for value in command],
                         "cwd": str(local), "exit": completed.returncode})
        (args.output / "command-receipts.json").write_text(json.dumps(receipts, indent=2) + "\n")
        if completed.returncode:
            import sys
            sys.stderr.buffer.write(completed.stderr)
            raise ValueError("The source-built observer command failed: " + name)
        return completed.stdout.decode()

    imports = {}
    defined = set()
    for member in MEMBERS:
        target = args.output / member
        plan = json.loads(Path(context["member_commands"]["path"]).read_bytes())
        if (plan.get("schema") != "crucible.libgcc.configured-commands.v1"
                or plan.get("target") != context["target"]
                or plan.get("elf_machine") != context["elf_machine"]
                or Path(plan["compiler_executable"]).resolve(strict=True) != args.compiler.resolve(strict=True)
                or Path(plan["cwd"]).resolve(strict=True) != local):
            raise ValueError("The actual configured GNU command tuple changed")
        candidates = [row for row in plan["commands"] if row["member"] == member]
        if len(candidates) != 1 or {row["member"] for row in plan["commands"]} != set(MEMBERS):
            raise ValueError("The fixed two-member command roster changed")
        row = candidates[0]
        source_path = source / "libgcc" / (member[:-2] + ".c")
        if (Path(row["source"]["path"]).resolve(strict=True) != source_path.resolve(strict=True)
                or digest(source_path) != {key: row["source"][key] for key in ("bytes", "sha256")}):
            raise ValueError("The actual command source body differs")
        command = row["argv"]
        if (not command or Path(command[0]).resolve(strict=True) != args.compiler.resolve(strict=True)
                or command.count("-c") != 1 or command[command.index("-c") + 1] != str(source_path)
                or command.count("@object@") != 2 or command.count("@dependency@") != 1):
            raise ValueError("The actual GNU compiler/source/output slots changed")
        for option, marker in (("-o", "@object@"), ("-MT", "@object@"), ("-MF", "@dependency@")):
            if command.count(option) != 1 or command[command.index(option) + 1] != marker:
                raise ValueError("The actual GNU dependency sink changed")
        substitutions = {"@object@": str(target), "@dependency@": str(args.output / (member + ".d"))}
        command = [substitutions.get(token, token) for token in command]
        run("compile-" + member, command)
        require_target_elf(target, context["elf_machine"])
        dependency_body = (args.output / (member + ".d")).read_text().replace("\\\n", " ")
        # Ignore -MP's subsequent phony targets; only the actual first rule
        # contains dependencies of this compiled member.
        first_rule = dependency_body.split("\n", 1)[0]
        paths = shlex.split(first_rule.split(":", 1)[1])
        dependency_rows = []
        for value in paths:
            path = Path(value)
            path = path if path.is_absolute() else local / path
            resolved = path.resolve(strict=True)
            if resolved not in records:
                raise ValueError("An actual member dependency lacks a source/context record: " + str(path))
            dependency_rows.append({"path": str(path), **digest(path)})
        (args.output / (member + ".dependencies.json")).write_text(json.dumps(dependency_rows, indent=2) + "\n")
        symbols = run("defined-" + member, [args.binutils / "nm", "-g", "--defined-only", target])
        for line in symbols.splitlines():
            fields = line.split()
            if len(fields) != 3:
                raise ValueError("An original symbol record changed geometry")
            defined.add(fields[2])
        imports[member] = run("imports-" + member, [args.binutils / "nm", "-u", target])

    names = {name: "crucible_qom_private_" + name for name in sorted(defined)}
    public = {"_Unwind_Backtrace": "qom_class_unwind_Backtrace",
              "_Unwind_GetCFA": "qom_class_unwind_GetCFA",
              "_Unwind_GetIP": "qom_class_unwind_GetIP",
              "__register_frame": "qom_class_unwind_register_frame",
              "__deregister_frame": "qom_class_unwind_deregister_frame"}
    if not (set(public) | {"_Unwind_Find_FDE"}) <= defined:
        raise ValueError("The GNU observer definitions are incomplete")
    names.update(public)
    for member in MEMBERS:
        mapping = dict(names)
        mapping["_Unwind_Find_FDE"] = ("qom_class_unwind_Find_FDE" if member == MEMBERS[0]
                                      else "qom_class_unwind_Find_FDE_impl")
        if member == MEMBERS[1]:
            mapping.update(malloc="qom_class_unwind_allocate", free="qom_class_unwind_retire")
        table = args.output / (member + ".symbols")
        table.write_text("".join(old + " " + new + "\n" for old, new in sorted(mapping.items())))
        run("transform-" + member, [args.binutils / "objcopy", "--redefine-syms=" + str(table),
                                   args.output / member, args.output / ("private-" + member)])
        observed = run("inspect-" + member, [args.binutils / "nm", "-g", args.output / ("private-" + member)])
        for line in observed.splitlines():
            name = line.split()[-1]
            if name in defined or (member == MEMBERS[1] and name in {"malloc", "free"}):
                raise ValueError("An ordinary unwinder or FDE allocator symbol escaped the private namespace")
            fields = line.split()
            if len(fields) == 2 and fields[0] == "U":
                expected_imports = {
                    "_dl_find_object", "abort", "memcpy", "memmove", "memset", "strlen",
                    "pthread_once", "pthread_mutex_lock", "pthread_mutex_unlock",
                    "pthread_cond_wait", "pthread_cond_broadcast",
                    "qom_class_unwind_Find_FDE", "qom_class_unwind_allocate",
                    "qom_class_unwind_retire", "_GLOBAL_OFFSET_TABLE_",
                    *names.values(), *source_atomic_imports(context),
                }
                if name not in expected_imports:
                    raise ValueError("The private member has an unreviewed linker import: " + name)
    archive = args.output / "libcrucible-qom-unwind.a"
    run("archive", [args.binutils / "ar", "rcsD", archive,
                    *[args.output / ("private-" + name) for name in MEMBERS]])
    if run("archive-members", [args.binutils / "ar", "t", archive]).splitlines() != [
            "private-" + member for member in MEMBERS]:
        raise ValueError("The private archive member set changed")
    manifest = {"schema": "crucible.qom.private-unwind.build.v2", "target": context["target"], "elf_machine": context["elf_machine"], "context": digest(args.context),
                "compiler": {"path": str(args.compiler), **digest(args.compiler)},
                "commands": receipts, "symbol_map": names, "original_imports": imports,
                "archive": digest(archive), "scope": "Source/member build only; no QOM closure or activation"}
    (args.output / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
