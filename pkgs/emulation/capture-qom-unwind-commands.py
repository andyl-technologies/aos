# SPDX-License-Identifier: GPL-2.0-or-later
"""Records two actual GNU Make compile commands without compiling the members.

The configured libgcc Makefile owns target selection. This adapter accepts one
source command per fixed member and replaces only its object/dependency sinks.
It does not execute captured shell text or grant process permission.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shlex

MEMBERS = ("unwind-dw2.o", "unwind-dw2-fde-dip.o")


def pin(path):
    body = path.read_bytes()
    return {"path": str(path), "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def command_for(member, local, source, compiler):
    raw = local / (member[:-2] + ".command")
    if raw.stat().st_size > 1024 * 1024:
        raise ValueError("The GNU dry-run command record exceeds its bound")
    source_path = source / "libgcc" / (member[:-2] + ".c")
    candidates = []
    for line in raw.read_text().replace("\\\n", " ").splitlines():
        if str(source_path) not in line:
            continue
        argv = shlex.split(line)
        if not argv or Path(argv[0]).resolve(strict=True) != compiler.resolve(strict=True):
            raise ValueError("GNU selected a different member compiler")
        if any(token in {";", "&&", "||", "|", ">", "<"} for token in argv):
            raise ValueError("A member command contains shell control syntax")
        if argv.count("-c") != 1 or argv[argv.index("-c") + 1] != str(source_path):
            raise ValueError("GNU selected an unexpected source unit")
        original_argv = list(argv)
        for option, marker in (("-o", "@object@"), ("-MT", "@object@"), ("-MF", "@dependency@")):
            # GNU's literal Makefile joins -MT/-MF to their values. Normalize
            # only that output-option spelling; preserve the original argv.
            joined = [index for index, token in enumerate(argv)
                      if token.startswith(option) and token != option]
            if joined:
                if len(joined) != 1 or option in argv:
                    raise ValueError("The source command has duplicate output options")
                index = joined[0]
                argv[index:index + 1] = [option, argv[index][len(option):]]
            if argv.count(option) != 1:
                raise ValueError("The source command has ambiguous output sinks")
            index = argv.index(option) + 1
            observed = Path(argv[index])
            if observed.is_absolute():
                observed = observed.relative_to(local)
            expected = member if option != "-MF" else member[:-2] + ".dep"
            if str(observed) != expected:
                raise ValueError("GNU changed the named member output geometry")
            argv[index] = marker
        if "-MD" not in argv or "-MP" not in argv:
            raise ValueError("GNU omitted complete member dependency output")
        if any(token.startswith(("-save-temps", "-fprofile-", "-fdump-", "-fstack-usage")) for token in argv):
            raise ValueError("The member command acquired an additional output family")
        candidates.append((argv, original_argv))
    if len(candidates) != 1:
        raise ValueError("Exactly one GNU source command per member is required")
    argv, original_argv = candidates[0]
    return {"member": member, "source": pin(source_path), "argv": argv,
            "original_argv": original_argv, "raw": pin(raw)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--gcc-build", type=Path, required=True)
    parser.add_argument("--local", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--elf-machine", type=int, required=True)
    args = parser.parse_args()
    source, local = args.source.resolve(strict=True), args.local.resolve(strict=True)
    expected_machine = {"x86_64-unknown-linux-gnu": 62, "aarch64-unknown-linux-gnu": 183}
    if expected_machine.get(args.target) != args.elf_machine:
        raise ValueError("The declared GNU target and ELF machine disagree")
    rows = [command_for(member, local, source, args.compiler) for member in MEMBERS]
    provenance = [local / "Makefile", local / "config.status", local / "config.log",
                  local / "auto-target.h", source / "libgcc/config.host",
                  source / "libgcc/Makefile.in", args.gcc_build / "libgcc.mvars"]
    value = {"schema": "crucible.libgcc.configured-commands.v1", "target": args.target,
             "elf_machine": args.elf_machine, "compiler_executable": str(args.compiler),
             "cwd": str(local), "commands": rows, "selection_inputs": [pin(p) for p in provenance],
             "scope": "Actual target GNU configure/Make dry-run records; no member execution or permission"}
    (local / "member-commands.json").write_text(json.dumps(value, indent=2) + "\n")


if __name__ == "__main__":
    main()
