"""Require a real compiler invocation for every pinned sccache option entry.

The table comparison verifies that the parser declarations were copied in full.
This check closes a different gap: a declared option must actually pass through
the accache frontend during the differential oracle suite. Unsupported or
compiler-rejected options still count when they exercise the bypass path.
"""

import json
from pathlib import Path
import re
import sys

EXPECTED_ENTRIES = {"gcc": 86, "clang": 100, "rust": 37}
TABLE_START = re.compile(r"counted_array!\(\s*(?:pub\s+)?static\s+ARGS\b")
ENTRY = re.compile(r"\b(flag|take_arg)!\(\s*(\"[^\"]+\"|ARCH_FLAG)\s*,([^\n]*)")


def entries(source):
    start = TABLE_START.search(source)
    assert start is not None, "compiler option table is missing"
    end = source.find("]);", start.start())
    assert end >= 0, "compiler option table is unterminated"

    for line in source[start.start():end].splitlines():
        declaration = ENTRY.search(line.split("//", 1)[0])
        if declaration is None:
            continue

        kind, spelling, remainder = declaration.groups()
        name = "-arch" if spelling == "ARCH_FLAG" else spelling[1:-1]
        if kind == "flag":
            yield name, None
            continue

        # Only the separator matters for spotting the invocation. Values and
        # disposition are tested by the differential compiler oracle itself.
        spelling_mode = re.search(
            r"\b(CanBeSeparated|CanBeConcatenated|Separated|Concatenated)"
            r"(?:\(b'([^']+)'\))?", remainder)
        if spelling_mode is None:
            raise AssertionError((name, remainder))

        form, delimiter = spelling_mode.groups()
        if form == "Separated":
            yield name, (True, None)
        elif form == "Concatenated":
            yield name, (False, delimiter or "")
        elif form == "CanBeSeparated":
            yield name, (True, delimiter or "")
        elif form == "CanBeConcatenated":
            yield name, (True, delimiter or "")
        else:
            raise AssertionError((name, remainder))


def exercised(name, mode, commands):
    for command in commands:
        arguments = command[1:]
        if mode is None or mode[0]:
            if name in arguments:
                return True
        if mode is not None and mode[1] is not None:
            prefix = name + mode[1]
            if any(argument.startswith(prefix) and len(argument) > len(prefix)
                   for argument in arguments):
                return True
    return False


def main(frontend, report_path):
    report = json.loads(report_path.read_text())
    commands = report["accache_commands"]
    assert commands, "oracle recorded no accache compiler invocations"

    by_compiler = {
        "gcc": [command for command in commands
                if Path(command[0]).name in {"gcc", "g++", "clang", "clang++"}],
        "clang": [command for command in commands
                  if Path(command[0]).name in {"clang", "clang++"}],
        "rust": [command for command in commands
                 if Path(command[0]).name == "rustc"],
    }

    missing = []
    for compiler, invocations in by_compiler.items():
        source = (frontend / "src/compiler" / f"{compiler}.rs").read_text()
        options = list(entries(source))
        assert len(options) == EXPECTED_ENTRIES[compiler], (
            compiler, len(options), EXPECTED_ENTRIES[compiler])
        absent = [name for name, mode in options
                  if not exercised(name, mode, invocations)]
        print(f"frontend runtime {compiler}: {len(options) - len(absent)}/{len(options)} entries",
              flush=True)
        missing.extend((compiler, name) for name in absent)

    assert not missing, "unexercised frontend entries: " + ", ".join(
        f"{compiler}:{name}" for compiler, name in missing)


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
