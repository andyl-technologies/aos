"""Align the conventional nspawn alias with the AOS physical entry point."""

from __future__ import annotations

import argparse
from pathlib import Path


NSPAWN_PATH = "/usr/bin/systemd-nspawn"
STOCK_CONTEXT = "system_u:object_r:systemd_nspawn_exec_t"
AOS_CONTEXT = "system_u:object_r:aos_nspawn_exec_t"


def align_nspawn_context(source: str) -> str:
    """Replaces exactly one stock regular-file rule, refusing changed inputs."""

    lines = source.splitlines(keepends=True)
    matches = []

    for index, line in enumerate(lines):
        fields = line.split()
        if not fields or fields[0] != NSPAWN_PATH:
            continue

        if fields != [NSPAWN_PATH, "--", STOCK_CONTEXT]:
            raise ValueError("the conventional nspawn context rule differs")
        matches.append(index)

    if len(matches) != 1:
        raise ValueError("expected exactly one stock conventional nspawn rule")

    index = matches[0]
    lines[index] = lines[index].replace(STOCK_CONTEXT, AOS_CONTEXT)
    return "".join(lines)


def main() -> None:
    """Rewrites one build-local final context map after complete validation."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file_contexts", type=Path)
    arguments = parser.parse_args()

    source = arguments.file_contexts.read_text(encoding="utf-8")
    aligned = align_nspawn_context(source)
    arguments.file_contexts.write_text(aligned, encoding="utf-8")


if __name__ == "__main__":
    main()
