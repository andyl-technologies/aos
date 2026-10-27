"""Pins executable build interpreters without changing firmware configuration."""

from pathlib import Path
import json
import sys


def main():
    if len(sys.argv) != 4:
        raise ValueError("Expected AOS Bash, Perl and Python executable paths")
    bash, perl, python = sys.argv[1:]
    replacements = {
        b"#!/usr/bin/perl -w": (perl + " -w").encode(),
        b"#! /usr/bin/perl -w": (perl + " -w").encode(),
        b"#!/usr/bin/env perl": perl.encode(),
        b"#!/bin/bash": bash.encode(),
        b"#!/usr/bin/env bash": bash.encode(),
        b"#!/bin/sh": bash.encode(),
        b"#!/bin/sh -e": (bash + " -e").encode(),
        b"#!/usr/bin/python3": python.encode(),
        b"#!/usr/bin/python": python.encode(),
        b"#! /usr/bin/env python": python.encode(),
        b"#!python3": python.encode(),
    }
    # These are original data/debug/browser scripts, not build interpreters.
    # Their source remains intact; the ROM targets do not execute them.
    retained = {b"#!ipxe", b"#!/usr/bin/gdb -x", b"#!/usr/bin/env node"}
    changes = []
    for root in (Path("roms/ipxe"), Path("roms/edk2/BaseTools")):
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            body = path.read_bytes()
            first, separator, rest = body.partition(b"\n")
            first = first.rstrip(b"\r")
            if not first.startswith(b"#!"):
                continue
            if first in retained:
                continue
            interpreter = replacements.get(first)
            if interpreter is None:
                raise ValueError("Unrecognized source interpreter: " + str(path))
            path.write_bytes(b"#!" + interpreter + b"\n" + rest)
            changes.append({"path": str(path), "original": first.decode(),
                            "replacement": interpreter.decode()})
    Path("interpreter-rewrites.json").write_text(json.dumps(changes, indent=2) + "\n")


if __name__ == "__main__":
    main()
