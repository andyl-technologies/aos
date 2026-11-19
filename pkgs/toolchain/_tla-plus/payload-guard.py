"""Reject compiled payloads in the source trees of a from-source Java build.

Upstream TLA+ projects distribute their third-party dependencies as compiled
JARs. Every source tree that reaches javac is checked for compiled classes,
archives, and native executables so a pinned input cannot silently start
carrying prebuilt code.

Usage: python3 payload-guard.py <label> <directory>...
"""

from pathlib import Path
import sys

COMPILED_SUFFIXES = {
    ".class", ".jar", ".so", ".dylib", ".dll", ".jnilib", ".a", ".o",
    ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
}

COMPILED_SIGNATURES = tuple(bytes.fromhex(value) for value in (
    "cafebabe", "7f454c46", "0061736d", "213c617263683e0a",
    "feedface", "cefaedfe", "feedfacf", "cffaedfe",
    "4d5a", "504b0304", "504b0506",
))


def main() -> None:
    label, *directories = sys.argv[1:]

    for directory in directories:
        for path in Path(directory).rglob("*"):
            if not path.is_file():
                continue

            with path.open("rb") as source:
                header = source.read(8)

            if path.suffix.lower() in COMPILED_SUFFIXES or header.startswith(COMPILED_SIGNATURES):
                raise SystemExit(f"Compiled payload in {label} source input: {path}")


main()
