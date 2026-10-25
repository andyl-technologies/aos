"""Maps private Bazel execution roots out of native source-location strings."""

import argparse
import os
import re
import sys


def execution_roots(arguments, directory, output_directory):
    """Finds execution roots in compiler paths and build-script context."""
    roots = set()
    for value in [directory, output_directory, *arguments]:
        # Build scripts can compile from a source-repository symlink while
        # passing generated files and include directories as absolute paths.
        # Preserve the repository-relative suffix, including its source name.
        match = re.search(r"(/[^=]*?/execroot/[^/=]+)(?:/|$)", value)
        if match:
            roots.add(match.group(1))
    return sorted(roots)


def main():
    """Replaces this process with the declared compiler and mapped arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    if not options.arguments or options.arguments[0] != "--":
        parser.error("compiler arguments must follow --")

    arguments = options.arguments[1:]
    roots = execution_roots(arguments, os.getcwd(), os.environ.get("OUT_DIR", ""))
    mappings = [f"-ffile-prefix-map={root}=." for root in roots]
    # Explicit caller mappings come last so their more specific policy can
    # override this default. exec preserves compiler signals and exit status.
    os.execv(options.compiler, [options.compiler, *mappings, *arguments])


if __name__ == "__main__":
    main()
