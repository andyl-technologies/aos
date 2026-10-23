"""Pins Bazel's POSIX command shell, including workspace status actions."""

import json
from pathlib import Path
import sys


shell = json.dumps(sys.argv[1])
path = Path("src/main/java/com/google/devtools/build/lib/util/CommandBuilder.java")
source = path.read_text()
replacements = {
    f'ImmutableList.of("/bin/sh", {shell})': f"ImmutableList.of({shell})",
    'ImmutableList.of("/bin/sh", "-c", Joiner.on(\' \').join(argv))':
        f'ImmutableList.of({shell}, "-c", Joiner.on(\' \').join(argv))',
}
for original, replacement in replacements.items():
    if source.count(original) != 1:
        raise ValueError(f"unexpected Bazel command-shell implementation: {original}")
    source = source.replace(original, replacement)
path.write_text(source)
