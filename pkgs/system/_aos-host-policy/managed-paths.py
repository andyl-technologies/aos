"""Records immutable image-owned configuration leaves without copying defaults."""

import json
from pathlib import Path
import sys

MAXIMUM_LEAVES = 65536


def visit(source, target, ancestors, paths):
    source = source.resolve(strict=True)
    if not source.is_dir():
        paths.add(target)
        return
    if len(ancestors) >= 64 or source in ancestors:
        raise ValueError("configuration tree contains a directory cycle")
    for child in sorted(source.iterdir()):
        visit(child, target + "/" + child.name, ancestors + [source], paths)
        if len(paths) > MAXIMUM_LEAVES:
            raise ValueError("configuration tree exceeds managed leaf limit")


def main():
    inputs = json.loads(Path(sys.argv[1]).read_text())
    paths = set(inputs["files"])
    for tree in inputs["trees"]:
        source = Path(tree["source"])
        if not source.is_dir():
            raise ValueError("configuration tree source is not a directory")
        visit(source, tree["target"], [], paths)
    Path(sys.argv[2]).write_text(json.dumps(sorted(paths), separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
