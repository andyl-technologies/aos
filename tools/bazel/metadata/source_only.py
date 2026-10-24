"""Removes bundled compiled tools from rule sources, retaining an audit list.

Source-built AOS toolchains replace upstream binary tool providers. Compiled
upstream examples/fixtures are also excluded from these source repositories;
their own upstream test suites are not first-party build targets.
"""

import argparse
import json
from pathlib import Path


COMPILED_SUFFIXES = {".jar", ".class", ".so", ".a", ".ar", ".aar", ".o", ".wasm", ".dll", ".dylib", ".exe"}
COMPILED_MAGIC = (
    b"\x7fELF", b"!<arch>\n", b"\x00asm", b"\xca\xfe\xba\xbe",
    b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    removed = []

    for path in sorted(args.root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        with path.open("rb") as stream:
            magic = stream.read(8)
        if path.suffix in COMPILED_SUFFIXES or magic.startswith(COMPILED_MAGIC):
            removed.append(path.relative_to(args.root).as_posix())
            path.unlink()

    (args.root / "aos-excluded-binaries.json").write_text(json.dumps(removed, indent=2) + "\n")


if __name__ == "__main__":
    main()
