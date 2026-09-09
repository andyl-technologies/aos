"""Retains dependency sources without executing downloaded native programs.

The dashboard build supplies its native compilers separately from AOS source
derivations. The removal inventory makes every excluded prebuilt file visible.
"""

import json
from pathlib import Path
import sys


root = Path(sys.argv[1])
removed = []
signatures = (
    b"\x7fELF",
    b"MZ",
    b"\0asm",
    b"!<arch>\n",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
)
native_suffixes = {".node", ".wasm", ".exe", ".dll", ".so", ".dylib", ".a"}

for path in sorted(root.rglob("*")):
    if path.is_symlink() or not path.is_file():
        continue

    with path.open("rb") as stream:
        header = stream.read(8)
    if path.suffix in native_suffixes or header.startswith(signatures):
        removed.append(str(path.relative_to(root)))
        path.unlink()

inventory = root.parent / "removed-precompiled-files.json"
inventory.write_text(json.dumps(removed, indent=2) + "\n")
