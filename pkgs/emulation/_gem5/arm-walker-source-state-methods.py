# SPDX-License-Identifier: MIT
"""Extracts source-exact walker methods for explicitly modeled data controls.

The constructor projection preserves four literal initializer expressions. It
does not replace compilation of the complete TableWalker translation unit.
"""

import hashlib
import json
from pathlib import Path
import re
import sys


def method(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 1
    cursor = opening + 1
    while depth and cursor < len(source):
        depth += (source[cursor] == "{") - (source[cursor] == "}")
        cursor += 1
    if depth:
        raise ValueError("native method has no complete body")
    return source[start:cursor]


def render(source_path, output_path):
    source_path, output_path = Path(source_path), Path(output_path)
    with source_path.open("rb") as stream:
        raw = stream.read(256 * 1024 + 1)
    if not 0 < len(raw) <= 256 * 1024:
        raise ValueError("native walker source exceeds its bounded extent")
    source = raw.decode("utf-8")
    constructor = source[source.index("TableWalker::TableWalker(const Params &p)"):]
    constructor = constructor[:constructor.index("\n{")]
    expressions = []
    for member in ("mmu", "release", "pendingReqs", "pendingChangeTick"):
        matches = list(re.finditer(r"\b" + member + r"\(", constructor))
        if len(matches) != 1:
            raise ValueError("native constructor lacks one explicit birth initializer")
        start = matches[0].start()
        opening = constructor.index("(", start)
        depth, end = 1, opening + 1
        while depth and end < len(constructor):
            depth += (constructor[end] == "(") - (constructor[end] == ")")
            end += 1
        if depth:
            raise ValueError("native initializer is incomplete")
        expressions.append(constructor[start:end])

    declarations = [
        "TableWalker::TableWalker() : " + ", ".join(expressions) + " {}",
        "void\n" + method(source, "TableWalker::setMmu(MMU *_mmu)"),
        "void\n" + method(source, "TableWalker::pendingChange()"),
        "bool\n" + method(source, "TableWalker::crucibleNativeClosure("),
    ]
    # The generated methods retain the complete native file's license notice.
    license_notice = source[:source.index("#include")]
    encoded = (license_notice + "\n// Source-extracted data fixture; no native authority.\n"
               + "\n\n".join(declarations) + "\n").encode()
    if len(encoded) > 32 * 1024:
        raise ValueError("generated modeled method extent exceeds its allowance")
    with output_path.open("xb") as stream:
        stream.write(encoded)
    record = {
        "source": str(source_path),
        "source_bytes": len(raw),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "output": str(output_path),
        "output_bytes": len(encoded),
        "output_sha256": hashlib.sha256(encoded).hexdigest(),
        "constructor_scope": "four exact birth expressions projected onto a data fixture",
        "methods_scope": "three complete literal native methods, with modeled collaborators",
        "configured_native_tu_qualified": False,
        "native_authority": False,
    }
    with output_path.with_suffix(".source.json").open("x") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise ValueError("expected native source and generated methods output")
    render(sys.argv[1], sys.argv[2])
