# SPDX-License-Identifier: MIT
"""Retains exact production method bodies for a narrow table-bank fixture."""

import hashlib
import json
import re
import sys
from pathlib import Path


METHODS = (
    "OriginalNodeScope",
    "current",
    "refuse",
    "ordinal",
    "declareTable",
    "tableEntry",
    "indexedEntry",
    "tablesComplete",
)


def selected_methods(raw):
    """Selects complete, uniquely named bodies from the admitted source file."""
    source = raw.decode("utf-8")
    structural = re.sub(r"//[^\n]*", lambda match: " " * len(match[0]), source)
    bodies = []
    for name in METHODS:
        anchor = "\nOriginalNodeScope::" + name + "("
        if source.count(anchor) != 1:
            raise ValueError("selected production method is not unique")
        name_start = source.index(anchor) + 1
        start = source.rfind("\n\n", 0, name_start) + 2
        opening = structural.index("{", name_start)
        depth = 1
        end = opening + 1
        while depth and end < len(source):
            depth += (structural[end] == "{") - (structural[end] == "}")
            end += 1
        if depth or source[end:end + 1] != "\n":
            raise ValueError("selected method lacks its complete closing body")
        body = source[start:end + 1]
        syntax = structural[start:end + 1]
        # The admitted methods use only line comments and no literals. Avoid
        # interpreting a new C++ lexical form with this narrow extractor.
        if '"' in syntax or "'" in syntax or "/*" in syntax or "*/" in syntax:
            raise ValueError("selected method needs a richer source parser")
        bodies.append((name, body.encode("utf-8")))
    return bodies


def main():
    if len(sys.argv) != 3:
        raise ValueError("expected matching scope source and component output")
    source = Path(sys.argv[1])
    with source.open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("scope source exceeds the finite component extent")
    bodies = selected_methods(raw)
    output = Path(sys.argv[2])
    rendered = (
        b"// Exact selected bodies only; not a configured native gem5 TU.\n"
        b"namespace gem5::crucible {\n\n"
        + b"\n".join(body for _, body in bodies)
        + b"\n} // namespace gem5::crucible\n"
    )
    output.write_bytes(rendered)
    output.with_suffix(".source.json").write_text(
        json.dumps(
            {
                "schema": "gem5.selected-table-method-component.v1",
                "source": str(source),
                "source_bytes": len(raw),
                "source_sha256": hashlib.sha256(raw).hexdigest(),
                "output_sha256": hashlib.sha256(rendered).hexdigest(),
                "methods": [
                    {"name": name, "bytes": len(body),
                     "sha256": hashlib.sha256(body).hexdigest()}
                    for name, body in bodies
                ],
                "configured_translation_unit_qualified": False,
                "native_authority": False,
            },
            indent=2,
            sort_keys=True,
        ) + "\n"
    )


if __name__ == "__main__":
    main()
