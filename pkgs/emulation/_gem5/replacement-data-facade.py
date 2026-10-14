# SPDX-License-Identifier: MIT
"""Extracts the complete unchanged data declaration for a component fixture."""

from pathlib import Path
import hashlib
import json
import sys


def main():
    if len(sys.argv) != 3:
        raise ValueError("expected actual upstream header and output facade")
    source = Path(sys.argv[1])
    with source.open("rb") as stream:
        raw = stream.read(65537)
    declaration = b"struct ReplacementData {};"
    if len(raw) > 65536 or raw.count(declaration) != 1:
        raise ValueError("the exact complete upstream declaration changed")

    output = Path(sys.argv[2])
    output.write_bytes(
        b"// Component-only source-exact declaration; not a configured gem5 TU.\n"
        b"namespace gem5 { namespace replacement_policy {\n"
        + declaration
        + b"\n} }\n"
    )
    output.with_suffix(".source.json").write_text(
        json.dumps(
            {
                "schema": "gem5.replacement-data-component-facade.v1",
                "actual_source": str(source),
                "actual_source_bytes": len(raw),
                "actual_source_sha256": hashlib.sha256(raw).hexdigest(),
                "complete_declaration": declaration.decode("ascii"),
                "facade_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                "full_translation_unit_qualified": False,
                "native_authority": False,
            },
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
