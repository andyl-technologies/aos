"""Verify a context map through one persistent libselinux resolver."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from context_plan import FileContextResolver, InodeKind, PlanError


def verify(file_contexts: Path, library: Path, expected_path: Path) -> None:
    """Requires every planned context to round-trip through libselinux."""

    document = json.loads(expected_path.read_text(encoding="utf-8"))
    if document.get("version") != 1 or not isinstance(document.get("entries"), list):
        raise PlanError("expected map must use schema version 1")

    with FileContextResolver(library, file_contexts) as resolver:
        for entry in document["entries"]:
            try:
                path = entry["path"]
                kind = InodeKind[entry["kind"]]
                expected = entry["context"]
            except (KeyError, TypeError) as error:
                raise PlanError("invalid expected context-map entry") from error

            observed = resolver.lookup(path, kind)
            if observed != expected:
                raise PlanError(
                    f"file-context round-trip differs for {path!r}: "
                    f"expected {expected!r}, observed {observed!r}"
                )


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    """Parses verifier command-line arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--file-contexts", type=Path, required=True)
    parser.add_argument("--libselinux", type=Path, required=True)
    parser.add_argument("--expected", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Verifies one compiled file-context database and expected map."""

    options = parse_args(sys.argv[1:] if argv is None else argv)
    verify(options.file_contexts, options.libselinux, options.expected)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, PlanError) as error:
        print(f"verify-context-lookups: {error}", file=sys.stderr)
        raise SystemExit(1) from error
