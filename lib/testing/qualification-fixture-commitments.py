"""Commits original fixture exports in the configured executor registry.

The registry is a trusted executor control input. These build-time commitments
bind its fixture bytes; they do not represent candidate-image signatures or
make an ambient store inventory authoritative at execution time.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat
import sys
from typing import Any


STORE_LOCATOR = re.compile(r"^(/nix/store/[0123456789abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+)(/[^\x00]*)?$")
DOCUMENT_LIMIT = 64 * 1024 * 1024
ARCHIVE_LIMIT = 128 * 1024 * 1024 * 1024


def store_root(locator: str) -> str:
    """Requires a canonical immutable root or a safe file within that root."""
    match = STORE_LOCATOR.fullmatch(locator) if isinstance(locator, str) else None
    if match is None or any(part in {".", "..", ""} for part in locator.split("/")[4:]):
        raise ValueError("fixture locator is not an immutable store path")
    return match.group(1)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Rejects repeated JSON object keys instead of silently replacing evidence."""
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("fixture document repeats an object key")
        document[key] = value
    return document


def read_document(path: Path) -> Any:
    """Reads one bounded regular fixture document without following a symlink."""
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > DOCUMENT_LIMIT:
        raise ValueError("fixture document is not a bounded regular file")
    with path.open("rb") as source:
        contents = source.read(DOCUMENT_LIMIT + 1)
    if len(contents) > DOCUMENT_LIMIT:
        raise ValueError("fixture document exceeds its read bound")
    return json.loads(contents, object_pairs_hook=unique_object)


def file_commitment(path: Path, limit: int) -> dict[str, Any]:
    """Hashes the actual built file bytes with a bounded streaming reader."""
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1 or metadata.st_size > limit:
        raise ValueError("fixture evidence is not a bounded nonempty regular file")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while block := source.read(8 * 1024 * 1024):
            size += len(block)
            if size > limit:
                raise ValueError("fixture evidence exceeds its read bound")
            digest.update(block)
    if size != metadata.st_size:
        raise ValueError("fixture evidence changed during commitment")
    return {"path": str(path), "sha256": "sha256:" + digest.hexdigest(), "size_bytes": size}


def validate_evaluations(evaluations: Any, inventory: Any) -> None:
    """Requires each declared bundle and source root in the original export graph."""
    if not isinstance(inventory, dict) or inventory.get("schema") != "aos.reference-graph/v1":
        raise ValueError("fixture inventory has another schema")
    roots = inventory.get("roots")
    members = inventory.get("paths")
    if not isinstance(roots, list) or not isinstance(members, list):
        raise ValueError("fixture inventory lacks its original roots and members")
    if any(store_root(root) != root for root in roots) or len(set(roots)) != len(roots):
        raise ValueError("fixture inventory roots are malformed")
    paths = [member["path"] for member in members]
    if len(paths) != len(set(paths)) or any(store_root(path) != path for path in paths):
        raise ValueError("fixture inventory members are malformed")
    if set(roots) - set(paths):
        raise ValueError("fixture inventory omits an explicit root")
    if not isinstance(evaluations, dict) or len(evaluations) > 4096:
        raise ValueError("fixture evaluations are malformed")
    for cohort, binding in evaluations.items():
        if not isinstance(cohort, str) or not cohort or not isinstance(binding, dict) or set(binding) != {"selected_evaluation", "adoption_evaluation"}:
            raise ValueError("fixture cohort requires both evaluation bindings")
        for selection in binding.values():
            validate_selection(selection, roots)


def validate_selection(selection: Any, roots: list[str]) -> None:
    """Binds one explicit target or adoption evaluation to original export roots."""
    if not isinstance(selection, dict) or set(selection) != {"role", "locator", "scenario_sources"}:
        raise ValueError("fixture evaluation binding is malformed")
    sources = selection["scenario_sources"]
    if selection["role"] not in {"candidate-baseline", "scenario"} or not isinstance(sources, list) or len(sources) > 4096:
        raise ValueError("fixture evaluation source role is malformed")
    if len(set(sources)) != len(sources) or (selection["role"] == "candidate-baseline") != (sources == []):
        raise ValueError("fixture evaluation sources disagree with its role")
    locator = selection["locator"]
    if store_root(locator) != locator:
        raise ValueError("fixture evaluation locator is not one bundle root")
    if any(root not in roots for root in [locator, *(store_root(source) for source in sources)]):
        raise ValueError("fixture evaluation is absent from the original export roots")


def commit_registry(document: Any) -> dict[str, Any]:
    """Binds original built fixture bytes to their configured executable selection."""
    if not isinstance(document, dict) or set(document) != {"registry", "fixtures"}:
        raise ValueError("executor registry inputs are malformed")
    registry = document["registry"]
    fixtures = document["fixtures"]
    if not isinstance(registry, dict) or not isinstance(fixtures, dict) or "fixture_inputs" in registry:
        raise ValueError("executor fixture commitments cannot be predeclared")
    executables = set(registry["scenarios"].values()) | set(registry.get("case_scenarios", {}).values())
    commitments = {}
    for executable, fixture in fixtures.items():
        if executable not in executables:
            raise ValueError("fixture executable is not selected by the configured registry")
        store_root(executable)
        if store_root(fixture) != fixture:
            raise ValueError("fixture archive is not one immutable output root")
        root = Path(fixture)
        inventory = root / "inventory.json"
        evaluations = root / "evaluations.json"
        validate_evaluations(read_document(evaluations), read_document(inventory))
        commitments[executable] = {
            "archive": file_commitment(root / "fixture.export", ARCHIVE_LIMIT),
            "inventory": file_commitment(inventory, DOCUMENT_LIMIT),
            "evaluations": file_commitment(evaluations, DOCUMENT_LIMIT),
        }
    return registry | ({"fixture_inputs": commitments} if commitments else {})


def main() -> None:
    """Writes canonical registry bytes containing only build-time commitments."""
    if len(sys.argv) != 3:
        raise ValueError("usage: qualification-fixture-commitments.py INPUT OUTPUT")
    registry = commit_registry(read_document(Path(sys.argv[1])))
    Path(sys.argv[2]).write_bytes(json.dumps(registry, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())


if __name__ == "__main__":
    main()
