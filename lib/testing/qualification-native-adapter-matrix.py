"""Emits explicit unqualified results until production VM cohorts exist.

The adapter exercises no native effect and therefore cannot report a passing
cell. It exists to carry the exact immutable specification through the release
executor and prove that admission derives failure from per-cell results.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import time
from typing import Any


ROOT = pathlib.Path.cwd()
REQUEST = ROOT / "request.json"
REPORT = ROOT / "scenario-report.json"
SPEC = pathlib.Path(os.environ["AOS_QUALIFICATION_NATIVE_ADAPTER_MATRIX_SPEC"])
EXPECTED_CHECK = os.environ["AOS_QUALIFICATION_NATIVE_ADAPTER_MATRIX_CHECK"]
SCENARIO_REGISTRY = ROOT / "scenario-registry.json"
APPLICABILITY_SCHEMA = "aos.qualification.native-adapter-matrix-applicability/v1"


def canonical(value: Any) -> bytes:
    """Encodes the canonical JSON representation used by release evidence."""

    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def sha256(value: Any) -> str:
    """Computes raw SHA-256 over one canonical value."""

    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def separated(domain: str, value: Any) -> str:
    """Computes a domain-separated canonical identity."""

    hashed = hashlib.sha256()
    hashed.update(domain.encode())
    hashed.update(b"\0")
    hashed.update(canonical(value))
    return "sha256:" + hashed.hexdigest()


def read_json(path: pathlib.Path) -> Any:
    """Reads a bounded executor-owned JSON input."""

    if path.stat().st_size > 16 * 1024 * 1024:
        raise RuntimeError(f"qualification input is oversized: {path}")
    with path.open("rb") as source:
        return json.load(source)


def read_canonical_json(path: pathlib.Path) -> Any:
    """Reads one canonical JSON artifact and rejects equivalent encodings."""

    raw = path.read_bytes()
    if len(raw) > 16 * 1024 * 1024:
        raise RuntimeError(f"qualification input is oversized: {path}")
    value = json.loads(raw)
    if canonical(value) != raw:
        raise RuntimeError("matrix specification is not its authoritative canonical bytes")
    return value


def applicable_cells(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Returns the authoritative applicable partition after reference checks."""

    cells = spec.get("cells")
    applicability = spec.get("applicability")
    if not isinstance(cells, list) or not isinstance(applicability, dict):
        raise RuntimeError("matrix applicability is missing")
    if set(applicability) != {"schema", "applicable_cell_ids", "inapplicable_cells"}:
        raise RuntimeError("matrix applicability has unknown fields")
    if applicability.get("schema") != APPLICABILITY_SCHEMA:
        raise RuntimeError("matrix applicability has an unsupported schema")

    cell_by_id = {cell.get("id"): cell for cell in cells if isinstance(cell, dict)}
    applicable_ids = applicability.get("applicable_cell_ids")
    inapplicable = applicability.get("inapplicable_cells")
    if (
        len(cell_by_id) != len(cells)
        or not isinstance(applicable_ids, list)
        or applicable_ids != sorted(set(applicable_ids))
        or not isinstance(inapplicable, list)
    ):
        raise RuntimeError("matrix cell identities or applicability order are malformed")
    inapplicable_ids = [entry.get("cell_id") for entry in inapplicable if isinstance(entry, dict)]
    if (
        len(inapplicable_ids) != len(inapplicable)
        or inapplicable_ids != sorted(set(inapplicable_ids))
        or set(applicable_ids).intersection(inapplicable_ids)
        or set(applicable_ids).union(inapplicable_ids) != set(cell_by_id)
        or any(
            set(entry) != {"cell_id", "reason"}
            or entry.get("reason")
            not in {
                "required-resource-lifetime-unavailable",
                "missing-authenticated-state-format",
            }
            for entry in inapplicable
        )
    ):
        raise RuntimeError("matrix applicability is not an exact cell partition")

    return [cell_by_id[cell_id] for cell_id in applicable_ids]

def main() -> None:
    """Writes an exact, uniformly unqualified matrix report."""

    request = read_json(REQUEST)
    spec = read_canonical_json(SPEC)
    scenario_registry = read_json(SCENARIO_REGISTRY)
    case = request["qualification_case"]
    if (
        request["policy_id"] != "ability-native-adapter-matrix"
        or case["requirement_id"] != "ability-native-adapter-matrix"
        or case["checks"] != [EXPECTED_CHECK]
        or EXPECTED_CHECK != "native-adapter-matrix"
        or case.get("matrix_spec") != spec
        or not case.get("predecessor")
        or not case.get("subjects")
    ):
        raise RuntimeError("matrix specification differs from the exact qualification case")

    started = time.time()
    environment = {
        "schema_version": "aos.release.native-adapter-matrix-environment/v1",
        "status": "unqualified",
        "platform": request["platform"],
        "scenario_registry_digest": sha256(scenario_registry),
        "candidate_subjects_digest": case["subjects_digest"],
        "predecessor_manifest_digest": case["predecessor"]["manifest_digest"],
        "unqualified_reason": "no production VM cohort observation exists",
    }
    environment_digest = sha256(environment)
    cells = []
    postcondition_count = 0
    for cell in applicable_cells(spec):
        postconditions = {
            name: {
                "passed": False,
                "detail": "unqualified: no production VM cohort observation exists",
            }
            for name in cell["postconditions"]
        }
        postcondition_count += len(postconditions)
        cells.append(
            {
                "id": cell["id"],
                "cell_digest": sha256(cell),
                "environment_digest": environment_digest,
                "postconditions": postconditions,
            }
        )

    finished = time.time()
    report = {
        "schema_version": "aos.release.qualification-scenario-report/v1",
        "registry": request["registry"],
        "release_id": request["release_id"],
        "staging_receipt_digest": request["staging_receipt_digest"],
        "manifest_digest": request["manifest_digest"],
        "case_digest": separated("aos.release.qualification-case/v2", case),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(finished)),
        "observed_seconds": int(finished - started),
        "checks": {},
        "operations": {
            "matrix_cells_reported": len(cells),
            "matrix_postconditions_reported": postcondition_count,
        },
        "environment": environment,
        "native_adapter_matrix": {
            "schema_version": "aos.release.native-adapter-matrix-observation/v1",
            "environment": environment,
            "cells": cells,
        },
    }
    REPORT.write_bytes(canonical(report))


if __name__ == "__main__":
    main()
