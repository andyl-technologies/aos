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


def applicable_cells(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Validates the exact exclusion partition and returns its complement."""

    cells = spec.get("cells")
    applicability = spec.get("applicability")
    if not isinstance(cells, list) or not isinstance(applicability, dict):
        raise RuntimeError("matrix applicability is missing")

    adapters = spec.get("surface", {}).get("adapters")
    if not isinstance(adapters, list):
        raise RuntimeError("matrix provider contracts are missing")
    contracts = {}
    for adapter in adapters:
        contract = adapter.get("provider_contract")
        if (
            not isinstance(contract, dict)
            or not isinstance(contract.get("lifecycle"), dict)
            or not isinstance(contract.get("resource_lifetimes"), list)
            or len(contract["resource_lifetimes"])
            != len(set(contract["resource_lifetimes"]))
            or not all(
                isinstance(value, str) and value
                for value in contract["resource_lifetimes"]
            )
            or (
                contract.get("state_format") is not None
                and (
                    not isinstance(contract.get("state_format"), str)
                    or len(contract["state_format"]) != 71
                    or not contract["state_format"].startswith("sha256:")
                    or any(
                        character not in "0123456789abcdef"
                        for character in contract["state_format"][7:]
                    )
                )
            )
            or adapter.get("adapter") in contracts
        ):
            raise RuntimeError("matrix provider contract metadata is malformed")
        contracts[adapter.get("adapter")] = contract

    expected = []
    for cell in cells:
        contract = contracts.get(cell["adapter"])
        if contract is None:
            raise RuntimeError("matrix cell has no authenticated provider contract")
        scenario = cell.get("applicability")
        if (
            not isinstance(scenario, dict)
            or not isinstance(scenario.get("required_resource_lifetimes"), list)
            or not isinstance(scenario.get("requires_state_format"), bool)
        ):
            raise RuntimeError("matrix cell has no typed applicability declaration")
        if any(
            lifetime not in contract["resource_lifetimes"]
            for lifetime in scenario["required_resource_lifetimes"]
        ):
            reason = "required-resource-lifetime-unavailable"
        elif scenario["requires_state_format"] and contract["state_format"] is None:
            reason = "missing-authenticated-state-format"
        else:
            continue
        expected.append({"cell_id": cell["id"], "reason": reason})

    if (
        set(applicability)
        != {"schema", "required_production_vm_cells", "inapplicable_cells"}
        or applicability.get("schema") != APPLICABILITY_SCHEMA
        or applicability.get("inapplicable_cells") != expected
        or applicability.get("required_production_vm_cells")
        != len(cells) - len(expected)
    ):
        raise RuntimeError("matrix applicability differs from provider contracts")

    excluded = {entry["cell_id"] for entry in expected}
    return [cell for cell in cells if cell["id"] not in excluded]


def main() -> None:
    """Writes an exact, uniformly unqualified matrix report."""

    request = read_json(REQUEST)
    spec = read_json(SPEC)
    scenario_registry = read_json(SCENARIO_REGISTRY)
    case = request["qualification_case"]
    spec_digest = sha256(spec)
    check = "native-adapter-matrix-v1-sha256-" + spec_digest.removeprefix("sha256:")
    if (
        request["policy_id"] != "ability-native-adapter-matrix"
        or case["requirement_id"] != "ability-native-adapter-matrix"
        or case["checks"] != [EXPECTED_CHECK]
        or check != EXPECTED_CHECK
        or not case.get("predecessor")
        or not case.get("subjects")
    ):
        raise RuntimeError("matrix specification differs from the exact qualification case")

    started = time.time()
    environment = {
        "schema_version": "aos.release.native-adapter-matrix-environment/v1",
        "status": "unqualified",
        "platform": request["platform"],
        "spec_digest": spec_digest,
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
            "spec": spec,
            "spec_digest": spec_digest,
            "environment": environment,
            "cells": cells,
        },
    }
    REPORT.write_bytes(canonical(report))


if __name__ == "__main__":
    main()
