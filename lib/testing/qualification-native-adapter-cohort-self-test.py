"""Exercises generic native-adapter cohort aggregation and validator routing."""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import sys
from typing import Any


DIGESTS = {
    name: "sha256:" + byte * 64
    for name, byte in {
        "interface": "1",
        "implementation": "2",
        "artifact": "3",
        "contract": "4",
        "subject": "5",
        "environment": "6",
        "state": "7",
    }.items()
}


def load(path: pathlib.Path):
    """Loads the cohort helper from the path supplied by its derivation."""

    spec = importlib.util.spec_from_file_location("matrix_cohort", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load matrix cohort helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FixtureValidator:
    """Accepts the bounded semantic fixture used by the aggregation test."""

    @staticmethod
    def accepts_subject(subject: Any) -> bool:
        return isinstance(subject, dict) and subject.get("schema") == "fixture/v1"

    @staticmethod
    def validate_subject(cell, subject, evidence_bytes, matrix_spec, routes) -> None:
        if (
            subject != {"schema": "fixture/v1", "resource": "fixture-resource"}
            or evidence_bytes != b"fixture-evidence"
            or cell["id"] not in {entry["id"] for entry in matrix_spec["cells"]}
            or len(routes) != 1
        ):
            raise RuntimeError("fixture subject is malformed")

    @staticmethod
    def validate_probe(
        postcondition, observations, cohort_subject, cell, matrix_spec
    ) -> None:
        if (
            postcondition != "compatible-state-adopted"
            or observations
            != {
                "resource": cohort_subject["resource"],
                "state": "compatible",
            }
            or not cell["id"].endswith("/adopt-compatible-state")
            or matrix_spec["cells"] != [cell]
        ):
            raise RuntimeError("fixture observation is malformed")


class FixtureSpecializedValidator:
    """Provides deterministic specialized and snapshot registry results."""

    @staticmethod
    def validate_provider_negative_cell(*_args):
        return ({"subject": True}, {"postcondition": True}, {"probe": True})

    @staticmethod
    def validate_cancellation_snapshot(expected_kind, value):
        if isinstance(value, dict) and value.get("specialized") is True:
            return value.get("kind") == expected_kind
        return None


def cell() -> dict[str, Any]:
    """Returns the one exact matrix cell used by this test."""

    return {
        "id": "fixture/aos.fixture/abi-1/apply/adopt-compatible-state",
        "matrix_schema": "aos.qualification.native-adapter-matrix/v1",
        "adapter": "fixture",
        "interface": {
            "name": "aos.fixture",
            "abi": 1,
            "descriptor": DIGESTS["interface"],
        },
        "method": "apply",
        "effect_class": "mutation",
        "scope": "fixture-resource",
        "boundary": "recovery",
        "failure": "none",
        "predecessor": "compatible",
        "candidate": "same",
        "postconditions": ["compatible-state-adopted"],
        "postcondition_kinds": {"compatible-state-adopted": "state-adoption"},
        "invalidated_by": ["subject", "policy", "executor", "environment"],
    }


def specification(matrix_cell: dict[str, Any]) -> dict[str, Any]:
    """Builds a closed package-derived matrix around one cell."""

    return {
        "schema": "aos.qualification.native-adapter-matrix-spec/v1",
        "surface": {
            "adapters": [
                {
                    "adapter": "fixture",
                    "interface_name": "aos.fixture",
                    "interface_abi": 1,
                    "interface_descriptor": DIGESTS["interface"],
                    "methods": [{"method": "apply", "effect_class": "mutation"}],
                    "provider_contract": {
                        "resource_lifetime": "persistent",
                        "state_format": DIGESTS["state"],
                    },
                }
            ]
        },
        "cells": [matrix_cell],
        "applicability": {
            "schema": "aos.qualification.native-adapter-matrix-applicability/v1",
            "required_production_vm_cells": 1,
            "inapplicable_cells": [],
        },
    }


def qualification_subject(module, spec) -> dict[str, Any]:
    """Builds the signed-route projection consumed by the generic aggregator."""

    return {
        "schema": module.QUALIFICATION_SUBJECT_SCHEMA,
        "matrix-spec-digest": module.sha256(spec),
        "routes": [
            {
                "adapter": "fixture",
                "interface": cell()["interface"],
                "methods": ["apply"],
                "provenance": [
                    {
                        "package": "fixture-package",
                        "ability-contract": DIGESTS["contract"],
                    }
                ],
                "implementation": DIGESTS["implementation"],
                "handler": "fixture-handler",
                "artifact": DIGESTS["artifact"],
                "entry-point": "libexec/fixture-handler",
            }
        ],
    }


def build_arguments(module) -> tuple[dict[str, Any], list[Any]]:
    """Returns one passing specification and its positional build arguments."""

    matrix_cell = cell()
    spec = specification(matrix_cell)
    subject = {"schema": "fixture/v1", "resource": "fixture-resource"}
    submissions = {
        matrix_cell["id"]: {
            "compatible-state-adopted": {
                "kind": "state-adoption",
                "detail": "the compatible state was adopted",
                "disposition": "compatible-state-adopted",
                "observations": {
                    "resource": "fixture-resource",
                    "state": "compatible",
                },
            }
        }
    }
    arguments = [
        submissions,
        [matrix_cell["id"]],
        {matrix_cell["id"]: subject},
        {matrix_cell["id"]: b"fixture-evidence"},
        DIGESTS["subject"],
        DIGESTS["environment"],
        None,
        None,
        None,
        qualification_subject(module, spec),
    ]
    return spec, arguments


def rejects(call, detail: str) -> None:
    """Requires one malformed fixture to fail closed."""

    try:
        call()
    except RuntimeError:
        return
    raise AssertionError(detail)


def assert_registry(module) -> None:
    """Checks unique subject, specialized-cell, and snapshot dispatch."""

    registry_type = module.provider_evidence.EvidenceValidatorRegistry
    registry = registry_type(
        subjects=(FixtureValidator,),
        specialized_cells=(FixtureSpecializedValidator,),
        snapshots=(FixtureSpecializedValidator,),
    )
    module.provider_evidence.DEFAULT_REGISTRY = registry

    assert registry.valid_snapshot(
        "fixture-kind", {"kind": "fixture-kind", "specialized": True}
    )
    assert registry.valid_snapshot("plain-kind", {"kind": "plain-kind"})

    ambiguous = registry_type(
        subjects=(FixtureValidator, FixtureValidator),
        specialized_cells=(FixtureSpecializedValidator, FixtureSpecializedValidator),
        snapshots=(FixtureSpecializedValidator, FixtureSpecializedValidator),
    )
    rejects(
        lambda: ambiguous.validate_subject(
            cell(),
            {"schema": "fixture/v1"},
            b"fixture-evidence",
            specification(cell()),
            [],
        ),
        "validator registry accepted an ambiguous subject",
    )
    rejects(
        lambda: ambiguous.validate_specialized_cell(
            cell(), {}, DIGESTS["subject"], set(), specification(cell()), {}
        ),
        "validator registry accepted an ambiguous specialized cell",
    )
    assert not ambiguous.valid_snapshot(
        "fixture-kind", {"kind": "fixture-kind", "specialized": True}
    )


def main() -> None:
    """Runs one positive aggregation and table-driven boundary mutations."""

    if len(sys.argv) != 3:
        raise RuntimeError("usage: self-test.py COHORT.py SCENARIOS.json")
    module = load(pathlib.Path(sys.argv[1]))
    assert_registry(module)

    spec, arguments = build_arguments(module)
    observations, count = module.build_cells(spec, *arguments)
    assert count == 1
    assert observations[0]["id"] == spec["cells"][0]["id"]
    assert observations[0]["postconditions"] == {
        "compatible-state-adopted": {
            "passed": True,
            "detail": "the compatible state was adopted",
        }
    }
    probe = observations[0]["probes"]["compatible-state-adopted"]
    assert probe["cell_digest"] == module.sha256(spec["cells"][0])
    assert probe["subject_digest"] == DIGESTS["subject"]

    mutations = []

    wrong_scope = copy.deepcopy(arguments)
    wrong_scope[1] = []
    mutations.append((spec, wrong_scope, "accepted missing cell scope"))

    repeated_scope = copy.deepcopy(arguments)
    repeated_scope[1].append(repeated_scope[1][0])
    mutations.append((spec, repeated_scope, "accepted repeated cell scope"))

    wrong_disposition = copy.deepcopy(arguments)
    wrong_disposition[0][arguments[1][0]]["compatible-state-adopted"][
        "disposition"
    ] = "invented-success"
    mutations.append((spec, wrong_disposition, "accepted an invented disposition"))

    forged_route = copy.deepcopy(arguments)
    forged_route[-1]["routes"][0]["artifact"] = "sha256:short"
    mutations.append((spec, forged_route, "accepted a forged package route"))

    wrong_applicability = copy.deepcopy(spec)
    wrong_applicability["applicability"]["required_production_vm_cells"] = 0
    mutations.append(
        (wrong_applicability, arguments, "accepted incorrect applicability")
    )

    for changed_spec, changed_arguments, detail in mutations:
        rejects(
            lambda changed_spec=changed_spec, changed_arguments=changed_arguments: module.build_cells(
                changed_spec, *changed_arguments
            ),
            detail,
        )


if __name__ == "__main__":
    main()
