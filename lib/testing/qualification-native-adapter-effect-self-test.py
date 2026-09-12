"""Exercises production effect-boundary evidence validation."""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import sys


def load(name: str, path: pathlib.Path):
    """Loads one checked-in helper under a stable module name."""

    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def rejected(action) -> None:
    """Requires a mutated evidence value to fail closed."""

    try:
        action()
    except RuntimeError:
        return
    raise AssertionError("mutated effect-boundary evidence was accepted")


def main() -> None:
    """Constructs one exact production-shaped plan and rejects false facts."""

    cohort = load("matrix_cohort", pathlib.Path(sys.argv[1]))
    evidence = load("effect_evidence", pathlib.Path(sys.argv[2]))
    digest = lambda byte: "sha256:" + byte * 64
    interface = {"name": "aos.test-effects", "abi": 1, "descriptor": digest("1")}
    binding = {"environment": "fixture", "key": "terminal"}
    target = {
        "interface": interface,
        "resource": {"provider": "fixture", "key": "owned"},
        "operations": ["apply"],
        "lifetime": "instance",
    }
    operation_key = {"scope": ["fixture"], "key": "apply-owned"}
    dependent_key = {"scope": ["fixture"], "key": "observe-owned"}
    operation = {
        "key": operation_key,
        "binding": binding,
        "interface": interface,
        "method": "apply",
        "target": target,
    }
    dependent = {
        "key": dependent_key,
        "binding": binding,
        "interface": interface,
        "method": "observe",
        "target": {**target, "operations": ["observe"]},
    }
    implementation = {
        "descriptor": digest("2"),
        "artifact": {
            "content": digest("3"),
            "store_path": "/nix/store/fixture-provider",
            "nar_hash": digest("4"),
            "closure": digest("5"),
        },
        "handler": "native-test",
    }
    edge = {
        "from": {"kind": "operation", "key": operation_key},
        "to": {"kind": "operation", "key": dependent_key},
        "kind": "required-success",
    }
    bundle = {
        "schema": "aos.ability.plan-bundle/v1",
        "plan": digest("6"),
        "desired": {
            "snapshot": {
                "resolution": {
                    "binding_document": {
                        "bindings": [
                            {
                                "id": binding,
                                "implementation": implementation,
                            }
                        ]
                    }
                }
            }
        },
        "current": None,
        "transition": {
            "effect_document": {
                "operations": [operation, dependent],
                "edges": [edge],
            }
        },
    }
    bundle_bytes = evidence.canonical(bundle)
    cell_id = (
        "test-adapter/aos.test-effects/abi-1/apply/"
        "interrupt-after-durable-intent"
    )
    cell = {
        "id": cell_id,
        "adapter": "test-adapter",
        "effect_class": "mutation",
        "interface": interface,
        "method": "apply",
        "postconditions": list(cohort.POSTCONDITION_KINDS)[:4],
    }
    observation = evidence.EffectBoundaryObservation(
        transaction="effect-flight",
        operation_key=operation_key,
        journal_before_loss="7" * 64,
        timeline=[
            {"sequence": 1, "kind": "operation-admitted", "node-ordinal": 0},
            {"sequence": 2, "kind": "effect-started", "node-ordinal": 0},
            {"sequence": 3, "kind": "operation-admitted", "node-ordinal": 0},
            {"sequence": 4, "kind": "reconciliation-started", "node-ordinal": 0},
            {"sequence": 5, "kind": "reconciled-safe-to-retry", "node-ordinal": 0},
            {"sequence": 6, "kind": "operation-admitted", "node-ordinal": 0},
            {"sequence": 7, "kind": "effect-started", "node-ordinal": 0},
            {"sequence": 8, "kind": "effect-completed", "node-ordinal": 0},
        ],
        boundary_timeline=[
            {
                "transcript-position": 2,
                "purpose": "effect",
                "boundary": "effect-intent-durable",
            },
            {
                "transcript-position": 4,
                "purpose": "effect",
                "boundary": "effect-outcome-durable",
            },
        ],
        interruption_position=2,
        settlement_sequence=8,
        settlement_position=4,
        owner_baseline={"count": 1, "identities": [{"resource": target["resource"]}]},
        owner_unsettled={"count": 1, "identities": [{"resource": target["resource"]}]},
        owner_after={"count": 1, "identities": [{"resource": target["resource"]}]},
        live_baseline={"revision": "old"},
        live_unsettled={"revision": "old"},
        live_after={"revision": "new"},
        foreign_baseline={"revision": "foreign"},
        foreign_unsettled={"revision": "foreign"},
        foreign_after={"revision": "foreign"},
        dependent_operation={
            "key": dependent_key,
            "ordinal": 1,
            "interface": interface,
            "method": "observe",
            "target": dependent["target"],
        },
        dependent_before=[],
        dependent_after=[
            {"sequence": 9, "kind": "effect-started", "node-ordinal": 1}
        ],
        dependent_boundary_after=[
            {
                "transcript-position": 7,
                "purpose": "effect",
                "boundary": "effect-intent-durable",
            }
        ],
    )
    builder = evidence.EffectBoundaryEvidence({"cells": [cell]}, [cell_id])
    builder.retain(cell_id, bundle_bytes, observation)
    subjects, bundles, probes = builder.finish()
    subject = subjects[cell_id]

    cohort._validate_effect_boundary_subject(cell, subject, bundles[cell_id])
    for postcondition, record in probes[cell_id].items():
        cohort._validate_effect_boundary_probe_facts(
            postcondition, record["observations"], subject, cell
        )

    wrong_handler = copy.deepcopy(subject)
    wrong_handler["provider-implementation"]["handler"] = "other"
    rejected(
        lambda: cohort._validate_effect_boundary_subject(
            cell, wrong_handler, bundles[cell_id]
        )
    )
    wrong_foreign = copy.deepcopy(
        probes[cell_id]["foreign-resources-unchanged"]["observations"]
    )
    wrong_foreign["snapshot-after"] = {"revision": "mutated"}
    rejected(
        lambda: cohort._validate_effect_boundary_probe_facts(
            "foreign-resources-unchanged", wrong_foreign, subject, cell
        )
    )
    wrong_dependency = copy.deepcopy(
        probes[cell_id]["dependent-effects-not-executed"]["observations"]
    )
    wrong_dependency["timeline-before-settlement"] = wrong_dependency[
        "timeline-after-settlement"
    ]
    rejected(
        lambda: cohort._validate_effect_boundary_probe_facts(
            "dependent-effects-not-executed", wrong_dependency, subject, cell
        )
    )


if __name__ == "__main__":
    main()
