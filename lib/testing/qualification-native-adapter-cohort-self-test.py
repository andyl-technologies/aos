"""Exercises fail-closed matrix cohort probe construction."""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import sys


def load(path: pathlib.Path):
    """Loads the cohort helper from the path supplied by its derivation."""

    spec = importlib.util.spec_from_file_location("matrix_cohort", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load matrix cohort helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def rejected(module, spec, probes, scope, subject, plan_bundle):
    """Requires one mutated probe population to fail closed."""

    try:
        module.build_cells(
            spec,
            probes,
            scope,
            subject,
            plan_bundle,
            "sha256:" + "11" * 32,
            "sha256:" + "22" * 32,
        )
    except RuntimeError:
        return
    raise AssertionError("mutated cohort probe was accepted")


def main() -> None:
    """Checks exact success and representative scope/probe mutations."""

    module = load(pathlib.Path(sys.argv[1]))
    cell_id = (
        "managed-configuration/aos.managed-configuration-effects/abi-1/"
        "publish/lose-external-result"
    )
    names = [
        "durable-attempt-state-classified",
        "at-most-one-resource-owner",
        "foreign-resources-unchanged",
        "dependent-effects-not-executed",
    ]
    interface = {
        "name": "aos.managed-configuration-effects",
        "abi": 1,
        "descriptor": (
            "sha256:682ee08aadd9d0198b409146a373bf38d901ba530b74180400c9087616a41dab"
        ),
    }
    environment = {"authority": "reference", "key": "host", "stage": "host"}
    publish_descriptor = "sha256:" + "33" * 32
    dependent_descriptor = "sha256:" + "44" * 32
    publish_key = {
        "scope": ["shared-configuration", publish_descriptor.removeprefix("sha256:")],
        "key": "publish-nginx-secondary-configuration",
    }
    dependent_key = {
        "scope": ["nginx-secondary", dependent_descriptor.removeprefix("sha256:")],
        "key": "reload-nginx-secondary-service",
    }
    publish_target = {
        "interface": interface,
        "resource": {
            "provider": {
                "environment": environment,
                "key": "shared-configuration",
            },
            "key": "nginx-secondary-configuration",
        },
        "operations": ["publish"],
        "lifetime": "instance",
    }
    dependent_interface = {
        "name": "aos.systemd-service-effects",
        "abi": 1,
        "descriptor": (
            "sha256:e02cd9535b3f97fbaf41066fd4b6ac8c2aa315f38188fb669815dccd291b4f98"
        ),
    }
    dependent_target = {
        "interface": dependent_interface,
        "resource": {
            "provider": {"environment": environment, "key": "shared-service"},
            "key": "nginx-secondary-service",
        },
        "operations": ["reload"],
        "lifetime": "instance",
    }
    spec = {
        "cells": [
            {
                "id": cell_id,
                "interface": interface,
                "method": "publish",
                "postconditions": names,
            }
        ]
    }
    observations = {
        "durable-attempt-state-classified": {
            "transaction": "transaction",
            "plan": "sha256:" + "55" * 32,
            "journal-before-loss": "55" * 32,
            "operation": {
                "key": publish_key,
                "ordinal": 5,
                "interface": interface,
                "method": "publish",
                "target": publish_target,
            },
            "timeline": [
                {"sequence": 4, "kind": "operation-admitted", "node-ordinal": 5},
                {"sequence": 5, "kind": "effect-started", "node-ordinal": 5},
                {"sequence": 6, "kind": "operation-admitted", "node-ordinal": 5},
                {
                    "sequence": 7,
                    "kind": "reconciliation-started",
                    "node-ordinal": 5,
                },
                {"sequence": 8, "kind": "reconciled-completed", "node-ordinal": 5},
            ],
            "boundary-timeline": [
                {
                    "transcript-position": 10,
                    "purpose": "effect",
                    "boundary": "effect-intent-durable",
                },
                {
                    "transcript-position": 11,
                    "purpose": "effect",
                    "boundary": "effect-returned",
                },
                {
                    "transcript-position": 12,
                    "purpose": "reconcile",
                    "boundary": "reconciliation-intent-durable",
                },
                {
                    "transcript-position": 13,
                    "purpose": "reconcile",
                    "boundary": "reconciliation-returned",
                },
                {
                    "transcript-position": 14,
                    "purpose": "reconcile",
                    "boundary": "reconciliation-outcome-durable",
                },
            ],
            "effect-return-position": 11,
            "reconciliation-return-position": 13,
        },
        "at-most-one-resource-owner": {
            "resource": {"provider": "fixture", "key": "configuration"},
            "destination": "/var/lib/fixture",
            "revision": "revision",
            "matching-markers": 1,
            "selected-after-gc": True,
        },
        "foreign-resources-unchanged": {
            "resource": {"provider": "fixture", "key": "foreign"},
            "revision": "foreign-revision",
            "content-before": "unchanged",
            "content-unsettled": "unchanged",
            "content-after-gc": "unchanged",
            "content-after-recovery": "unchanged",
        },
        "dependent-effects-not-executed": {
            "publish-operation": {
                "key": publish_key,
                "ordinal": 5,
                "interface": interface,
                "method": "publish",
                "target": publish_target,
            },
            "dependent-operation": {
                "key": dependent_key,
                "ordinal": 2,
                "interface": dependent_interface,
                "method": "reload",
                "target": dependent_target,
            },
            "dependency-edge": {
                "from": {"kind": "operation", "key": publish_key},
                "to": {"kind": "operation", "key": dependent_key},
                "kind": "required-success",
            },
            "timeline-before-completion": [],
            "effect-boundaries-before-completion": [],
            "publish-reconciled-sequence": 8,
            "publish-reconciliation-return-position": 13,
            "timeline-after-recovery": [
                {"sequence": 9, "kind": "operation-admitted", "node-ordinal": 2},
                {"sequence": 10, "kind": "effect-started", "node-ordinal": 2},
                {"sequence": 11, "kind": "effect-completed", "node-ordinal": 2},
            ],
            "effect-boundary-timeline": [
                {
                    "transcript-position": 15,
                    "purpose": "effect",
                    "boundary": "effect-intent-durable",
                },
                {
                    "transcript-position": 16,
                    "purpose": "effect",
                    "boundary": "effect-returned",
                },
                {
                    "transcript-position": 17,
                    "purpose": "effect",
                    "boundary": "effect-outcome-durable",
                },
            ],
            "dependent-effect-return-position": 16,
            "route-while-unsettled": "predecessor",
            "route-after-recovery": "candidate",
            "changed-only-after-recovery": True,
        },
    }
    publish_operation = observations["durable-attempt-state-classified"]["operation"]
    dependent_operation = observations["dependent-effects-not-executed"][
        "dependent-operation"
    ]
    plan_bundle_value = {
        "schema": "aos.ability.plan-bundle/v1",
        "plan": "sha256:" + "55" * 32,
        "transition": {
            "schema": "aos.ability.transition-snapshot/v1",
            "evaluations": [
                {
                    "provider": {
                        "environment": environment,
                        "key": "shared-configuration",
                    },
                    "implementation": {"descriptor": publish_descriptor},
                    "result": {"status": "returned"},
                },
                {
                    "provider": {
                        "environment": environment,
                        "key": "nginx-secondary",
                    },
                    "implementation": {"descriptor": dependent_descriptor},
                    "result": {"status": "returned"},
                },
            ],
            "effect_document": {
                "operations": [
                    {},
                    {},
                    dependent_operation,
                    {},
                    {},
                    publish_operation,
                ]
            },
        },
    }
    plan_bundle = module.canonical(plan_bundle_value)
    subject = {
        "schema": "aos.qualification.host-resource-cohort-subject/v1",
        "plan": "sha256:" + "55" * 32,
        "plan-bundle-digest": module.sha256(plan_bundle_value),
        "authoring-evaluations": {
            "publish": {
                "provider": {
                    "environment": environment,
                    "key": "shared-configuration",
                },
                "implementation-descriptor": publish_descriptor,
            },
            "dependent": {
                "provider": {
                    "environment": environment,
                    "key": "nginx-secondary",
                },
                "implementation-descriptor": dependent_descriptor,
            },
        },
        "publish-operation": publish_operation,
        "dependent-operation": dependent_operation,
    }
    probes = {
        cell_id: {
            name: {
                "kind": module.POSTCONDITION_KINDS[name],
                "detail": f"independent {name} probe passed",
                "observations": observations[name],
            }
            for name in names
        }
    }
    cells, count = module.build_cells(
        spec,
        probes,
        [cell_id],
        subject,
        plan_bundle,
        "sha256:" + "11" * 32,
        "sha256:" + "22" * 32,
    )
    assert count == 4
    assert all(value["passed"] for value in cells[0]["postconditions"].values())
    assert set(cells[0]["probes"]) == set(names)
    assert cells[0]["cohort_subject"] == subject
    assert {
        probe["cohort_subject_digest"] for probe in cells[0]["probes"].values()
    } == {module.sha256(subject)}

    def replace_nested(value, path, replacement):
        target = value
        for component in path[:-1]:
            target = target[component]
        target[path[-1]] = replacement

    def probes_for_subject(mutated_subject):
        mutated_probes = copy.deepcopy(probes)
        durable = mutated_probes[cell_id]["durable-attempt-state-classified"][
            "observations"
        ]
        durable["operation"] = copy.deepcopy(mutated_subject["publish-operation"])
        dependency = mutated_probes[cell_id]["dependent-effects-not-executed"][
            "observations"
        ]
        dependency["publish-operation"] = copy.deepcopy(
            mutated_subject["publish-operation"]
        )
        dependency["dependent-operation"] = copy.deepcopy(
            mutated_subject["dependent-operation"]
        )
        dependency["dependency-edge"]["from"]["key"] = copy.deepcopy(
            mutated_subject["publish-operation"]["key"]
        )
        dependency["dependency-edge"]["to"]["key"] = copy.deepcopy(
            mutated_subject["dependent-operation"]["key"]
        )
        return mutated_probes

    def rejected_dependent_operation(path, replacement):
        mutated_subject = copy.deepcopy(subject)
        replace_nested(
            mutated_subject["dependent-operation"], path, replacement
        )
        mutated_probes = probes_for_subject(mutated_subject)
        rejected(module, spec, mutated_probes, [cell_id], mutated_subject, plan_bundle)

    def rejected_publish_operation(path, replacement):
        mutated_subject = copy.deepcopy(subject)
        replace_nested(mutated_subject["publish-operation"], path, replacement)
        mutated_probes = probes_for_subject(mutated_subject)
        rejected(module, spec, mutated_probes, [cell_id], mutated_subject, plan_bundle)

    def rejected_author(role, field, replacement):
        mutated_subject = copy.deepcopy(subject)
        author = mutated_subject["authoring-evaluations"][role]
        operation = mutated_subject[f"{role}-operation"]
        if field == "provider":
            author["provider"]["key"] = replacement
            operation["key"]["scope"][0] = replacement
        else:
            author["implementation-descriptor"] = replacement
            operation["key"]["scope"][1] = replacement.removeprefix("sha256:")
        mutated_probes = probes_for_subject(mutated_subject)
        rejected(module, spec, mutated_probes, [cell_id], mutated_subject, plan_bundle)

    rejected_dependent_operation(("key", "scope", 0), "foreign")
    rejected_dependent_operation(("key", "scope", 1), "77" * 32)
    rejected_dependent_operation(
        ("target", "resource", "provider", "key"), "foreign-service"
    )
    rejected_dependent_operation(
        ("target", "resource", "key"), "foreign-service"
    )
    rejected_dependent_operation(("target", "lifetime"), "session")
    rejected_dependent_operation(
        ("target", "interface"), copy.deepcopy(interface)
    )
    rejected_dependent_operation(("target", "operations"), ["start"])
    rejected_publish_operation(
        ("key", "key"), "publish-foreign-configuration"
    )
    rejected_publish_operation(("ordinal",), 4)
    rejected_publish_operation(
        ("target", "resource", "provider", "key"), "foreign-configuration"
    )
    rejected_publish_operation(("key", "scope", 0), "foreign")
    rejected_publish_operation(
        ("target", "resource", "key"), "foreign-configuration"
    )
    rejected_publish_operation(("target", "lifetime"), "session")
    rejected_publish_operation(("target", "operations"), ["read"])
    rejected_author("publish", "provider", "foreign-configuration")
    rejected_author("publish", "descriptor", "sha256:" + "88" * 32)
    rejected_author("dependent", "provider", "foreign-nginx")
    rejected_author("dependent", "descriptor", "sha256:" + "99" * 32)

    malformed_transaction = copy.deepcopy(probes)
    malformed_transaction[cell_id]["durable-attempt-state-classified"][
        "observations"
    ]["transaction"] = "not/a/local-key"
    rejected(module, spec, malformed_transaction, [cell_id], subject, plan_bundle)

    malformed_plan_subject = copy.deepcopy(subject)
    malformed_plan_subject["plan"] = "sha256:short"
    malformed_plan = copy.deepcopy(probes)
    malformed_plan[cell_id]["durable-attempt-state-classified"]["observations"][
        "plan"
    ] = malformed_plan_subject["plan"]
    rejected(module, spec, malformed_plan, [cell_id], malformed_plan_subject, plan_bundle)

    substituted_plan = copy.deepcopy(probes)
    substituted_plan[cell_id]["durable-attempt-state-classified"][
        "observations"
    ]["plan"] = "sha256:" + "77" * 32
    rejected(module, spec, substituted_plan, [cell_id], subject, plan_bundle)

    malformed_bundle_subject = copy.deepcopy(subject)
    malformed_bundle_subject["plan-bundle-digest"] = "sha256:" + "aa" * 32
    rejected(module, spec, probes, [cell_id], malformed_bundle_subject, plan_bundle)

    malformed_journal = copy.deepcopy(probes)
    malformed_journal[cell_id]["durable-attempt-state-classified"][
        "observations"
    ]["journal-before-loss"] = "sha256:" + "55" * 32
    rejected(module, spec, malformed_journal, [cell_id], subject, plan_bundle)

    foreign_scope = ["foreign/aos.interface/abi-1/publish/lose-external-result"]
    rejected(module, spec, probes, foreign_scope, subject, plan_bundle)

    missing = copy.deepcopy(probes)
    del missing[cell_id][names[0]]
    rejected(module, spec, missing, [cell_id], subject, plan_bundle)

    wrong_kind = copy.deepcopy(probes)
    wrong_kind[cell_id][names[0]]["kind"] = "ownership-inventory"
    rejected(module, spec, wrong_kind, [cell_id], subject, plan_bundle)

    unknown = copy.deepcopy(probes)
    unknown[cell_id][names[0]]["claimed"] = True
    rejected(module, spec, unknown, [cell_id], subject, plan_bundle)

    duplicate = copy.deepcopy(probes)
    duplicate[cell_id][names[1]]["observations"] = duplicate[cell_id][names[0]][
        "observations"
    ]
    rejected(module, spec, duplicate, [cell_id], subject, plan_bundle)

    null_observation = copy.deepcopy(probes)
    null_observation[cell_id][names[0]]["observations"] = {"probe": None}
    rejected(module, spec, null_observation, [cell_id], subject, plan_bundle)

    false_barrier = copy.deepcopy(probes)
    false_barrier[cell_id]["dependent-effects-not-executed"]["observations"][
        "changed-only-after-recovery"
    ] = False
    rejected(module, spec, false_barrier, [cell_id], subject, plan_bundle)

    reordered_timeline = copy.deepcopy(probes)
    timeline = reordered_timeline[cell_id]["durable-attempt-state-classified"][
        "observations"
    ]["timeline"]
    timeline[1]["kind"], timeline[3]["kind"] = (
        timeline[3]["kind"],
        timeline[1]["kind"],
    )
    rejected(module, spec, reordered_timeline, [cell_id], subject, plan_bundle)

    reordered_boundaries = copy.deepcopy(probes)
    boundary = reordered_boundaries[cell_id]["durable-attempt-state-classified"][
        "observations"
    ]["boundary-timeline"]
    boundary[1], boundary[3] = boundary[3], boundary[1]
    rejected(module, spec, reordered_boundaries, [cell_id], subject, plan_bundle)

    early_dependent = copy.deepcopy(probes)
    early_dependent[cell_id]["dependent-effects-not-executed"]["observations"][
        "timeline-before-completion"
    ] = [{"sequence": 8, "kind": "operation-admitted", "node-ordinal": 2}]
    rejected(module, spec, early_dependent, [cell_id], subject, plan_bundle)

    wrong_dependent_ordinal = copy.deepcopy(probes)
    wrong_dependent_ordinal[cell_id]["dependent-effects-not-executed"][
        "observations"
    ]["dependent-operation"]["ordinal"] = 8
    rejected(module, spec, wrong_dependent_ordinal, [cell_id], subject, plan_bundle)


if __name__ == "__main__":
    main()
