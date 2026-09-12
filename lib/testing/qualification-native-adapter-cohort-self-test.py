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
            {scope[0]: subject},
            {scope[0]: plan_bundle},
            "sha256:" + "11" * 32,
            "sha256:" + "22" * 32,
        )
    except RuntimeError:
        return
    raise AssertionError("mutated cohort probe was accepted")


def assert_semantic_validators(module, subject, cell, observations):
    """Exercises every postcondition validator with positive and negative facts."""

    predecessor = subject["publish-operation"]
    dependent = subject["dependent-operation"]
    resource = {"provider": "fixture", "key": "resource"}
    predecessor_owner = {"controller": "predecessor", "incarnation": "old"}
    candidate_owner = {"controller": "candidate", "incarnation": "new"}
    digest = lambda byte: "sha256:" + byte * 64

    cases = {
        "durable-attempt-state-classified": (
            observations["durable-attempt-state-classified"],
            ("effect-return-position", 12),
        ),
        "at-most-one-resource-owner": (
            observations["at-most-one-resource-owner"],
            ("matching-markers", 2),
        ),
        "foreign-resources-unchanged": (
            observations["foreign-resources-unchanged"],
            ("content-after-recovery", "changed"),
        ),
        "dependent-effects-not-executed": (
            observations["dependent-effects-not-executed"],
            ("changed-only-after-recovery", False),
        ),
        "fresh-receiving-authority": (
            {
                "predecessor-authority": digest("1"),
                "candidate-authority": digest("2"),
                "predecessor-incarnation": "old",
                "candidate-incarnation": "new",
                "authority-sequence-before": 7,
                "authority-sequence-after": 8,
                "fresh": True,
            },
            ("fresh", False),
        ),
        "compatible-state-adopted": (
            {
                "resource": resource,
                "compatibility-contract": digest("3"),
                "predecessor-state": digest("4"),
                "adopted-state": digest("4"),
                "adoption-record": digest("5"),
                "candidate-effect-count": 0,
                "adopted": True,
            },
            ("candidate-effect-count", 1),
        ),
        "exactly-one-resource-owner": (
            {
                "resource": resource,
                "expected-owner": candidate_owner,
                "owners": [candidate_owner],
                "matching-markers": 1,
            },
            ("owners", []),
        ),
        "transfer-rejected-before-candidate-effect": (
            {
                "candidate-operation": predecessor,
                "rejection": "lost-result",
                "candidate-effect-count": 0,
                "rejected-before-effect": True,
            },
            ("candidate-effect-count", 1),
        ),
        "predecessor-remains-sole-owner": (
            {
                "resource": resource,
                "predecessor-owner": predecessor_owner,
                "owners": [predecessor_owner],
                "behavior-before": "served-old-revision",
                "behavior-after": "served-old-revision",
            },
            ("behavior-after", "served-new-revision"),
        ),
        "current-grants-reauthorized": (
            {
                "plan": subject["plan"],
                "retained-grant": digest("6"),
                "current-grant": digest("7"),
                "authority-sequence-before": 12,
                "authority-sequence-after": 13,
                "reauthorized": True,
            },
            ("reauthorized", False),
        ),
        "retained-target-identity-preserved": (
            {
                "retained-target": resource,
                "activated-target": resource,
                "retained-revision": digest("8"),
                "activated-revision": digest("8"),
            },
            ("activated-revision", digest("9")),
        ),
        "prerequisite-failure-recorded": (
            {
                "predecessor-operation": predecessor,
                "dependent-operation": dependent,
                "dependency-edge": {
                    "from": {"kind": "operation", "key": predecessor["key"]},
                    "to": {"kind": "operation", "key": dependent["key"]},
                    "kind": "required-success",
                },
                "failure-record": digest("a"),
                "dependent-effect-count": 0,
            },
            ("dependent-effect-count", 1),
        ),
        "foreign-attempt-rejected-before-mutation": (
            {
                "foreign-resource": resource,
                "attempted-resource": resource,
                "authorized-resources": [],
                "rejection": "lost-result",
                "mutation-count": 0,
                "rejected-before-mutation": True,
            },
            ("mutation-count", 1),
        ),
    }

    assert set(cases) == set(module.POSTCONDITION_KINDS)
    for name, (valid, mutation) in cases.items():
        module._validate_probe_facts(name, valid, subject, cell)

        invalid = copy.deepcopy(valid)
        invalid[mutation[0]] = mutation[1]
        try:
            module._validate_probe_facts(name, invalid, subject, cell)
        except RuntimeError:
            continue
        raise AssertionError(f"{name} semantic validator accepted false facts")


def assert_negative_semantic_validators(module, subject, base_cell):
    """Exercises the production dependency and foreign-resource proof shapes."""

    publish = subject["publish-operation"]
    dependent = subject["dependent-operation"]
    cause_timeline = [
        {"sequence": 7, "kind": "operation-admitted", "node-ordinal": 5},
        {"sequence": 8, "kind": "effect-started", "node-ordinal": 5},
        {"sequence": 9, "kind": "rejected-before-effect", "node-ordinal": 5},
    ]
    boundaries = [
        {
            "transcript-position": 20,
            "purpose": "effect",
            "boundary": "effect-intent-durable",
        },
        {
            "transcript-position": 21,
            "purpose": "effect",
            "boundary": "effect-returned",
        },
        {
            "transcript-position": 22,
            "purpose": "effect",
            "boundary": "effect-outcome-durable",
        },
    ]
    edge = {
        "from": {"kind": "operation", "key": publish["key"]},
        "to": {"kind": "operation", "key": dependent["key"]},
        "kind": "required-success",
    }

    foreign_cell = copy.deepcopy(base_cell)
    foreign_cell["id"] = foreign_cell["id"].replace(
        "lose-external-result", "reject-foreign-resource-mutation"
    )
    foreign_cell["failure"] = "foreign-authority-rejected"
    foreign_facts = {
        "durable-attempt-state-classified": {
            "transaction": "transaction-negative",
            "plan": subject["plan"],
            "operation": publish,
            "timeline": cause_timeline,
            "cause-operation": publish,
            "cause-timeline": cause_timeline,
            "boundary-timeline": boundaries,
            "failure-record": "aa" * 32,
            "classified": True,
        },
        "at-most-one-resource-owner": {
            "resource": publish["target"]["resource"],
            "owner-count-before": 1,
            "owner-count-after": 1,
            "one-owner-throughout": True,
            "owner-evidence-before": "foreign-marker",
            "owner-evidence-after": "foreign-marker",
        },
        "foreign-resources-unchanged": {
            "resource": {"provider": "fixture", "key": "independent"},
            "snapshot-before": "unchanged",
            "snapshot-after": "unchanged",
            "unchanged": True,
        },
        "dependent-effects-not-executed": {
            "predecessor-operation": publish,
            "dependent-operation": dependent,
            "dependency-edge": edge,
            "dependent-timeline": [],
            "dependent-effect-boundaries": [],
            "behavior-before": "baseline",
            "behavior-after": "baseline",
            "blocked": True,
        },
        "foreign-attempt-rejected-before-mutation": {
            "foreign-resource": {"provider": "fixture", "key": "foreign"},
            "attempted-resource": {"provider": "fixture", "key": "foreign"},
            "authorized-resources": [publish["target"]["resource"]],
            "rejection": "foreign-authority-rejected",
            "mutation-count": 0,
            "rejected-before-mutation": True,
        },
    }
    for name, facts in foreign_facts.items():
        module._validate_probe_facts(name, facts, subject, foreign_cell)

    blocked_cell = copy.deepcopy(base_cell)
    blocked_cell["id"] = (
        "systemd-service-legacy/aos.systemd-service-effects/abi-1/"
        "reload/block-dependent-effect"
    )
    blocked_cell["interface"] = dependent["interface"]
    blocked_cell["method"] = "reload"
    blocked_cell["failure"] = "prerequisite-failed"
    blocked_facts = copy.deepcopy(foreign_facts)
    blocked_facts.pop("foreign-attempt-rejected-before-mutation")
    blocked_facts["durable-attempt-state-classified"]["operation"] = dependent
    blocked_facts["durable-attempt-state-classified"]["timeline"] = []
    blocked_facts["at-most-one-resource-owner"]["resource"] = dependent["target"][
        "resource"
    ]
    blocked_facts["foreign-resources-unchanged"]["cell"] = blocked_cell["id"]
    blocked_facts["dependent-effects-not-executed"]["cell"] = blocked_cell["id"]
    blocked_facts["prerequisite-failure-recorded"] = {
        "predecessor-operation": publish,
        "dependent-operation": dependent,
        "dependency-edge": edge,
        "failure-record": "sha256:" + "bb" * 32,
        "dependent-effect-count": 0,
    }
    for name, facts in blocked_facts.items():
        module._validate_probe_facts(name, facts, subject, blocked_cell)

    false_block = copy.deepcopy(blocked_facts["dependent-effects-not-executed"])
    false_block["dependent-timeline"] = [
        {"sequence": 10, "kind": "operation-admitted", "node-ordinal": 2}
    ]
    try:
        module._validate_probe_facts(
            "dependent-effects-not-executed", false_block, subject, blocked_cell
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("dependency validator accepted an executed dependent")


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
                "matrix_schema": "aos.qualification.native-adapter-matrix/v1",
                "adapter": "managed-configuration",
                "interface": interface,
                "method": "publish",
                "effect_class": "mutation",
                "scope": "host-filesystem",
                "boundary": "after-external-return",
                "failure": "lost-result",
                "predecessor": "same",
                "candidate": "same",
                "postconditions": names,
                "recovery": {"reconcile": "observe", "cancel": "cancel"},
                "invalidated_by": ["subject", "policy", "executor", "environment"],
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
                "disposition": "reconciled-completed",
                "observations": observations[name],
            }
            for name in names
        }
    }
    cells, count = module.build_cells(
        spec,
        probes,
        [cell_id],
        {cell_id: subject},
        {cell_id: plan_bundle},
        "sha256:" + "11" * 32,
        "sha256:" + "22" * 32,
    )
    assert count == 4
    assert all(value["passed"] for value in cells[0]["postconditions"].values())
    assert set(cells[0]["probes"]) == set(names)
    assert cells[0]["cohort_subject"]["subject"] == subject
    assert cells[0]["cohort_subject"]["cell_id"] == cell_id
    assert cells[0]["cohort_subject"]["cell_digest"] == module.sha256(spec["cells"][0])
    assert {
        probe["cohort_subject_digest"] for probe in cells[0]["probes"].values()
    } == {module.sha256(cells[0]["cohort_subject"])}
    assert {
        probe["cell_id"] for probe in cells[0]["probes"].values()
    } == {cell_id}
    assert {
        probe["cell_digest"] for probe in cells[0]["probes"].values()
    } == {module.sha256(spec["cells"][0])}
    assert_semantic_validators(module, subject, spec["cells"][0], observations)
    assert_negative_semantic_validators(module, subject, spec["cells"][0])

    first_cell = spec["cells"][0]
    replay_cell = copy.deepcopy(first_cell)
    replay_cell["id"] = replay_cell["id"].replace(
        "managed-configuration/", "foreign-adapter/", 1
    )
    shared_probe_digests = set()
    module._validated_probes(
        first_cell,
        probes[cell_id],
        subject,
        module._bound_cohort_subject(first_cell, subject),
        "sha256:" + "11" * 32,
        shared_probe_digests,
    )
    try:
        module._validated_probes(
            replay_cell,
            probes[cell_id],
            subject,
            module._bound_cohort_subject(first_cell, subject),
            "sha256:" + "11" * 32,
            set(),
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("a cohort subject bound to another cell was accepted")

    try:
        module._validated_probes(
            replay_cell,
            probes[cell_id],
            subject,
            module._bound_cohort_subject(replay_cell, subject),
            "sha256:" + "11" * 32,
            shared_probe_digests,
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("a production probe replayed across cells was accepted")

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

    wrong_disposition = copy.deepcopy(probes)
    wrong_disposition[cell_id][names[0]]["disposition"] = "invented-success"
    rejected(module, spec, wrong_disposition, [cell_id], subject, plan_bundle)

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
