"""Exercises supported-cancellation production evidence validation."""

from __future__ import annotations

import copy
import importlib.util
import json
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
    """Requires one forged cancellation claim to fail closed."""

    try:
        action()
    except RuntimeError:
        return
    raise AssertionError("mutated cancellation evidence was accepted")


def fixture_postconditions(policy):
    """Returns one bounded postcondition projection for synthetic cells."""

    names = policy["postcondition_groups"]["baseline"] + policy["postcondition_groups"]["failure"]
    kinds = policy["postcondition_kinds"]
    return names, {name: kinds[name] for name in names}


def package_routes(cell, subject):
    """Projects the terminal route authenticated by this semantic fixture."""

    implementation = subject["provider-implementation"]
    return [
        {
            "adapter": cell["adapter"],
            "interface": cell["interface"],
            "methods": [cell["method"]],
            "implementation": implementation["descriptor"],
            "handler": implementation["handler"],
            "entry-point": "libexec/fixture-handler",
        }
    ]


def synthetic_matrix(cell, dispatch, entry_point, cancellation_oracle):
    """Builds one bounded generated-claim projection for a synthetic cell."""

    adapters = [
        {
            "adapter": cell["adapter"],
            "interface_name": cell["interface"]["name"],
            "observation_kind": cancellation_oracle,
            "provider_implementation": {
                "observer": {
                    "result": {
                        "fields": {
                            "provider": {
                                "kind": "string-enum",
                                "values": [cell["adapter"]],
                            },
                            "kind": {
                                "kind": "string-enum",
                                "values": [cancellation_oracle],
                            },
                        }
                    }
                },
            },
        }
    ]
    if cell["adapter"] != "systemd-manager":
        adapters.append(
            {
                "adapter": "systemd-manager",
                "interface_name": "aos.systemd-manager",
                "observation_kind": "systemd",
                "provider_implementation": {
                    "observer": {
                        "result": {
                            "fields": {
                                "provider": {
                                    "kind": "string-enum",
                                    "values": ["systemd-manager"],
                                },
                                "kind": {
                                    "kind": "string-enum",
                                    "values": ["systemd"],
                                },
                            }
                        }
                    },
                },
            }
        )

    return {
        "schema": "aos.test.matrix/v1",
        "cells": [cell],
        "surface": {
            "adapters": adapters
        },
    }


def validate_image_rollout_case(
    cohort, effect, cancellation, digest, scenario_policy
) -> None:
    """Checks the image route, physical oracle, digests, and probe uniqueness."""

    interface = {
        "name": "aos.ab-image-rollout-effects",
        "abi": 1,
        "descriptor": digest("a"),
    }
    binding = {"environment": "rollout", "key": "terminal"}
    resource = {"provider": "rollout", "key": "machine"}
    target = {
        "interface": interface,
        "resource": resource,
        "operations": ["drain"],
        "lifetime": "persistent",
    }
    operation_key = {"scope": ["rollout"], "key": "drain"}
    dependent_key = {"scope": ["rollout"], "key": "dependent"}
    operation = {
        "key": operation_key,
        "binding": binding,
        "interface": interface,
        "method": "drain",
        "target": target,
        "recovery": {"cancel": {"interface": interface, "method": "drain"}},
    }
    dependent = {
        **operation,
        "key": dependent_key,
    }
    implementation = {
        "descriptor": digest("b"),
        "artifact": {
            "content": digest("c"),
            "store_path": "/nix/store/rollout-provider",
            "nar_hash": digest("d"),
            "closure": digest("e"),
        },
        "handler": "native-ab-image-rollout",
    }
    edge = {
        "from": {"kind": "operation", "key": operation_key},
        "to": {"kind": "operation", "key": dependent_key},
        "kind": "required-success",
    }
    bundle = {
        "schema": "aos.ability.plan-bundle/v1",
        "plan": digest("f"),
        "desired": {
            "snapshot": {
                "resolution": {
                    "binding_document": {
                        "bindings": [
                            {"id": binding, "implementation": implementation}
                        ]
                    }
                }
            }
        },
        "current": None,
        "transition_authority": None,
        "transition": {
            "effect_document": {
                "operations": [operation, dependent],
                "edges": [edge],
            }
        },
    }
    mapping = {
        "resource": resource,
        "revision": digest("0"),
        "owner_package": digest("1"),
        "binding": binding,
        "implementation": implementation,
        "qualification": {"kind": "image-rollout"},
    }
    policy = {
        "schema": "aos.ability.authenticated-policy-set/v1",
        "policies": [],
        "native_resource_map": {
            "schema": "aos.ability.native-resource-map/v1",
            "desired_state": digest("2"),
            "entries": [mapping],
        },
    }
    policy_bytes = cancellation.canonical(policy)
    authority = {
        "generation": 8,
        "manifest-path": "/var/lib/profiles/system/gen-8/manifest.json",
        "policy-pin": {
            "store_path": "/nix/store/rollout-policy",
            "document": "policy.json",
            "document_sha256": effect.sha256_bytes(policy_bytes),
            "document_size": len(policy_bytes),
        },
        "policy-document": policy,
    }
    cell_id = (
        "image-rollout/aos.ab-image-rollout-effects/abi-1/"
        "drain/cancel-unsettled-attempt"
    )
    postconditions, postcondition_kinds = fixture_postconditions(scenario_policy)
    cell = {
        "id": cell_id,
        "adapter": "image-rollout",
        "applicability": {
            "required_resource_lifetimes": [],
            "requires_state_format": False,
        },
        "required_target_access": "exclusive-write",
        "interface": interface,
        "method": "drain",
        "boundary": "provider-effect",
        "failure": "process-termination",
        "disposition": {
            "kind": "cancellation-route",
            "supported": "cancelled-after-reconciliation",
            "unsupported": "unsupported-cancellation-retains-ownership",
        },
        "candidate": "new",
        "predecessor": "same",
        "postconditions": postconditions,
        "postcondition_kinds": postcondition_kinds,
    }
    matrix_spec = synthetic_matrix(
        cell,
        "native-ab-image-rollout",
        "libexec/aos-ab-image-rollout-handler",
        "image-rollout",
    )
    owner = {"count": 1, "identities": [{"resource": resource}]}
    live = {
        "kind": "image-rollout",
        "filesystem": {
            "kind": "filesystem",
            "entries": [
                {
                    "path": "/var/lib/profiles/image/state.json",
                    "metadata": "regular file|0|0|600|1|now|now",
                    "digest": digest("3").removeprefix("sha256:"),
                },
                {
                    "path": "/var/lib/profiles/image/ability-rollouts/fixture/state.json",
                    "metadata": "regular file|0|0|600|1|now|now",
                    "digest": digest("4").removeprefix("sha256:"),
                },
            ],
        },
        "hook-state": {"kind": "filesystem", "entries": []},
        "kernel-command-line": "root=PARTUUID=fixture",
    }
    foreign = {
        "adapter": "systemd-manager",
        "resource": {"provider": "rollout", "key": "foreign-service"},
        "observation": {"kind": "systemd", "units": []},
    }
    observation = cancellation.CancellationObservation(
        transaction="rollout-cancel-flight",
        switch_process=456,
        operation_key=operation_key,
        journal_before_signal="8" * 64,
        timeline=[
            {"sequence": 1, "kind": "operation-admitted", "node-ordinal": 0},
            {"sequence": 2, "kind": "effect-started", "node-ordinal": 0},
            {"sequence": 3, "kind": "cancellation-started", "node-ordinal": 0},
            {"sequence": 4, "kind": "cancellation-indeterminate", "node-ordinal": 0},
        ],
        boundary_timeline=[
            {"transcript-position": index, "purpose": purpose, "boundary": boundary}
            for index, (purpose, boundary) in enumerate(
                cancellation.CANCELLATION_BOUNDARIES
            )
        ],
        owner_before=owner,
        owner_unsettled=owner,
        owner_after=owner,
        live_before=live,
        live_unsettled=live,
        live_after=live,
        foreign_before=foreign,
        foreign_unsettled=foreign,
        foreign_after=foreign,
        dependent_operation={
            "key": dependent_key,
            "ordinal": 1,
            "interface": interface,
            "method": "drain",
            "target": target,
        },
        dependent_before=[],
        dependent_after=[],
        dependent_boundaries=[],
    )
    builder = cancellation.CancellationEvidence(matrix_spec, [cell_id])
    builder.retain(
        cell_id, cancellation.canonical(bundle), authority, authority, observation
    )
    subjects, bundles, probes = builder.finish()
    subject = subjects[cell_id]
    records = probes[cell_id]
    routes = package_routes(cell, subject)

    cohort._validate_cohort_subject(
        cell, subject, bundles[cell_id], matrix_spec, routes
    )
    for postcondition, record in records.items():
        cohort._validate_probe_facts(
            postcondition, record["observations"], subject, cell, matrix_spec
        )
    probe_digests = {
        cohort.sha256(record["observations"]) for record in records.values()
    }
    assert len(probe_digests) == len(records)
    bound_subject = cohort._bound_cohort_subject(cell, subject)
    observed_probe_digests = set()
    cohort._validated_probes(
        cell,
        records,
        subject,
        bound_subject,
        digest("5"),
        observed_probe_digests,
        matrix_spec,
    )
    rejected(
        lambda: cohort._validated_probes(
            cell,
            records,
            subject,
            bound_subject,
            digest("5"),
            observed_probe_digests,
            matrix_spec,
        )
    )

    for field in ("cell-digest", "plan-bundle-digest"):
        mutation = copy.deepcopy(subject)
        mutation[field] = digest("9")
        rejected(
            lambda mutation=mutation: cohort._validate_cohort_subject(
                cell, mutation, bundles[cell_id], matrix_spec, routes
            )
        )
    wrong_handler = copy.deepcopy(subject)
    wrong_handler["provider-implementation"]["handler"] = "foreign-handler"
    rejected(
        lambda: cohort._validate_cohort_subject(
            cell, wrong_handler, bundles[cell_id], matrix_spec, routes
        )
    )
    wrong_route = copy.deepcopy(subject)
    wrong_route["cancel-route"]["method"] = "hold"
    rejected(
        lambda: cohort._validate_cohort_subject(
            cell, wrong_route, bundles[cell_id], matrix_spec, routes
        )
    )
    for mutation in ("kind", "filesystem"):
        wrong_live = copy.deepcopy(
            records["durable-attempt-state-classified"]["observations"]
        )
        if mutation == "kind":
            wrong_live["live-after"]["kind"] = "filesystem"
        else:
            wrong_live["live-after"]["filesystem"]["entries"] = []
        rejected(
            lambda wrong_live=wrong_live: cohort._validate_probe_facts(
                "durable-attempt-state-classified", wrong_live, subject, cell, matrix_spec
            )
        )

    duplicate_probe = copy.deepcopy(
        records["foreign-resources-unchanged"]["observations"]
    )
    duplicate_probe.update(
        records["durable-attempt-state-classified"]["observations"]
    )
    rejected(
        lambda: cohort._validate_probe_facts(
            "foreign-resources-unchanged", duplicate_probe, subject, cell, matrix_spec
        )
    )


def main() -> None:
    """Builds one exact production-shaped cancellation and rejects mutations."""

    cohort = load("matrix_cohort", pathlib.Path(sys.argv[1]))
    effect = load("effect_evidence", pathlib.Path(sys.argv[2]))
    cancellation = load("cancellation_evidence", pathlib.Path(sys.argv[3]))
    scenario_policy = json.loads(pathlib.Path(sys.argv[4]).read_text())
    cancellation.EFFECT_EVIDENCE = effect

    digest = lambda byte: "sha256:" + byte * 64
    interface = {
        "name": "aos.managed-configuration-effects",
        "abi": 1,
        "descriptor": digest("1"),
    }
    binding = {"environment": "fixture", "key": "terminal"}
    resource = {"provider": "fixture", "key": "owned"}
    target = {
        "interface": interface,
        "resource": resource,
        "operations": ["publish"],
        "lifetime": "instance",
    }
    operation_key = {"scope": ["fixture"], "key": "publish-owned"}
    dependent_key = {"scope": ["fixture"], "key": "observe-owned"}
    operation = {
        "key": operation_key,
        "binding": binding,
        "interface": interface,
        "method": "publish",
        "disposition": {
            "kind": "cancellation-route",
            "supported": "cancelled-after-reconciliation",
            "unsupported": "unsupported-cancellation-retains-ownership",
        },
        "target": target,
        "recovery": {"cancel": {"interface": interface, "method": "remove"}},
    }
    dependent = {
        "key": dependent_key,
        "binding": binding,
        "interface": interface,
        "method": "prepare",
        "target": {**target, "operations": ["prepare"]},
    }
    implementation = {
        "descriptor": digest("2"),
        "artifact": {
            "content": digest("3"),
            "store_path": "/nix/store/fixture-provider",
            "nar_hash": digest("4"),
            "closure": digest("5"),
        },
        "handler": "managed-configuration-terminal",
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
                            {"id": binding, "implementation": implementation}
                        ]
                    }
                }
            }
        },
        "current": None,
        "transition_authority": None,
        "transition": {
            "effect_document": {
                "operations": [operation, dependent],
                "edges": [edge],
            }
        },
    }
    mapping = {
        "resource": resource,
        "revision": digest("8"),
        "owner_package": digest("9"),
        "binding": binding,
        "implementation": implementation,
        "qualification": {"kind": "test"},
    }
    policy = {
        "schema": "aos.ability.authenticated-policy-set/v1",
        "policies": [],
        "native_resource_map": {
            "schema": "aos.ability.native-resource-map/v1",
            "desired_state": digest("a"),
            "entries": [mapping],
        },
    }
    policy_bytes = cancellation.canonical(policy)
    authority = {
        "generation": 7,
        "manifest-path": "/var/lib/profiles/system/gen-7/manifest.json",
        "policy-pin": {
            "store_path": "/nix/store/fixture-policy",
            "document": "policy.json",
            "document_sha256": effect.sha256_bytes(policy_bytes),
            "document_size": len(policy_bytes),
        },
        "policy-document": policy,
    }
    cell_id = (
        "managed-configuration/aos.managed-configuration-effects/abi-1/"
        "publish/cancel-unsettled-attempt"
    )
    postconditions, postcondition_kinds = fixture_postconditions(scenario_policy)
    cell = {
        "id": cell_id,
        "adapter": "managed-configuration",
        "applicability": {
            "required_resource_lifetimes": [],
            "requires_state_format": False,
        },
        "required_target_access": "exclusive-write",
        "interface": interface,
        "method": "publish",
        "postconditions": postconditions,
        "postcondition_kinds": postcondition_kinds,
    }
    matrix_spec = synthetic_matrix(
        cell,
        "managed-configuration-terminal",
        "bin/.aos-package-runtime-unwrapped",
        "filesystem",
    )
    owner = {"count": 1, "identities": [{"resource": resource}]}
    live = {"kind": "filesystem", "entries": [{"path": "/owned"}]}
    foreign = {
        "adapter": "managed-configuration",
        "resource": {"provider": "fixture", "key": "foreign"},
        "observation": {"kind": "filesystem", "entries": [{"path": "/foreign"}]},
    }
    observation = cancellation.CancellationObservation(
        transaction="cancel-flight",
        switch_process=123,
        operation_key=operation_key,
        journal_before_signal="7" * 64,
        timeline=[
            {"sequence": 1, "kind": "operation-admitted", "node-ordinal": 0},
            {"sequence": 2, "kind": "effect-started", "node-ordinal": 0},
            {"sequence": 3, "kind": "cancellation-started", "node-ordinal": 0},
            {"sequence": 4, "kind": "cancellation-indeterminate", "node-ordinal": 0},
        ],
        boundary_timeline=[
            {"transcript-position": index, "purpose": purpose, "boundary": boundary}
            for index, (purpose, boundary) in enumerate(
                cancellation.CANCELLATION_BOUNDARIES
            )
        ],
        owner_before=owner,
        owner_unsettled=owner,
        owner_after=owner,
        live_before=live,
        live_unsettled=live,
        live_after=live,
        foreign_before=foreign,
        foreign_unsettled=foreign,
        foreign_after=foreign,
        dependent_operation={
            "key": dependent_key,
            "ordinal": 1,
            "interface": interface,
            "method": "prepare",
            "target": dependent["target"],
        },
        dependent_before=[],
        dependent_after=[],
        dependent_boundaries=[],
    )
    builder = cancellation.CancellationEvidence(matrix_spec, [cell_id])
    builder.retain(
        cell_id, cancellation.canonical(bundle), authority, authority, observation
    )
    subjects, bundles, probes = builder.finish()
    subject = subjects[cell_id]
    routes = package_routes(cell, subject)

    cohort._validate_cohort_subject(
        cell, subject, bundles[cell_id], matrix_spec, routes
    )
    for postcondition, record in probes[cell_id].items():
        cohort._validate_probe_facts(
            postcondition, record["observations"], subject, cell, matrix_spec
        )

    wrong_handler = copy.deepcopy(subject)
    wrong_handler["provider-implementation"]["handler"] = "foreign-handler"
    rejected(
        lambda: cohort._validate_cohort_subject(
            cell, wrong_handler, bundles[cell_id], matrix_spec, routes
        )
    )
    wrong_matrix = copy.deepcopy(subject)
    wrong_matrix["matrix-spec-digest"] = digest("f")
    rejected(
        lambda: cohort._validate_cohort_subject(
            cell, wrong_matrix, bundles[cell_id], matrix_spec, routes
        )
    )
    wrong_boundary = copy.deepcopy(
        probes[cell_id]["durable-attempt-state-classified"]["observations"]
    )
    wrong_boundary["boundary-timeline"][2]["boundary"] = "effect-returned"
    rejected(
        lambda: cohort._validate_probe_facts(
            "durable-attempt-state-classified", wrong_boundary, subject, cell, matrix_spec
        )
    )
    wrong_owner = copy.deepcopy(
        probes[cell_id]["at-most-one-resource-owner"]["observations"]
    )
    wrong_owner["owner-after"]["count"] = 2
    rejected(
        lambda: cohort._validate_probe_facts(
            "at-most-one-resource-owner", wrong_owner, subject, cell, matrix_spec
        )
    )
    wrong_foreign = copy.deepcopy(
        probes[cell_id]["foreign-resources-unchanged"]["observations"]
    )
    wrong_foreign["foreign-after"] = copy.deepcopy(wrong_foreign["foreign-after"])
    wrong_foreign["foreign-after"]["observation"]["entries"] = []
    rejected(
        lambda: cohort._validate_probe_facts(
            "foreign-resources-unchanged", wrong_foreign, subject, cell, matrix_spec
        )
    )
    wrong_dependency = copy.deepcopy(
        probes[cell_id]["dependent-effects-not-executed"]["observations"]
    )
    wrong_dependency["dependent-effect-count"] = 1
    rejected(
        lambda: cohort._validate_probe_facts(
            "dependent-effects-not-executed", wrong_dependency, subject, cell, matrix_spec
        )
    )

    validate_image_rollout_case(cohort, effect, cancellation, digest, scenario_policy)


if __name__ == "__main__":
    main()
