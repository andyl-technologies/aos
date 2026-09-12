"""Exercises fail-closed matrix cohort probe construction."""

from __future__ import annotations

import copy
import hashlib
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
            {cell_id: subject for cell_id in scope},
            {cell_id: plan_bundle for cell_id in scope},
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
            ("interruption-position", 12),
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


def assert_provider_negative_validator(module, template_cell):
    """Exercises candidate-linked paired-flight validation and rejection."""

    cell = copy.deepcopy(template_cell)
    cell.update(
        {
            "id": (
                "network-endpoint/aos.network-endpoint-effects/abi-1/"
                "materialize/reject-foreign-resource-mutation"
            ),
            "adapter": "network-endpoint",
            "interface": {
                "name": "aos.network-endpoint-effects",
                "abi": 1,
                "descriptor": "sha256:" + "10" * 32,
            },
            "method": "materialize",
            "boundary": "foreign-resource",
            "failure": "foreign-authority-rejected",
            "postconditions": [
                "durable-attempt-state-classified",
                "at-most-one-resource-owner",
                "foreign-resources-unchanged",
                "dependent-effects-not-executed",
                "foreign-attempt-rejected-before-mutation",
            ],
        }
    )
    cell_digest = module.sha256(cell)
    foreign_resource = {"provider": "fixture", "key": "foreign-endpoint"}
    successor_resource = {"provider": "fixture", "key": "blocked-endpoint"}
    foreign_operation = {
        "key": {"scope": ["negative"], "key": "foreign"},
        "ordinal": 0,
        "interface": cell["interface"],
        "method": cell["method"],
        "resource": foreign_resource,
    }
    dependent_operation = {
        "key": {"scope": ["negative"], "key": "dependent"},
        "ordinal": 1,
        "interface": cell["interface"],
        "method": cell["method"],
        "resource": successor_resource,
    }
    subject = {
        "schema": module.PROVIDER_NEGATIVE_SUBJECT_SCHEMA,
        "cell-id": cell["id"],
        "cell-digest": cell_digest,
        "adapter": cell["adapter"],
        "interface": cell["interface"],
        "method": cell["method"],
        "scenario": "reject-foreign-resource-mutation",
        "plan": "sha256:" + "20" * 32,
        "transaction": "provider-negative",
        "flight": "endpoint-materialize",
    }
    plan = {
        "schema": module.PROVIDER_NEGATIVE_PLAN_SCHEMA,
        "digest": "sha256:" + "30" * 32,
        "plan": subject["plan"],
        "foreign-operation": foreign_operation,
        "dependent-operation": dependent_operation,
        "required-success": {
            "from": foreign_operation,
            "to": dependent_operation,
            "kind": "required-success",
        },
        "behavioral-witness": None,
    }
    snapshot = "sha256:" + "40" * 32
    record = {
        "cell_digest": cell_digest,
        "subject": subject,
        "plan_bundle": plan,
        "evidence": {
            "provider-route": {
                "adapter": cell["adapter"],
                "interface": cell["interface"],
                "method": cell["method"],
                "candidate-linked": True,
                "artifact": "sha256:" + "50" * 32,
                "handler": "network-endpoint-terminal",
                "entry-point": "libexec/aos-network-endpoint-handler-v1",
            },
            "boundary": "after-durable-intent-before-external-effect",
            "journal": {
                "digest": "sha256:" + "60" * 32,
                "failure-record": "sha256:" + "70" * 32,
                "foreign-operation": foreign_operation,
                "foreign-timeline": [
                    {
                        "sequence": 1,
                        "kind": "operation-admitted",
                        "node-ordinal": 0,
                    },
                    {
                        "sequence": 2,
                        "kind": "effect-started",
                        "node-ordinal": 0,
                    },
                    {
                        "sequence": 3,
                        "kind": "rejected-before-effect",
                        "node-ordinal": 0,
                    },
                ],
                "dependent-operation": dependent_operation,
                "dependent-timeline": [],
                "behavioral-witness": None,
                "witness-timeline": [],
                "classified": "foreign-authority-rejected",
            },
            "ownership": {
                "foreign-owner-count-before": 1,
                "foreign-owner-count-after": 1,
                "candidate-owner-count": 0,
                "maximum-owner-count": 1,
            },
            "foreign-resource": {
                "kind": "loopback-listener",
                "resource": foreign_resource,
                "before": snapshot,
                "after": snapshot,
                "unchanged": True,
                "live": True,
            },
            "blocked-successor": {
                "kind": "loopback-listener",
                "resource": successor_resource,
                "before": snapshot,
                "after": snapshot,
                "unchanged": True,
                "live": True,
            },
            "blocked-witness": None,
        },
    }

    module._validated_provider_negative_cell(
        cell, record, "sha256:" + "80" * 32, set()
    )
    forged = copy.deepcopy(record)
    forged["evidence"]["provider-route"]["candidate-linked"] = False
    try:
        module._validated_provider_negative_cell(
            cell, forged, "sha256:" + "80" * 32, set()
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("provider-negative validator accepted an unlinked route")


def assert_rollout_provider_negative_validator(module, template_cell):
    """Exercises same-machine dependency and one-machine map rejection proofs."""

    interface = {
        "name": "aos.ab-image-rollout-effects",
        "abi": 1,
        "descriptor": "sha256:" + "09" * 32,
    }
    machine = {"provider": {"key": "rollout"}, "key": "machine"}
    forged_machine = {"provider": {"key": "rollout"}, "key": "foreign-machine"}
    sentinel = {"provider": {"key": "sentinel"}, "key": "foreign-service"}
    snapshot = "sha256:" + "44" * 32

    def oracle(kind, resource):
        return {
            "kind": kind,
            "resource": resource,
            "before": snapshot,
            "after": snapshot,
            "unchanged": True,
            "live": True,
        }

    for mode, scenario, method, effect_class in [
        ("rollout-dependency", "block-dependent-effect", "observe-boot", "observation"),
        (
            "rollout-map-validation",
            "reject-foreign-resource-mutation",
            "prepare",
            "mutation",
        ),
    ]:
        cell = copy.deepcopy(template_cell)
        cell.update(
            {
                "id": f"image-rollout/aos.ab-image-rollout-effects/abi-1/{method}/{scenario}",
                "adapter": "image-rollout",
                "interface": interface,
                "method": method,
                "effect_class": effect_class,
                "boundary": "dependency" if scenario == "block-dependent-effect" else "foreign-resource",
                "failure": "prerequisite-failed" if scenario == "block-dependent-effect" else "foreign-authority-rejected",
                "postconditions": [
                    "durable-attempt-state-classified",
                    "at-most-one-resource-owner",
                    "foreign-resources-unchanged",
                    "dependent-effects-not-executed",
                    (
                        "prerequisite-failure-recorded"
                        if scenario == "block-dependent-effect"
                        else "foreign-attempt-rejected-before-mutation"
                    ),
                ],
            }
        )
        cell_digest = module.sha256(cell)
        predecessor_resource = machine if mode == "rollout-dependency" else forged_machine
        predecessor = {
            "key": {"scope": ["negative"], "key": "predecessor"},
            "ordinal": 0,
            "interface": interface,
            "method": method,
            "resource": predecessor_resource,
        }
        dependent = {
            "key": {"scope": ["negative"], "key": "dependent"},
            "ordinal": 1,
            "interface": interface,
            "method": method,
            "resource": machine,
        }
        witness = (
            {
                "key": {"scope": ["negative"], "key": "witness"},
                "ordinal": 2,
                "interface": interface,
                "method": "hold",
                "resource": machine,
            }
            if effect_class == "observation"
            else None
        )
        plan_digest = "sha256:" + "20" * 32
        subject = {
            "schema": module.PROVIDER_NEGATIVE_SUBJECT_SCHEMA,
            "cell-id": cell["id"],
            "cell-digest": cell_digest,
            "adapter": "image-rollout",
            "interface": interface,
            "method": method,
            "scenario": scenario,
            "plan": plan_digest,
            "transaction": "rollout-negative",
            "flight": "rollout-flight",
        }
        classification = (
            {
                "kind": "execution-journal",
                "digest": "sha256:" + "30" * 32,
                "failure-record": "sha256:" + "31" * 32,
                "predecessor-timeline": [
                    {"kind": "operation-admitted"},
                    {"kind": "effect-started"},
                    {"kind": "rejected-before-effect"},
                ],
                "dependent-timeline": [],
                "witness-timeline": [],
                "classified": "boot-slot-authority-rejected",
            }
            if mode == "rollout-dependency"
            else {
                "kind": "native-resource-map-validation",
                "digest": "sha256:" + "30" * 32,
                "attempted-map-digest": "sha256:" + "31" * 32,
                "failure-record": "sha256:" + "32" * 32,
                "classified": "foreign-authority-rejected",
                "dependent-timeline": [],
                "witness-timeline": [],
            }
        )
        ownership = (
            {
                "machine-owner-count-before": 1,
                "machine-owner-count-after": 1,
                "candidate-owner-count": 0,
                "maximum-owner-count": 1,
            }
            if mode == "rollout-dependency"
            else {
                "machine-owner-count-before": 1,
                "machine-owner-count-after": 1,
                "forged-owner-count": 0,
                "maximum-owner-count": 1,
            }
        )
        record = {
            "mode": mode,
            "cell_digest": cell_digest,
            "subject": subject,
            "plan_bundle": {
                "schema": module.PROVIDER_NEGATIVE_PLAN_SCHEMA,
                "digest": "sha256:" + "40" * 32,
                "plan": plan_digest,
                "foreign-operation": predecessor,
                "dependent-operation": dependent,
                "required-success": {
                    "from": predecessor,
                    "to": dependent,
                    "kind": "required-success",
                },
                "behavioral-witness": witness,
            },
            "evidence": {
                "provider-route": {
                    "adapter": "image-rollout",
                    "interface": interface,
                    "method": method,
                    "candidate-linked": True,
                    "artifact": "sha256:" + "50" * 32,
                    "handler": "image-rollout-terminal",
                    "entry-point": "libexec/aos-ab-image-rollout-handler-v1",
                },
                "boundary": (
                    "after-durable-intent-before-external-effect"
                    if mode == "rollout-dependency"
                    else "native-resource-map-validation"
                ),
                "classification": classification,
                "ownership": ownership,
                "foreign-resource": oracle("systemd-unit", sentinel),
                "blocked-successor": oracle("boot-slot", machine),
                "blocked-witness": (
                    oracle("boot-slot", machine) if witness is not None else None
                ),
            },
        }

        module._validated_provider_negative_cell(
            cell, record, "sha256:" + "60" * 32, set()
        )
        forged = copy.deepcopy(record)
        forged["evidence"]["blocked-successor"]["after"] = "sha256:" + "61" * 32
        try:
            module._validated_provider_negative_cell(
                cell, forged, "sha256:" + "60" * 32, set()
            )
        except RuntimeError:
            pass
        else:
            raise AssertionError("rollout validator accepted changed boot-slot state")


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


def assert_postgresql_cohort(module):
    """Exercises exact compatible and incompatible PostgreSQL evidence."""

    digest = lambda byte: "sha256:" + byte * 64
    interface = {
        "name": "aos.postgresql-effects",
        "abi": 1,
        "descriptor": (
            "sha256:6a1e7d5fb03d9b91127144a64fb96e4c98f4995e7f4f0de258f79fb61fbb9fd6"
        ),
    }
    resource_interface = {
        "name": "aos.postgresql",
        "abi": 1,
        "descriptor": digest("2"),
    }
    resource = {
        "provider": {
            "environment": {"authority": "test", "key": "host", "stage": "host"},
            "key": "postgresql",
        },
        "key": "database-postgresql",
    }
    state_format = {
        "schema": "postgresql-17",
        "descriptor": digest("3"),
        "artifact": {"store_path": "/nix/store/" + "a" * 32 + "-state"},
    }

    def endpoint(label, format_value):
        return {
            "provider": {"scope": [label], "key": "postgresql"},
            "package": digest("4" if label == "source" else "5"),
            "interface": resource_interface,
            "implementation": {"descriptor": digest("6" if label == "source" else "7")},
            "state_format": format_value,
            "handler_binding": {"scope": [label], "key": "postgresql-handler"},
            "handler_method": "materialize",
            "handler_provider": {"scope": [label], "key": "terminal"},
            "handler_incarnation": f"{label}-incarnation",
            "handler_interface": interface,
            "handler_implementation": {"descriptor": digest("8" if label == "source" else "9")},
            "handler_package": digest("a" if label == "source" else "b"),
        }

    adoption = {
        "resource": resource,
        "resource_interface": resource_interface,
        "source": endpoint("source", state_format),
        "candidate": endpoint("candidate", state_format),
    }
    authority = {
        "current_planning": digest("c"),
        "desired_planning": digest("d"),
        "authorization_policy_revision": digest("e"),
        "provider_adoptions": [adoption],
    }
    operation = {
        "key": {"scope": ["candidate"], "key": "materialize-postgresql"},
        "interface": interface,
        "method": "materialize",
        "target": {
            "interface": interface,
            "resource": resource,
            "operations": ["materialize"],
            "lifetime": "persistent",
        },
    }
    restart_operation = {
        **operation,
        "key": {"scope": ["candidate"], "key": "restart-postgresql"},
        "method": "restart",
        "target": {**operation["target"], "operations": ["restart"]},
    }
    bundle = {
        "schema": "aos.ability.plan-bundle/v1",
        "plan": digest("f"),
        "transition_authority": authority,
        "transition": {
            "effect_document": {
                "operations": [operation, restart_operation],
                "edges": [
                    {
                        "from": {"kind": "operation", "key": operation["key"]},
                        "to": {
                            "kind": "operation",
                            "key": restart_operation["key"],
                        },
                        "kind": "required-success",
                    }
                ],
            }
        },
    }
    bundle_bytes = module.canonical(bundle)
    subject = module._postgresql_plan_subject(bundle_bytes, "materialize")
    cell = {
        "id": module.POSTGRESQL_CELL_IDS[0],
        "adapter": "postgresql",
        "interface": {
            **interface,
        },
        "method": "materialize",
        "boundary": "recovery",
        "failure": "none",
        "candidate": "compatible-replacement",
        "predecessor": "in-flight-compatible",
    }
    module._validate_cohort_subject(cell, subject, bundle_bytes)

    row_digest = digest("0")
    facts = {
        "durable-attempt-state-classified": {
            "transaction": "transaction-postgresql",
            "plan": subject["plan"],
            "operation": subject["operation"],
            "timeline": [
                {"sequence": index, "kind": kind, "node-ordinal": 0}
                for index, kind in enumerate(
                    ["operation-admitted", "effect-started", "effect-completed"]
                )
            ],
            "record-digest": digest("1"),
            "terminal": "complete",
            "classified": True,
        },
        "at-most-one-resource-owner": {
            "resource": resource,
            "owners-before": [{"identity": module.endpoint_identity(adoption["source"])}],
            "owners-unsettled": [],
            "owners-after": [{"identity": module.endpoint_identity(adoption["candidate"])}],
        },
        "foreign-resources-unchanged": {
            "resource": {"provider": "test", "key": "storage"},
            "snapshot-before": digest("2"),
            "snapshot-after": digest("2"),
            "unchanged": True,
        },
        "fresh-receiving-authority": {
            "source-handler-incarnation": "source-incarnation",
            "candidate-handler-incarnation": "candidate-incarnation",
            "authorization-policy-revision": authority["authorization_policy_revision"],
            "current-planning": authority["current_planning"],
            "desired-planning": authority["desired_planning"],
            "fresh": True,
        },
        "compatible-state-adopted": {
            "resource": resource,
            "source-state-format": state_format,
            "candidate-state-format": state_format,
            "system-identifier-before": "cluster-1",
            "system-identifier-after": "cluster-1",
            "row-digest-before": row_digest,
            "row-digest-after": row_digest,
            "adopted": True,
        },
        "exactly-one-resource-owner": {
            "resource": resource,
            "expected-owner": {"identity": module.endpoint_identity(adoption["candidate"])},
            "owners": [{"identity": module.endpoint_identity(adoption["candidate"])}],
        },
    }
    for name, observation in facts.items():
        module._validate_postgresql_probe_facts(name, observation, subject, cell)

        invalid = copy.deepcopy(observation)
        if name == "durable-attempt-state-classified":
            invalid["classified"] = False
        elif name == "at-most-one-resource-owner":
            invalid["owners-after"].append({"identity": "foreign"})
        elif name == "foreign-resources-unchanged":
            invalid["snapshot-after"] = digest("3")
        elif name == "fresh-receiving-authority":
            invalid["fresh"] = False
        elif name == "compatible-state-adopted":
            invalid["adopted"] = False
        else:
            invalid["owners"] = []
        try:
            module._validate_postgresql_probe_facts(name, invalid, subject, cell)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"PostgreSQL {name} validator accepted false facts")

    incompatible = copy.deepcopy(adoption)
    incompatible["candidate"]["state_format"] = {
        **state_format,
        "descriptor": digest("9"),
    }
    rejection_policy = {
        "transition_authority": {**authority, "provider_adoptions": [incompatible]}
    }
    policy_bytes = module.canonical(rejection_policy)
    activation = {
        "authenticated_policy_set": {
            "document_sha256": "sha256:" + hashlib.sha256(policy_bytes).hexdigest(),
            "document_size": len(policy_bytes),
        }
    }
    rejection = {
        "schema": module.POSTGRESQL_REJECTION_EVIDENCE_SCHEMA,
        "activation": activation,
        "policy": rejection_policy,
        "observation": {
            "error": "state-format descriptors are incompatible",
            "generation-before": 7,
            "generation-after": 7,
            "owner-ledger-before": digest("1"),
            "owner-ledger-after": digest("1"),
            "persistent-state-before": digest("2"),
            "persistent-state-after": digest("2"),
            "candidate-effect-count": 0,
        },
    }
    rejection_bytes = module.canonical(rejection)
    rejection_subject = module._postgresql_rejection_subject(rejection_bytes)
    rejection_cell = {
        **cell,
        "id": module.POSTGRESQL_CELL_IDS[1],
        "failure": "transfer-rejected",
        "candidate": "unsupported-replacement",
        "predecessor": "in-flight-incompatible",
    }
    module._validate_cohort_subject(
        rejection_cell, rejection_subject, rejection_bytes
    )

    incompatible_facts = {
        "durable-attempt-state-classified": {
            "transaction": "planning-rejection",
            "plan": rejection_subject["plan"],
            "operation": rejection_subject["operation"],
            "timeline": [],
            "record-digest": digest("1"),
            "terminal": "rejected-before-effect",
            "classified": True,
        },
        "dependent-effects-not-executed": {
            "predecessor-operation": rejection_subject["operation"],
            "dependent-operations": [],
            "dependent-timelines-before-settlement": [],
            "dependent-effect-count-before-settlement": 0,
            "blocked": True,
        },
        "transfer-rejected-before-candidate-effect": {
            "candidate-operation": rejection_subject["operation"],
            "source-state-format": rejection_subject["source"]["state_format"],
            "candidate-state-format": rejection_subject["candidate"]["state_format"],
            "rejection": "transfer-rejected",
            "candidate-effect-count": 0,
            "generation-before": 7,
            "generation-after": 7,
            "rejected-before-effect": True,
        },
        "predecessor-remains-sole-owner": {
            "resource": resource,
            "predecessor-owner-before": {"identity": "source"},
            "predecessor-owner-after": {"identity": "source"},
            "system-identifier-before": "cluster-1",
            "system-identifier-after": "cluster-1",
            "row-digest-before": row_digest,
            "row-digest-after": row_digest,
        },
    }
    for name, observation in incompatible_facts.items():
        module._validate_postgresql_probe_facts(
            name, observation, rejection_subject, rejection_cell
        )
        invalid = copy.deepcopy(observation)
        if name == "durable-attempt-state-classified":
            invalid["classified"] = False
        elif name == "dependent-effects-not-executed":
            invalid["blocked"] = False
        elif name == "transfer-rejected-before-candidate-effect":
            invalid["candidate-effect-count"] = 1
        else:
            invalid["row-digest-after"] = digest("3")
        try:
            module._validate_postgresql_probe_facts(
                name, invalid, rejection_subject, rejection_cell
            )
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"PostgreSQL {name} validator accepted false facts")

    restart_subject = module._postgresql_plan_subject(bundle_bytes, "restart")
    lost_cell = {
        **cell,
        "id": module.POSTGRESQL_CELL_IDS[2],
        "method": "restart",
        "failure": "external-result-lost",
    }
    retained_cell = {
        **lost_cell,
        "id": module.POSTGRESQL_CELL_IDS[3],
        "failure": "none",
        "candidate": "retained-target",
        "predecessor": "current-authority",
    }
    module._validate_cohort_subject(lost_cell, restart_subject, bundle_bytes)
    module._validate_cohort_subject(retained_cell, restart_subject, bundle_bytes)

    restart_timeline = {
        "transaction": "transaction-postgresql",
        "plan": restart_subject["plan"],
        "operation": restart_subject["operation"],
        "timeline": [
            {"sequence": index, "kind": kind, "node-ordinal": 1}
            for index, kind in enumerate(
                [
                    "operation-admitted",
                    "effect-started",
                    "operation-admitted",
                    "reconciliation-started",
                    "reconciled-completed",
                ]
            )
        ],
        "record-digest": digest("1"),
        "terminal": "complete",
        "classified": True,
    }
    module._validate_postgresql_probe_facts(
        "durable-attempt-state-classified",
        restart_timeline,
        restart_subject,
        lost_cell,
    )
    module._validate_postgresql_probe_facts(
        "dependent-effects-not-executed",
        {
            "predecessor-operation": restart_subject["operation"],
            "dependent-operations": [],
            "dependent-timelines-before-settlement": [],
            "dependent-effect-count-before-settlement": 0,
            "blocked": True,
        },
        restart_subject,
        lost_cell,
    )

    retained_facts = {
        "current-grants-reauthorized": {
            "authorization-policy-revision": authority["authorization_policy_revision"],
            "source-handler-incarnation": "source-incarnation",
            "candidate-handler-incarnation": "candidate-incarnation",
            "current-planning": authority["current_planning"],
            "desired-planning": authority["desired_planning"],
            "reauthorized": True,
        },
        "retained-target-identity-preserved": {
            "resource": resource,
            "data-path-before": "/var/lib/postgresql/data",
            "data-path-after": "/var/lib/postgresql/data",
            "system-identifier-before": "cluster-1",
            "system-identifier-after": "cluster-1",
            "row-digest-before": row_digest,
            "row-digest-after": row_digest,
        },
    }
    for name, observation in retained_facts.items():
        module._validate_postgresql_probe_facts(
            name, observation, restart_subject, retained_cell
        )
        invalid = copy.deepcopy(observation)
        if name == "current-grants-reauthorized":
            invalid["reauthorized"] = False
        else:
            invalid["data-path-after"] = "/var/lib/postgresql/replaced"
        try:
            module._validate_postgresql_probe_facts(
                name, invalid, restart_subject, retained_cell
            )
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"PostgreSQL {name} validator accepted false facts")

    invalid_rejection = copy.deepcopy(rejection)
    invalid_rejection["observation"]["candidate-effect-count"] = 1
    invalid_rejection_bytes = module.canonical(invalid_rejection)
    try:
        module._validate_cohort_subject(
            rejection_cell,
            rejection_subject,
            invalid_rejection_bytes,
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("PostgreSQL rejection accepted a candidate effect")


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
            "interruption-position": 11,
            "settlement-position": 14,
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
            "publish-settlement-sequence": 8,
            "publish-settlement-position": 13,
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
    scope = [
        module.QUALIFIED_CELL_PREFIX + scenario
        for scenario in module.QUALIFIED_CRASH_SCENARIOS
    ]
    scenarios = {
        "interrupt-after-durable-intent": {
            "boundary": "after-durable-intent",
            "failure": "injected-interruption",
            "disposition": "reconciled-after-interruption",
        },
        "interrupt-after-durable-outcome": {
            "boundary": "after-durable-outcome",
            "failure": "injected-interruption",
            "disposition": "completed-before-interruption",
        },
    }
    for scenario, scenario_spec in scenarios.items():
        scenario_cell_id = module.QUALIFIED_CELL_PREFIX + scenario
        scenario_cell = copy.deepcopy(spec["cells"][0])
        scenario_cell.update(
            {
                "id": scenario_cell_id,
                "boundary": scenario_spec["boundary"],
                "failure": scenario_spec["failure"],
            }
        )
        spec["cells"].append(scenario_cell)

        scenario_observations = copy.deepcopy(observations)
        durable = scenario_observations["durable-attempt-state-classified"]
        expected_timeline = module.EXPECTED_ATTEMPT_TIMELINES[scenario]
        expected_boundaries = module.EXPECTED_ATTEMPT_BOUNDARIES[scenario]
        offset = 20 if scenario == "interrupt-after-durable-intent" else 40
        durable["transaction"] = "transaction-" + scenario
        durable["journal-before-loss"] = (
            "66" if scenario == "interrupt-after-durable-intent" else "77"
        ) * 32
        durable["timeline"] = [
            {"sequence": offset + index, "kind": kind, "node-ordinal": 5}
            for index, kind in enumerate(expected_timeline)
        ]
        durable["boundary-timeline"] = [
            {
                "transcript-position": offset + index,
                "purpose": purpose,
                "boundary": boundary,
            }
            for index, (purpose, boundary) in enumerate(expected_boundaries)
        ]
        interruption_index = {
            "interrupt-after-durable-intent": 0,
            "interrupt-after-durable-outcome": 2,
        }[scenario]
        durable["interruption-position"] = durable["boundary-timeline"][
            interruption_index
        ]["transcript-position"]
        durable["settlement-position"] = durable["boundary-timeline"][-1][
            "transcript-position"
        ]

        ownership = scenario_observations["at-most-one-resource-owner"]
        ownership["revision"] = "revision-" + scenario
        foreign = scenario_observations["foreign-resources-unchanged"]
        for field in [
            "content-before",
            "content-unsettled",
            "content-after-gc",
            "content-after-recovery",
        ]:
            foreign[field] = "unchanged-" + scenario
        dependency = scenario_observations["dependent-effects-not-executed"]
        dependency["publish-settlement-sequence"] = durable["timeline"][-1][
            "sequence"
        ]
        dependency["publish-settlement-position"] = durable[
            "boundary-timeline"
        ][-1]["transcript-position"]
        dependent_offset = offset + len(expected_timeline) + 2
        dependency["timeline-after-recovery"] = [
            {
                "sequence": dependent_offset + index,
                "kind": kind,
                "node-ordinal": 2,
            }
            for index, kind in enumerate(module.DEPENDENT_EFFECT_TIMELINE)
        ]
        dependency["effect-boundary-timeline"] = [
            {
                "transcript-position": dependent_offset + index,
                "purpose": purpose,
                "boundary": boundary,
            }
            for index, (purpose, boundary) in enumerate(
                module.DEPENDENT_EFFECT_BOUNDARY_TIMELINE
            )
        ]
        dependency["dependent-effect-return-position"] = dependency[
            "effect-boundary-timeline"
        ][1]["transcript-position"]
        dependency["route-while-unsettled"] = "predecessor-" + scenario
        dependency["route-after-recovery"] = "candidate-" + scenario
        probes[scenario_cell_id] = {
            name: {
                "kind": module.POSTCONDITION_KINDS[name],
                "detail": f"independent {scenario} {name} probe passed",
                "disposition": scenario_spec["disposition"],
                "observations": scenario_observations[name],
            }
            for name in names
        }

    spec["cells"].sort(key=lambda cell: cell["id"])
    cells, count = module.build_cells(
        spec,
        probes,
        scope,
        {qualified: subject for qualified in scope},
        {qualified: plan_bundle for qualified in scope},
        "sha256:" + "11" * 32,
        "sha256:" + "22" * 32,
    )
    assert count == 12
    qualified_cells = {cell["id"]: cell for cell in cells}
    assert all(
        all(value["passed"] for value in qualified_cells[qualified]["postconditions"].values())
        for qualified in scope
    )
    cell_observation = qualified_cells[cell_id]
    cell_spec = next(cell for cell in spec["cells"] if cell["id"] == cell_id)
    assert set(cell_observation["probes"]) == set(names)
    assert cell_observation["cohort_subject"]["subject"] == subject
    assert cell_observation["cohort_subject"]["cell_id"] == cell_id
    assert cell_observation["cohort_subject"]["cell_digest"] == module.sha256(cell_spec)
    assert {
        probe["cohort_subject_digest"] for probe in cell_observation["probes"].values()
    } == {module.sha256(cell_observation["cohort_subject"])}
    assert {
        probe["cell_id"] for probe in cell_observation["probes"].values()
    } == {cell_id}
    assert {
        probe["cell_digest"] for probe in cell_observation["probes"].values()
    } == {module.sha256(cell_spec)}
    assert_semantic_validators(module, subject, cell_spec, observations)
    assert_provider_negative_validator(module, cell_spec)
    assert_rollout_provider_negative_validator(module, cell_spec)
    assert_negative_semantic_validators(module, subject, cell_spec)
    assert_postgresql_cohort(module)

    authority_cell = copy.deepcopy(cell_spec)
    authority_cell.update(
        {
            "id": (
                "managed-configuration/aos.managed-configuration-effects/abi-1/"
                "publish/revoke-caller-before-acquisition"
            ),
            "boundary": "before-acquisition",
            "failure": "caller-authority-revoked",
        }
    )
    authority_digest = module.sha256(authority_cell)
    audit_digest = "sha256:" + "66" * 32
    authority_record = {
        "cell_digest": authority_digest,
        "subject": {
            "schema": "aos.qualification.native-adapter-runtime-subject/v1",
            "cell-id": authority_cell["id"],
            "cell-digest": authority_digest,
            "interface": authority_cell["interface"],
            "method": authority_cell["method"],
            "plan": "sha256:" + "77" * 32,
            "transaction": "authority-fixture",
        },
        "plan_bundle": {
            "schema": "aos.qualification.native-adapter-runtime-plan/v1",
            "digest": audit_digest,
            "bytes-sha256": audit_digest,
        },
        "evidence": {
            "role": "caller-binding-grant",
            "authority-boundary": "before-resource-acquisition",
            "runtime-boundary": "BeforeResourceAcquisition",
            "journal": {
                "digest": "sha256:" + "88" * 32,
                "head": "sha256:" + "99" * 32,
                "authority-rejections": 1,
                "effect-outcomes": 0,
            },
            "reservation-ledger": {
                "digest": "sha256:" + "aa" * 32,
                "acquire-calls": 0,
                "release-calls": 0,
                "max-owners": 0,
                "owners": 0,
            },
            "dispatch-calls": 0,
            "foreign-before": "sha256:" + "bb" * 32,
            "foreign-after": "sha256:" + "bb" * 32,
        },
    }
    control_cell = copy.deepcopy(cell_spec)
    control_cell.update(
        {
            "id": (
                "managed-configuration/aos.managed-configuration-effects/abi-1/"
                "publish/cancel-unsettled-attempt"
            ),
            "boundary": "cancellation",
            "failure": "unsupported-cancellation-retains-ownership",
            "recovery": {
                "reconcile": control_cell["recovery"]["reconcile"],
                "cancel": None,
            },
        }
    )
    control_digest = module.sha256(control_cell)
    control_record = {
        "cell_digest": control_digest,
        "subject": {
            "schema": "aos.qualification.native-adapter-runtime-subject/v1",
            "cell-id": control_cell["id"],
            "cell-digest": control_digest,
            "interface": control_cell["interface"],
            "method": control_cell["method"],
            "plan": "sha256:" + "12" * 32,
            "transaction": "control-fixture",
        },
        "plan_bundle": {
            "schema": "aos.qualification.native-adapter-runtime-plan/v1",
            "digest": "sha256:" + "13" * 32,
            "bytes-sha256": "sha256:" + "13" * 32,
        },
        "evidence": {
            "scenario": "cancel-unsettled-attempt",
            "classification": "cancellation-unsupported-intervention",
            "recovery-routes": control_cell["recovery"],
            "fixture-recovery-routes": {
                "reconcile": control_cell["method"],
                "cancel": None,
            },
            "journal": {
                "digest": "sha256:" + "14" * 32,
                "head": "sha256:" + "15" * 32,
                "cancellation-requested": 0,
                "cancellation-observed": 0,
                "cancellation-interventions": 1,
                "deadline-aborts": 0,
                "dependent-effect-events": 0,
                "dependent-settlements": 1,
            },
            "reservation-ledger": {
                "digest": "sha256:" + "16" * 32,
                "acquire-calls": 1,
                "release-calls": 0,
                "release-failures": 0,
                "max-owners": 1,
                "owners-at-failure": 1,
                "owners-final": 1,
                "retained-resources": 1,
                "cleanup-errors": 0,
            },
            "adapter": {
                "execute-calls": 0,
                "reconcile-calls": 0,
                "cancel-calls": 0,
            },
            "clock": {"now-millis": 1, "restart-stable-millis": 1},
            "foreign-before": "sha256:" + "17" * 32,
            "foreign-after": "sha256:" + "17" * 32,
        },
    }
    replacement_primary = copy.deepcopy(subject["publish-operation"])
    replacement_primary["preconditions"] = [
        {
            "resource": replacement_primary["target"]["resource"],
            "expected_revision": None,
            "expected_incarnation": "planned-provider-incarnation",
        }
    ]
    replacement_dependent = copy.deepcopy(replacement_primary)
    replacement_dependent["key"] = {
        "scope": ["audit"],
        "key": "matrix-dependent",
    }
    replacement_edge = {
        "from": {"kind": "operation", "key": replacement_primary["key"]},
        "to": {"kind": "operation", "key": replacement_dependent["key"]},
        "kind": "required-success",
    }
    provider_cell = copy.deepcopy(authority_cell)
    provider_cell.update(
        {
            "id": (
                "managed-configuration/aos.managed-configuration-effects/abi-1/"
                "publish/replace-provider-incarnation"
            ),
            "boundary": "recovery",
            "failure": "stale-provider-rejected",
            "candidate": "new-provider-incarnation",
            "predecessor": "in-flight",
        }
    )
    provider_digest = module.sha256(provider_cell)
    provider_record = {
        "cell_digest": provider_digest,
        "subject": {
            "schema": (
                "aos.qualification.native-adapter-incarnation-replacement-subject/v1"
            ),
            "cell-id": provider_cell["id"],
            "cell-digest": provider_digest,
            "interface": provider_cell["interface"],
            "method": provider_cell["method"],
            "plan": "sha256:" + "31" * 32,
            "transaction": "provider-fixture",
            "primary-operation": replacement_primary,
            "dependent-operation": replacement_dependent,
            "dependency-edge": replacement_edge,
        },
        "plan_bundle": {
            "schema": "aos.qualification.native-adapter-runtime-plan/v1",
            "digest": "sha256:" + "32" * 32,
            "bytes-sha256": "sha256:" + "32" * 32,
        },
        "evidence": {
            "role": None,
            "authority-boundary": None,
            "runtime-boundary": "ProviderCatalogReplacement",
            "rejection": {
                "kind": "resource-provider-incarnation-precondition",
                "digest": "sha256:" + "33" * 32,
            },
            "journal": {
                "digest": "sha256:" + "34" * 32,
                "head": "sha256:" + "35" * 32,
                "authority-rejections": 0,
                "effect-outcomes": 0,
            },
            "reservation-ledger": {
                "digest": "sha256:" + "36" * 32,
                "acquire-calls": 1,
                "release-calls": 1,
                "max-owners": 1,
                "owners": 0,
            },
            "dispatch-calls": 0,
            "initial-ready": [replacement_primary["key"]],
            "blocked-dependent": replacement_dependent["key"],
            "foreign-before": "sha256:" + "37" * 32,
            "foreign-after": "sha256:" + "37" * 32,
        },
    }
    executor_cell = copy.deepcopy(provider_cell)
    executor_cell.update(
        {
            "id": (
                "managed-configuration/aos.managed-configuration-effects/abi-1/"
                "publish/replace-executor-incarnation"
            ),
            "failure": "stale-executor-rejected",
            "candidate": "new-executor-incarnation",
        }
    )
    executor_record = copy.deepcopy(provider_record)
    executor_digest = module.sha256(executor_cell)
    executor_record["cell_digest"] = executor_digest
    executor_record["subject"].update(
        {
            "cell-id": executor_cell["id"],
            "cell-digest": executor_digest,
            "transaction": "executor-fixture",
        }
    )
    executor_record["evidence"]["runtime-boundary"] = "ExecutorSessionReplacement"
    executor_record["evidence"]["rejection"] = {
        "kind": "stale-executor-admission",
        "digest": "sha256:" + "38" * 32,
    }
    executor_record["evidence"]["reservation-ledger"].update(
        {"release-calls": 0, "owners": 1}
    )
    runtime_spec = {
        "cells": [
            *spec["cells"],
            authority_cell,
            provider_cell,
            executor_cell,
            control_cell,
        ]
    }
    runtime_audit = {
        "schema": "aos.qualification.native-adapter-runtime-audit/v2",
        "matrix_spec_digest": module.sha256(runtime_spec),
        "cells": {
            authority_cell["id"]: authority_record,
            provider_cell["id"]: provider_record,
            executor_cell["id"]: executor_record,
            control_cell["id"]: control_record,
        },
    }
    runtime_scope = [
        *scope,
        authority_cell["id"],
        provider_cell["id"],
        executor_cell["id"],
        control_cell["id"],
    ]
    authority_cells, authority_count = module.build_cells(
        runtime_spec,
        probes,
        runtime_scope,
        {qualified: subject for qualified in scope},
        {qualified: plan_bundle for qualified in scope},
        "sha256:" + "11" * 32,
        "sha256:" + "22" * 32,
        runtime_audit,
    )
    assert authority_count == 28
    authority_observations = {
        cell["id"]: cell for cell in authority_cells
    }[authority_cell["id"]]
    assert all(
        value["passed"]
        for value in authority_observations["postconditions"].values()
    )
    control_observations = {
        cell["id"]: cell for cell in authority_cells
    }[control_cell["id"]]
    assert all(
        value["passed"]
        for value in control_observations["postconditions"].values()
    )
    for replacement_cell in [provider_cell, executor_cell]:
        replacement_observations = {
            cell["id"]: cell for cell in authority_cells
        }[replacement_cell["id"]]
        assert all(
            value["passed"]
            for value in replacement_observations["postconditions"].values()
        )
    rejected_audit = copy.deepcopy(runtime_audit)
    rejected_audit["cells"][authority_cell["id"]]["evidence"][
        "dispatch-calls"
    ] = 1
    try:
        module.build_cells(
            runtime_spec,
            probes,
            runtime_scope,
            {qualified: subject for qualified in scope},
            {qualified: plan_bundle for qualified in scope},
            "sha256:" + "11" * 32,
            "sha256:" + "22" * 32,
            rejected_audit,
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("authority audit accepted an adapter dispatch")

    rejected_provider = copy.deepcopy(runtime_audit)
    rejected_provider["cells"][provider_cell["id"]]["evidence"]["rejection"][
        "kind"
    ] = "fresh-authority-revoked"
    try:
        module.build_cells(
            runtime_spec,
            probes,
            runtime_scope,
            {qualified: subject for qualified in scope},
            {qualified: plan_bundle for qualified in scope},
            "sha256:" + "11" * 32,
            "sha256:" + "22" * 32,
            rejected_provider,
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("provider replacement accepted another rejection kind")

    rejected_graph = copy.deepcopy(runtime_audit)
    rejected_graph["cells"][executor_cell["id"]]["subject"]["dependency-edge"][
        "kind"
    ] = "ordering-only"
    try:
        module.build_cells(
            runtime_spec,
            probes,
            runtime_scope,
            {qualified: subject for qualified in scope},
            {qualified: plan_bundle for qualified in scope},
            "sha256:" + "11" * 32,
            "sha256:" + "22" * 32,
            rejected_graph,
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("executor replacement accepted a non-blocking graph")

    rejected_control = copy.deepcopy(runtime_audit)
    rejected_control["cells"][control_cell["id"]]["evidence"]["journal"][
        "cancellation-interventions"
    ] = 0
    try:
        module.build_cells(
            runtime_spec,
            probes,
            runtime_scope,
            {qualified: subject for qualified in scope},
            {qualified: plan_bundle for qualified in scope},
            "sha256:" + "11" * 32,
            "sha256:" + "22" * 32,
            rejected_control,
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("runtime audit accepted a missing cancellation intervention")

    supported_control_cell = copy.deepcopy(control_cell)
    supported_control_cell["failure"] = "cancelled-after-reconciliation"
    supported_control_cell["recovery"]["cancel"] = "cancel"
    supported_control_record = copy.deepcopy(control_record)
    supported_control_digest = module.sha256(supported_control_cell)
    supported_control_record["cell_digest"] = supported_control_digest
    supported_control_record["subject"]["cell-digest"] = supported_control_digest
    supported_control_record["evidence"]["recovery-routes"] = supported_control_cell[
        "recovery"
    ]
    try:
        module._validated_failure_control_cell(
            supported_control_cell,
            supported_control_record,
            "sha256:" + "11" * 32,
            set(),
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("runtime audit accepted provider-specific cancellation")

    interruption_cell = copy.deepcopy(cell_spec)
    interruption_cell.update(
        {
            "id": (
                "managed-configuration/aos.managed-configuration-effects/abi-1/"
                "publish/interrupt-before-acquisition"
            ),
            "boundary": "before-acquisition",
            "failure": "injected-interruption",
            "predecessor": "none",
        }
    )
    interruption_digest = module.sha256(interruption_cell)
    interruption_plan = "sha256:" + "c1" * 32
    interruption_transaction = "interruption-fixture"
    interruption_operation = {"scope": ["audit"], "key": "publish"}
    interruption_dependent = {"scope": ["audit"], "key": "dependent"}
    boundary_bytes = {
        "schema": "aos.qualification.interruption-boundary/v1",
        "scenario": "interrupt-before-acquisition",
        "transaction": interruption_transaction,
        "operation": {
            "plan": interruption_plan,
            "operation": interruption_operation,
        },
        "attempt": 1,
        "purpose": "effect",
        "boundary": "BeforeResourceAcquisition",
    }
    journal = {
        "digest": "sha256:" + "c2" * 32,
        "head": "sha256:" + "c3" * 32,
        "state": "pending",
        "events": {"transaction-planned": 1},
    }
    interruption_record = {
        "cell_digest": interruption_digest,
        "subject": {
            "schema": "aos.qualification.interruption-subject/v1",
            "cell-id": interruption_cell["id"],
            "cell-digest": interruption_digest,
            "interface": interruption_cell["interface"],
            "method": interruption_cell["method"],
            "plan": interruption_plan,
            "transaction": interruption_transaction,
            "operation": interruption_operation,
            "dependent-operation": interruption_dependent,
        },
        "plan_bundle": {
            "schema": "aos.qualification.interruption-plan/v1",
            "digest": "sha256:" + "c4" * 32,
            "bytes-sha256": "sha256:" + "c4" * 32,
        },
        "evidence": {
            "scenario": "interrupt-before-acquisition",
            "runtime-boundary": "BeforeResourceAcquisition",
            "declared-recovery-routes": interruption_cell["recovery"],
            "fixture-recovery-routes": {
                "reconcile": interruption_cell["method"],
                "cancel": None,
            },
            "boundary-record": {
                "digest": module.sha256(boundary_bytes),
                "bytes": boundary_bytes,
            },
            "journal-at-fault": journal,
            "journal-after-restart": copy.deepcopy(journal),
            "reservation-ledger": {
                "digest": "sha256:" + "c5" * 32,
                "acquire-calls": 0,
                "release-calls": 0,
                "max-owners": 0,
                "owners": [],
            },
            "adapter-calls": {"total": 0, "dependent": 0},
            "primary-ready-at-restart": True,
            "dependent-ready-at-restart": False,
            "foreign-before": "sha256:" + "c6" * 32,
            "foreign-after": "sha256:" + "c6" * 32,
        },
    }
    combined_spec = {
        "cells": [*runtime_spec["cells"], interruption_cell]
    }
    interruption_audit = {
        "schema": "aos.qualification.interruption-audit/v1",
        "matrix_spec_digest": module.sha256(combined_spec),
        "cells": {interruption_cell["id"]: interruption_record},
    }
    combined_runtime_audit = copy.deepcopy(runtime_audit)
    combined_runtime_audit["matrix_spec_digest"] = module.sha256(combined_spec)
    combined_scope = [
        *scope,
        interruption_cell["id"],
        *runtime_scope[len(scope) :],
    ]
    combined_cells, combined_count = module.build_cells(
        combined_spec,
        probes,
        combined_scope,
        {qualified: subject for qualified in scope},
        {qualified: plan_bundle for qualified in scope},
        "sha256:" + "11" * 32,
        "sha256:" + "22" * 32,
        combined_runtime_audit,
        interruption_audit,
    )
    assert combined_count == 32
    interruption_observation = {
        cell["id"]: cell for cell in combined_cells
    }[interruption_cell["id"]]
    assert all(
        value["passed"]
        for value in interruption_observation["postconditions"].values()
    )
    rejected_interruption = copy.deepcopy(interruption_audit)
    rejected_interruption["cells"][interruption_cell["id"]]["evidence"][
        "reservation-ledger"
    ]["acquire-calls"] = 1
    try:
        module.build_cells(
            combined_spec,
            probes,
            combined_scope,
            {qualified: subject for qualified in scope},
            {qualified: plan_bundle for qualified in scope},
            "sha256:" + "11" * 32,
            "sha256:" + "22" * 32,
            combined_runtime_audit,
            rejected_interruption,
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("interruption audit accepted a resource acquisition")

    first_cell = cell_spec
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
        rejected(module, spec, mutated_probes, scope, mutated_subject, plan_bundle)

    def rejected_publish_operation(path, replacement):
        mutated_subject = copy.deepcopy(subject)
        replace_nested(mutated_subject["publish-operation"], path, replacement)
        mutated_probes = probes_for_subject(mutated_subject)
        rejected(module, spec, mutated_probes, scope, mutated_subject, plan_bundle)

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
        rejected(module, spec, mutated_probes, scope, mutated_subject, plan_bundle)

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
    rejected(module, spec, malformed_transaction, scope, subject, plan_bundle)

    malformed_plan_subject = copy.deepcopy(subject)
    malformed_plan_subject["plan"] = "sha256:short"
    malformed_plan = copy.deepcopy(probes)
    malformed_plan[cell_id]["durable-attempt-state-classified"]["observations"][
        "plan"
    ] = malformed_plan_subject["plan"]
    rejected(module, spec, malformed_plan, scope, malformed_plan_subject, plan_bundle)

    substituted_plan = copy.deepcopy(probes)
    substituted_plan[cell_id]["durable-attempt-state-classified"][
        "observations"
    ]["plan"] = "sha256:" + "77" * 32
    rejected(module, spec, substituted_plan, scope, subject, plan_bundle)

    malformed_bundle_subject = copy.deepcopy(subject)
    malformed_bundle_subject["plan-bundle-digest"] = "sha256:" + "aa" * 32
    rejected(module, spec, probes, scope, malformed_bundle_subject, plan_bundle)

    malformed_journal = copy.deepcopy(probes)
    malformed_journal[cell_id]["durable-attempt-state-classified"][
        "observations"
    ]["journal-before-loss"] = "sha256:" + "55" * 32
    rejected(module, spec, malformed_journal, scope, subject, plan_bundle)

    foreign_scope = ["foreign/aos.interface/abi-1/publish/lose-external-result"]
    rejected(module, spec, probes, foreign_scope, subject, plan_bundle)

    missing = copy.deepcopy(probes)
    del missing[cell_id][names[0]]
    rejected(module, spec, missing, scope, subject, plan_bundle)

    wrong_kind = copy.deepcopy(probes)
    wrong_kind[cell_id][names[0]]["kind"] = "ownership-inventory"
    rejected(module, spec, wrong_kind, scope, subject, plan_bundle)

    wrong_disposition = copy.deepcopy(probes)
    wrong_disposition[cell_id][names[0]]["disposition"] = "invented-success"
    rejected(module, spec, wrong_disposition, scope, subject, plan_bundle)

    unknown = copy.deepcopy(probes)
    unknown[cell_id][names[0]]["claimed"] = True
    rejected(module, spec, unknown, scope, subject, plan_bundle)

    duplicate = copy.deepcopy(probes)
    duplicate[cell_id][names[1]]["observations"] = duplicate[cell_id][names[0]][
        "observations"
    ]
    rejected(module, spec, duplicate, scope, subject, plan_bundle)

    null_observation = copy.deepcopy(probes)
    null_observation[cell_id][names[0]]["observations"] = {"probe": None}
    rejected(module, spec, null_observation, scope, subject, plan_bundle)

    false_barrier = copy.deepcopy(probes)
    false_barrier[cell_id]["dependent-effects-not-executed"]["observations"][
        "changed-only-after-recovery"
    ] = False
    rejected(module, spec, false_barrier, scope, subject, plan_bundle)

    reordered_timeline = copy.deepcopy(probes)
    timeline = reordered_timeline[cell_id]["durable-attempt-state-classified"][
        "observations"
    ]["timeline"]
    timeline[1]["kind"], timeline[3]["kind"] = (
        timeline[3]["kind"],
        timeline[1]["kind"],
    )
    rejected(module, spec, reordered_timeline, scope, subject, plan_bundle)

    reordered_boundaries = copy.deepcopy(probes)
    boundary = reordered_boundaries[cell_id]["durable-attempt-state-classified"][
        "observations"
    ]["boundary-timeline"]
    boundary[1], boundary[3] = boundary[3], boundary[1]
    rejected(module, spec, reordered_boundaries, scope, subject, plan_bundle)

    early_dependent = copy.deepcopy(probes)
    early_dependent[cell_id]["dependent-effects-not-executed"]["observations"][
        "timeline-before-completion"
    ] = [{"sequence": 8, "kind": "operation-admitted", "node-ordinal": 2}]
    rejected(module, spec, early_dependent, scope, subject, plan_bundle)

    wrong_dependent_ordinal = copy.deepcopy(probes)
    wrong_dependent_ordinal[cell_id]["dependent-effects-not-executed"][
        "observations"
    ]["dependent-operation"]["ordinal"] = 8
    rejected(module, spec, wrong_dependent_ordinal, scope, subject, plan_bundle)


if __name__ == "__main__":
    main()
