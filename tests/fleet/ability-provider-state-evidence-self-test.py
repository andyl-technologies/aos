"""Exercises fail-closed provider-state evidence binding."""

from __future__ import annotations

import copy
import importlib.util
import sys
from dataclasses import replace
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("ability-provider-state-evidence.py")
SPEC = importlib.util.spec_from_file_location("provider_state_evidence", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

INTERFACE = {"abi": 1, "descriptor": "sha256:" + "11" * 32, "name": "test.effects"}
RESOURCE = {"key": "resource", "provider": {"key": "provider", "package": "test"}}
IMPLEMENTATION = {
    "artifact": {"digest": "sha256:" + "22" * 32, "name": "handler"},
    "kind": "native",
}
OPERATION_KEY = {"key": "primary", "package": "test"}
DEPENDENT_KEY = {"key": "dependent", "package": "test"}
OPERATION = {
    "binding": {"key": "candidate-binding", "package": "test"},
    "interface": INTERFACE,
    "key": OPERATION_KEY,
    "method": "apply",
    "target": {
        "interface": INTERFACE,
        "lifetime": "instance",
        "operations": ["apply"],
        "resource": RESOURCE,
    },
}
DEPENDENT = {
    "binding": {"key": "dependent-binding", "package": "test"},
    "interface": INTERFACE,
    "key": DEPENDENT_KEY,
    "method": "observe",
    "target": {
        "interface": INTERFACE,
        "lifetime": "instance",
        "operations": ["observe"],
        "resource": {"key": "dependent", "provider": RESOURCE["provider"]},
    },
}
EDGE = {
    "from": {"kind": "operation", "key": OPERATION_KEY},
    "kind": "required-success",
    "to": {"kind": "operation", "key": DEPENDENT_KEY},
}
PLAN = "sha256:" + "33" * 32
TRANSACTION = "provider-state-transaction"
BUNDLE = MODULE.canonical(
    {
        "plan": PLAN,
        "schema": "aos.ability.plan-bundle/v1",
        "transition": {
            "effect_document": {
                "current_revisions": [
                    {"resource": RESOURCE, "revision": "sha256:" + "44" * 32}
                ],
                "desired_revisions": [
                    {"resource": RESOURCE, "revision": "sha256:" + "55" * 32}
                ],
                "edges": [EDGE],
                "operations": [OPERATION, DEPENDENT],
            }
        },
    }
)


def cell(scenario: str, postconditions: list[str]) -> dict:
    """Returns one exact matrix cell for the local contract test."""

    return {
        "adapter": "test",
        "boundary": "recovery",
        "candidate": "current-authority",
        "effect_class": "mutation",
        "failure": "none",
        "id": f"test/test.effects/abi-1/apply/{scenario}",
        "interface": INTERFACE,
        "invalidated_by": ["subject", "policy", "executor", "environment"],
        "matrix_schema": "aos.qualification.native-adapter-matrix/v1",
        "method": "apply",
        "postconditions": postconditions,
        "predecessor": "retained",
        "recovery": {"cancel": "apply", "reconcile": "apply"},
        "scope": "host-resource",
    }


def authority(
    plan: str,
    transaction: str,
    binding_key: str,
    incarnation: str,
    sequence: int,
    observed_at: int,
) -> dict:
    """Returns the closed subset consumed from a real current-authority document."""

    binding = {
        "caller_grant": {
            "methods": ["apply"],
            "resources": [{"operations": ["apply"], "resource": RESOURCE}],
        },
        "id": {"key": binding_key, "package": "test"},
        "implementation": IMPLEMENTATION,
        "interface": INTERFACE,
        "policy_revision": "sha256:" + "66" * 32,
        "provider": RESOURCE["provider"],
        "provider_package": "sha256:" + "77" * 32,
    }
    return {
        "authority_epoch": 1,
        "bindings": [binding],
        "observed_at_restart_millis": observed_at,
        "plan": plan,
        "policy_fence": "sha256:" + "88" * 32,
        "policy_revision": binding["policy_revision"],
        "provider_assignments": [
            {
                "implementation": IMPLEMENTATION,
                "incarnation": incarnation,
                "interface": INTERFACE,
                "provider": RESOURCE["provider"],
            }
        ],
        "resolution_policy": "sha256:" + "99" * 32,
        "resource_observations": [
            {
                "resource": RESOURCE,
                "state": {"revision": "sha256:" + "44" * 32, "state": "present"},
            }
        ],
        "schema": "aos.ability.current-authority/v2",
        "sequence": sequence,
        "transaction": transaction,
    }


def ledger(binding_key: str) -> dict:
    """Returns one exact terminal-consumer claim for the logical resource."""

    return {
        "consumers": [
            {
                "artifacts": ["/nix/store/provider-runtime"],
                "attempt": 1,
                "binding": {"key": binding_key, "package": "test"},
                "consumer": RESOURCE["provider"],
                "desired_revision": "sha256:" + "44" * 32,
                "generation": "gen-1",
                "logical": RESOURCE,
                "operation": OPERATION_KEY,
                "physical": {
                    "authority": "test-authority",
                    "class": "test-resource",
                    "object": "/var/lib/aos/test-resource",
                },
                "plan": PLAN,
                "provider": RESOURCE["provider"],
                "transaction": TRANSACTION,
            }
        ],
        "owners": [],
        "schema": "aos.ability.native-resource-ledger/v1",
    }


LEDGER = ledger("candidate-binding")
RETAINED_POSTCONDITIONS = [
    "durable-attempt-state-classified",
    "at-most-one-resource-owner",
    "foreign-resources-unchanged",
    "current-grants-reauthorized",
    "retained-target-identity-preserved",
    "exactly-one-resource-owner",
]
UNSUPPORTED_POSTCONDITIONS = [
    "durable-attempt-state-classified",
    "at-most-one-resource-owner",
    "foreign-resources-unchanged",
    "dependent-effects-not-executed",
    "fresh-receiving-authority",
    "transfer-rejected-before-candidate-effect",
    "predecessor-remains-sole-owner",
]
RETAINED_CELL = cell(MODULE.RETAINED_SCENARIO, RETAINED_POSTCONDITIONS)
UNSUPPORTED_CELL = cell(MODULE.UNSUPPORTED_SCENARIO, UNSUPPORTED_POSTCONDITIONS)
MATRIX = {"cells": [RETAINED_CELL, UNSUPPORTED_CELL]}


def retained_observation() -> object:
    """Returns a valid retained rollback observation."""

    before = authority(PLAN, TRANSACTION, "candidate-binding", "candidate", 1, 20)
    after = authority(PLAN, TRANSACTION, "candidate-binding", "recovered", 2, 21)
    return MODULE.RetainedTargetObservation(
        retained_generation=1,
        predecessor_generation=2,
        activated_generation=1,
        transaction=TRANSACTION,
        operation_key=OPERATION_KEY,
        journal_before_loss="aa" * 32,
        timeline=[
            {"kind": "operation-admitted", "sequence": 1},
            {"kind": "effect-started", "sequence": 2},
            {"kind": "effect-completed", "sequence": 3},
        ],
        boundary_timeline=[
            {"boundary": "resources-acquired", "purpose": "effect"},
            {"boundary": "effect-returned", "purpose": "effect"},
        ],
        authority_before=before,
        authority_after=after,
        ledger_before=LEDGER,
        ledger_unsettled=LEDGER,
        ledger_after=LEDGER,
        live_before={"revision": "old"},
        live_unsettled={"revision": "old"},
        live_after={"revision": "retained"},
        foreign_before={"revision": "foreign"},
        foreign_unsettled={"revision": "foreign"},
        foreign_after={"revision": "foreign"},
        dependent_operation=MODULE._operation_identity(DEPENDENT, 1),
        dependent_before=[],
        dependent_after=[{"kind": "effect-completed", "sequence": 4}],
    )


def unsupported_observation() -> object:
    """Returns a valid pre-effect transfer rejection observation."""

    source = authority("sha256:" + "aa" * 32, "source", "source-binding", "source", 9, 10)
    candidate = authority(PLAN, TRANSACTION, "candidate-binding", "candidate", 10, 20)
    source_ledger = ledger("source-binding")
    return MODULE.UnsupportedTransferObservation(
        source_generation=2,
        candidate_generation=3,
        transaction=TRANSACTION,
        operation_key=OPERATION_KEY,
        journal_at_rejection="bb" * 32,
        timeline_at_rejection=[{"kind": "operation-admitted", "sequence": 1}],
        boundary_timeline=[
            {"boundary": "resources-acquired", "purpose": "effect"}
        ],
        source_authority=source,
        candidate_authority=candidate,
        ledger_before=source_ledger,
        ledger_after=source_ledger,
        live_before={"revision": "source"},
        live_after={"revision": "source"},
        foreign_before={"revision": "foreign"},
        foreign_after={"revision": "foreign"},
        dependent_operation=MODULE._operation_identity(DEPENDENT, 1),
        dependent_timeline=[],
    )


def unsupported_contract() -> bytes:
    """Returns the canonical production contract shape used by the flight."""

    return MODULE.canonical(
        {
            "disposition": {
                "rejection": {
                    "binding_lifetime": "instance",
                    "reason": "non-persistent-lifetime",
                    "request_lifetime": "instance",
                    "target_lifetime": "instance",
                },
                "status": "unsupported",
            },
            "operation": OPERATION,
            "plan": PLAN,
            "schema": MODULE.TRANSFER_CONTRACT_SCHEMA,
        }
    )


def must_reject(action) -> None:
    """Requires one malformed evidence path to fail closed."""

    try:
        action()
    except RuntimeError:
        return
    raise AssertionError("provider-state evidence accepted a malformed observation")


retained_builder = MODULE.ProviderStateEvidence(MATRIX, [RETAINED_CELL["id"]])
retained_builder.retain_retained_target(
    RETAINED_CELL["id"], BUNDLE, retained_observation()
)
assert set(retained_builder.finish()[2]) == {RETAINED_CELL["id"]}

unsupported_builder = MODULE.ProviderStateEvidence(MATRIX, [UNSUPPORTED_CELL["id"]])
unsupported_builder.retain_unsupported_transfer(
    UNSUPPORTED_CELL["id"], BUNDLE, unsupported_contract(), unsupported_observation()
)
assert set(unsupported_builder.finish()[2]) == {UNSUPPORTED_CELL["id"]}

wrong_generation = replace(retained_observation(), activated_generation=2)
must_reject(
    lambda: MODULE.ProviderStateEvidence(MATRIX, [RETAINED_CELL["id"]]).retain_retained_target(
        RETAINED_CELL["id"], BUNDLE, wrong_generation
    )
)

reused_incarnation = copy.deepcopy(unsupported_observation())
reused_incarnation.candidate_authority["provider_assignments"][0]["incarnation"] = "source"
must_reject(
    lambda: MODULE.ProviderStateEvidence(
        MATRIX, [UNSUPPORTED_CELL["id"]]
    ).retain_unsupported_transfer(
        UNSUPPORTED_CELL["id"], BUNDLE, unsupported_contract(), reused_incarnation
    )
)

missing_owner = copy.deepcopy(unsupported_observation())
missing_owner.ledger_before["consumers"] = []
must_reject(
    lambda: MODULE.ProviderStateEvidence(
        MATRIX, [UNSUPPORTED_CELL["id"]]
    ).retain_unsupported_transfer(
        UNSUPPORTED_CELL["id"], BUNDLE, unsupported_contract(), missing_owner
    )
)

forged_contract = bytearray(unsupported_contract())
forged_contract[-2] = ord(" ")
must_reject(
    lambda: MODULE.ProviderStateEvidence(
        MATRIX, [UNSUPPORTED_CELL["id"]]
    ).retain_unsupported_transfer(
        UNSUPPORTED_CELL["id"], BUNDLE, bytes(forged_contract), unsupported_observation()
    )
)

print("provider-state evidence self-test passed")
