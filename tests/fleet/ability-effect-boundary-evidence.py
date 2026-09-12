"""Builds matrix probes from production native-adapter crash flights.

The flight owns process interruption and provider-specific observation.  This
module only binds those retained facts to the immutable matrix cell and the
exact plan bundle that the candidate package runtime executed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


SUBJECT_SCHEMA = "aos.qualification.native-adapter-effect-cohort-subject/v1"
SCENARIO_BOUNDARIES = {
    "interrupt-after-acquisition": "resources-acquired",
    "interrupt-after-durable-intent": "effect-intent-durable",
    "lose-external-result": "effect-returned",
    "interrupt-after-durable-outcome": "effect-outcome-durable",
}
SCENARIO_DISPOSITIONS = {
    "interrupt-after-acquisition": "unsettled-after-acquisition",
    "interrupt-after-durable-intent": "reconciled-after-interruption",
    "lose-external-result": "reconciled-completed",
    "interrupt-after-durable-outcome": "completed-before-interruption",
}
SCENARIO_TIMELINES = {
    "interrupt-after-acquisition": [
        "operation-admitted",
        "operation-admitted",
        "effect-started",
        "effect-completed",
    ],
    "interrupt-after-durable-intent": [
        "operation-admitted",
        "effect-started",
        "operation-admitted",
        "reconciliation-started",
        "reconciled-safe-to-retry",
        "operation-admitted",
        "effect-started",
        "effect-completed",
    ],
    "lose-external-result": [
        "operation-admitted",
        "effect-started",
        "operation-admitted",
        "reconciliation-started",
        "reconciled-completed",
    ],
    "interrupt-after-durable-outcome": [
        "operation-admitted",
        "effect-started",
        "effect-completed",
    ],
}


def expected_timeline(scenario: str, effect_class: str) -> list[str]:
    """Returns the exact recovery classification for one matrix effect class."""

    if (
        scenario == "interrupt-after-durable-intent"
        and effect_class == "observation"
    ):
        return [
            "operation-admitted",
            "effect-started",
            "operation-admitted",
            "reconciliation-started",
            "reconciled-completed",
        ]
    return SCENARIO_TIMELINES[scenario]


def canonical(value: Any) -> bytes:
    """Encodes one value with the release evidence canonical JSON profile."""

    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def sha256_bytes(value: bytes) -> str:
    """Returns the ordinary SHA-256 identity of exact retained bytes."""

    return "sha256:" + hashlib.sha256(value).hexdigest()


def _scenario(cell_id: str) -> str:
    scenario = cell_id.rsplit("/", 1)[-1]
    if scenario not in SCENARIO_BOUNDARIES:
        raise RuntimeError(f"unsupported effect-boundary scenario {scenario!r}")
    return scenario


def _operation_identity(operation: dict[str, Any], ordinal: int) -> dict[str, Any]:
    return {
        "key": operation["key"],
        "ordinal": ordinal,
        "interface": operation["interface"],
        "method": operation["method"],
        "target": operation["target"],
    }


@dataclass(frozen=True)
class EffectBoundaryObservation:
    """Carries independently collected facts for one interrupted operation."""

    transaction: str
    operation_key: dict[str, Any]
    journal_before_loss: str
    timeline: list[dict[str, Any]]
    boundary_timeline: list[dict[str, Any]]
    interruption_position: int
    settlement_sequence: int
    settlement_position: int
    owner_baseline: Any
    owner_unsettled: Any
    owner_after: Any
    live_baseline: Any
    live_unsettled: Any
    live_after: Any
    foreign_baseline: Any
    foreign_unsettled: Any
    foreign_after: Any
    dependent_operation: dict[str, Any]
    dependent_before: list[dict[str, Any]]
    dependent_after: list[dict[str, Any]]
    dependent_boundary_after: list[dict[str, Any]]


class EffectBoundaryEvidence:
    """Collects nonreplayable cell evidence for one production VM cohort."""

    def __init__(self, matrix_spec: dict[str, Any], qualified_cells: list[str]):
        cells = {cell["id"]: cell for cell in matrix_spec["cells"]}
        if len(cells) != len(matrix_spec["cells"]):
            raise RuntimeError("native-adapter matrix repeats a cell identity")
        if len(set(qualified_cells)) != len(qualified_cells):
            raise RuntimeError("effect-boundary cohort repeats a cell identity")
        if any(cell_id not in cells for cell_id in qualified_cells):
            raise RuntimeError("effect-boundary cohort names a foreign matrix cell")

        self._cells = cells
        self._qualified = set(qualified_cells)
        self.subjects: dict[str, Any] = {}
        self.plan_bundles: dict[str, bytes] = {}
        self.probes: dict[str, Any] = {}

    def retain(
        self,
        cell_id: str,
        plan_bundle: bytes,
        observation: EffectBoundaryObservation,
    ) -> None:
        """Binds a production transaction and physical observations to a cell."""

        if cell_id not in self._qualified or cell_id in self.probes:
            raise RuntimeError(f"unexpected or repeated effect-boundary cell {cell_id}")
        cell = self._cells[cell_id]
        scenario = _scenario(cell_id)
        bundle = json.loads(plan_bundle)
        if canonical(bundle) != plan_bundle:
            raise RuntimeError("effect-boundary plan bundle is not canonical")

        matches = [
            (ordinal, operation)
            for ordinal, operation in enumerate(
                bundle["transition"]["effect_document"]["operations"]
            )
            if operation["interface"] == cell["interface"]
            and operation["method"] == cell["method"]
            and operation["key"] == observation.operation_key
        ]
        if len(matches) != 1:
            raise RuntimeError("plan does not contain one exact matrix operation")
        ordinal, operation = matches[0]
        operation_identity = _operation_identity(operation, ordinal)
        if operation["target"]["interface"] != cell["interface"]:
            raise RuntimeError("matrix operation targets another interface")
        if not any(
            event.get("boundary") == SCENARIO_BOUNDARIES[scenario]
            and event.get("purpose") == "effect"
            for event in observation.boundary_timeline
        ):
            raise RuntimeError("boundary transcript lacks the selected interruption")
        if [event.get("kind") for event in observation.timeline] != expected_timeline(
            scenario, cell["effect_class"]
        ):
            raise RuntimeError("durable journal has another recovery classification")
        ownership_inventories = (
            observation.owner_baseline,
            observation.owner_unsettled,
            observation.owner_after,
        )
        if not all(_single_owner_inventory(value) for value in ownership_inventories):
            raise RuntimeError("native resource inventory admits duplicate ownership")
        resource = operation["target"]["resource"]
        if any(
            owner.get("resource") != resource
            for inventory in ownership_inventories
            for owner in inventory["identities"]
        ):
            raise RuntimeError("native resource inventory names another owner resource")
        if not (
            observation.foreign_baseline
            == observation.foreign_unsettled
            == observation.foreign_after
        ):
            raise RuntimeError("foreign resource changed across recovery")
        if observation.dependent_before:
            raise RuntimeError("a required successor ran before recovery settlement")

        effect_document = bundle["transition"]["effect_document"]
        dependents = _required_success_dependents(effect_document, operation_identity)
        if observation.dependent_operation not in dependents:
            raise RuntimeError("observed successor is not a real required-success dependent")
        if not observation.dependent_after:
            raise RuntimeError("required-success successor did not execute after settlement")
        if observation.dependent_after[0].get("sequence", -1) <= observation.settlement_sequence:
            raise RuntimeError("required-success successor ran before predecessor settlement")
        if not observation.dependent_boundary_after:
            raise RuntimeError("required-success successor has no production boundary transcript")
        if (
            observation.dependent_boundary_after[0].get("transcript-position", -1)
            <= observation.settlement_position
        ):
            raise RuntimeError("required-success boundary preceded predecessor settlement")

        subject = {
            "schema": SUBJECT_SCHEMA,
            "plan": bundle["plan"],
            "plan-bundle-digest": sha256_bytes(plan_bundle),
            "adapter": cell["adapter"],
            "operation": operation_identity,
            "dependent-operation": observation.dependent_operation,
            "dependency-edge": {
                "from": {"kind": "operation", "key": operation_identity["key"]},
                "to": {
                    "kind": "operation",
                    "key": observation.dependent_operation["key"],
                },
                "kind": "required-success",
            },
            "provider-implementation": _provider_implementation(bundle, operation),
        }
        disposition = SCENARIO_DISPOSITIONS[scenario]
        live_digest_baseline = sha256_bytes(canonical(observation.live_baseline))
        live_digest_unsettled = sha256_bytes(canonical(observation.live_unsettled))
        live_digest_after = sha256_bytes(canonical(observation.live_after))
        external_effect_returned = scenario in {
            "lose-external-result",
            "interrupt-after-durable-outcome",
        }
        mutation_observed = live_digest_baseline != live_digest_unsettled
        if cell["effect_class"] == "mutation" and (
            mutation_observed != external_effect_returned
        ):
            raise RuntimeError(
                "live provider state differs from the selected interruption boundary"
            )
        self.subjects[cell_id] = subject
        self.plan_bundles[cell_id] = plan_bundle
        self.probes[cell_id] = {
            "durable-attempt-state-classified": {
                "kind": "journal-timeline",
                "disposition": disposition,
                "detail": (
                    "The candidate runtime retained the selected production boundary "
                    "and recovered the exact operation from its durable plan."
                ),
                "observations": {
                    "transaction": observation.transaction,
                    "plan": bundle["plan"],
                    "operation": operation_identity,
                    "provider-implementation": subject["provider-implementation"],
                    "journal-before-loss": observation.journal_before_loss,
                    "timeline": observation.timeline,
                    "boundary-timeline": observation.boundary_timeline,
                    "interruption-position": observation.interruption_position,
                    "settlement-sequence": observation.settlement_sequence,
                    "settlement-position": observation.settlement_position,
                },
            },
            "at-most-one-resource-owner": {
                "kind": "ownership-inventory",
                "disposition": disposition,
                "detail": (
                    "The production resource inventory retained one exact owner "
                    "before interruption and after reconciliation."
                ),
                "observations": {
                    "resource": operation["target"]["resource"],
                    "owner-baseline": observation.owner_baseline,
                    "owner-unsettled": observation.owner_unsettled,
                    "owner-after": observation.owner_after,
                    "one-owner-throughout": True,
                    "live-observation-baseline": observation.live_baseline,
                    "live-observation-unsettled": observation.live_unsettled,
                    "live-observation-after": observation.live_after,
                    "live-digest-baseline": live_digest_baseline,
                    "live-digest-unsettled": live_digest_unsettled,
                    "live-digest-after": live_digest_after,
                    "external-effect-returned": external_effect_returned,
                    "mutation-observed-before-loss": mutation_observed,
                },
            },
            "foreign-resources-unchanged": {
                "kind": "foreign-resource-snapshot",
                "disposition": disposition,
                "detail": (
                    "An independently observed live resource retained identical "
                    "provider state across interruption and recovery."
                ),
                "observations": {
                    "resource": operation["target"]["resource"],
                    "snapshot-baseline": observation.foreign_baseline,
                    "snapshot-unsettled": observation.foreign_unsettled,
                    "snapshot-after": observation.foreign_after,
                    "unchanged": True,
                },
            },
            "dependent-effects-not-executed": {
                "kind": "dependency-barrier",
                "disposition": disposition,
                "detail": (
                    "The required-success successor had no durable event before "
                    "the interrupted production operation settled."
                ),
                "observations": {
                    "operation": operation_identity,
                    "dependent-operation": observation.dependent_operation,
                    "dependency-edge": subject["dependency-edge"],
                    "timeline-before-settlement": observation.dependent_before,
                    "timeline-after-settlement": observation.dependent_after,
                    "boundary-timeline-after-settlement": (
                        observation.dependent_boundary_after
                    ),
                    "blocked": True,
                    "settlement-sequence": observation.settlement_sequence,
                    "settlement-position": observation.settlement_position,
                },
            },
        }

    def finish(self) -> tuple[dict[str, Any], dict[str, bytes], dict[str, Any]]:
        """Returns exact output maps after proving complete cohort coverage."""

        observed = set(self.probes)
        if observed != self._qualified:
            missing = sorted(self._qualified - observed)
            unexpected = sorted(observed - self._qualified)
            raise RuntimeError(
                f"effect-boundary evidence is incomplete: missing={missing}, "
                f"unexpected={unexpected}"
            )
        return self.subjects, self.plan_bundles, self.probes


def _provider_implementation(
    bundle: dict[str, Any], operation: dict[str, Any]
) -> dict[str, Any]:
    binding_id = operation["binding"]
    bindings = []
    for state in (bundle.get("desired"), bundle.get("current")):
        if state is not None:
            bindings.extend(
                state["snapshot"]["resolution"]["binding_document"]["bindings"]
            )
    matches = [binding for binding in bindings if binding["id"] == binding_id]
    implementations = {
        canonical(binding["implementation"]): binding["implementation"]
        for binding in matches
    }
    if len(implementations) != 1:
        raise RuntimeError("matrix operation binding is absent or ambiguous")
    implementation = next(iter(implementations.values()))
    if not implementation.get("handler"):
        raise RuntimeError("matrix operation did not select a terminal provider")
    return implementation


def _required_success_dependents(
    effect_document: dict[str, Any], operation: dict[str, Any]
) -> list[dict[str, Any]]:
    """Projects real RequiredSuccess successors from the retained effect graph."""

    target_keys = [
        edge["to"]["key"]
        for edge in effect_document["edges"]
        if edge.get("from") == {"kind": "operation", "key": operation["key"]}
        and edge.get("kind") == "required-success"
        and edge.get("to", {}).get("kind") == "operation"
    ]
    return [
        _operation_identity(candidate, ordinal)
        for ordinal, candidate in enumerate(effect_document["operations"])
        if candidate["key"] in target_keys
    ]


def _single_owner_inventory(inventory: Any) -> bool:
    """Accepts an empty or single exact row from the native ownership ledger."""

    if not isinstance(inventory, dict):
        return False
    if set(inventory) != {"count", "identities"}:
        return False
    if inventory["count"] not in {0, 1}:
        return False
    if (
        not isinstance(inventory["identities"], list)
        or len(inventory["identities"]) != inventory["count"]
        or any(not isinstance(identity, dict) for identity in inventory["identities"])
    ):
        return False
    return True
