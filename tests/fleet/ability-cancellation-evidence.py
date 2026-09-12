"""Builds matrix evidence from production native-adapter cancellation flights.

Each flight sends SIGTERM to an authenticated transient switch after its
selected operation has durable intent. Provider state comes from the separate
physical-resource oracles; this module binds those facts to the checked route,
plan bundle, and durable cancellation journal.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


SUBJECT_SCHEMA = "aos.qualification.native-adapter-cancellation-subject/v1"
EVIDENCE_SCHEMA = "aos.qualification.native-adapter-cancellation-flight/v1"
CANCELLATION_SCENARIO = "cancel-unsettled-attempt"
CANCELLATION_BOUNDARIES = [
    ("effect", "resources-acquired"),
    ("effect", "effect-intent-durable"),
    ("cancel", "cancellation-intent-durable"),
    ("cancel", "final-dispatch"),
    ("cancel", "cancellation-returned"),
    ("cancel", "cancellation-outcome-durable"),
]
CANCELLATION_RESULTS = {
    "cancellation-rejected-before-effect",
    "cancellation-observed-completion",
    "cancellation-indeterminate",
}
HANDLER_ROUTES = {
    "aos.credential-delivery-effects": (
        "native-credential-delivery-v1",
        "libexec/aos-credential-delivery-handler-v1",
    ),
    "aos.foreground-process": (
        "native-foreground-process-v1",
        "libexec/aos-foreground-process-handler-v1",
    ),
    "aos.host-network-policy-effects": (
        "native-host-network-policy-v1",
        "libexec/aos-host-network-policy-handler-v1",
    ),
    "aos.host-storage-effects": (
        "native-host-storage-v1",
        "libexec/aos-host-storage-handler-v1",
    ),
    "aos.managed-configuration-effects": (
        "managed-configuration-terminal",
        "bin/.aos-package-runtime-unwrapped",
    ),
    "aos.network-endpoint-effects": (
        "native-network-endpoint-v1",
        "libexec/aos-network-endpoint-handler-v1",
    ),
    "aos.nginx-validation": ("nginx-terminal", "bin/nginx"),
}


def canonical(value: Any) -> bytes:
    """Encodes one value with the release evidence canonical JSON profile."""

    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


@dataclass(frozen=True)
class CancellationObservation:
    """Carries independently collected facts for one cancelled operation."""

    transaction: str
    switch_process: int
    operation_key: dict[str, Any]
    journal_before_signal: str
    timeline: list[dict[str, Any]]
    boundary_timeline: list[dict[str, Any]]
    owner_before: Any
    owner_unsettled: Any
    owner_after: Any
    live_before: Any
    live_unsettled: Any
    live_after: Any
    foreign_before: Any
    foreign_unsettled: Any
    foreign_after: Any
    dependent_operation: dict[str, Any]
    dependent_before: list[dict[str, Any]]
    dependent_after: list[dict[str, Any]]
    dependent_boundaries: list[dict[str, Any]]


class CancellationEvidence:
    """Collects exact production evidence for supported cancellation cells."""

    def __init__(self, matrix_spec: dict[str, Any], qualified_cells: list[str]):
        cells = {cell["id"]: cell for cell in matrix_spec["cells"]}
        if len(cells) != len(matrix_spec["cells"]):
            raise RuntimeError("native-adapter matrix repeats a cell identity")
        if len(set(qualified_cells)) != len(qualified_cells):
            raise RuntimeError("cancellation cohort repeats a cell identity")
        if any(cell_id not in cells for cell_id in qualified_cells):
            raise RuntimeError("cancellation cohort names a foreign matrix cell")
        if any(
            cell_id.rsplit("/", 1)[-1] != CANCELLATION_SCENARIO
            for cell_id in qualified_cells
        ):
            raise RuntimeError("cancellation cohort names another matrix scenario")

        self._cells = cells
        self._qualified = set(qualified_cells)
        self._matrix_spec_digest = EFFECT_EVIDENCE.sha256_bytes(
            canonical(matrix_spec)
        )
        self.subjects: dict[str, Any] = {}
        self.plan_bundles: dict[str, bytes] = {}
        self.probes: dict[str, Any] = {}

    def retain(
        self,
        cell_id: str,
        plan_bundle: bytes,
        source_authority: dict[str, Any],
        candidate_authority: dict[str, Any],
        observation: CancellationObservation,
    ) -> None:
        """Binds one durable cancellation and physical observations to a cell."""

        if cell_id not in self._qualified or cell_id in self.probes:
            raise RuntimeError(f"unexpected or repeated cancellation cell {cell_id}")
        cell = self._cells[cell_id]
        if cell["recovery"]["cancel"] is None:
            raise RuntimeError("supported cancellation cell has no checked route")

        bundle = json.loads(plan_bundle)
        if canonical(bundle) != plan_bundle:
            raise RuntimeError("cancellation plan bundle is not canonical")
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
            raise RuntimeError("plan does not contain one exact cancellation operation")
        ordinal, operation = matches[0]
        operation_identity = EFFECT_EVIDENCE._operation_identity(operation, ordinal)
        if operation["recovery"]["cancel"] != {
            "interface": cell["interface"],
            "method": cell["recovery"]["cancel"],
        }:
            raise RuntimeError("operation carries another checked cancellation route")

        kinds = [event["kind"] for event in observation.timeline]
        if kinds[:3] != [
            "operation-admitted",
            "effect-started",
            "cancellation-started",
        ]:
            raise RuntimeError(f"cancellation journal has another prefix: {kinds!r}")
        results = [kind for kind in kinds if kind in CANCELLATION_RESULTS]
        if len(results) != 1 or kinds[-1] != results[0]:
            raise RuntimeError(f"cancellation journal has no exact outcome: {kinds!r}")
        boundaries = [
            (event["purpose"], event["boundary"])
            for event in observation.boundary_timeline
        ]
        if boundaries != CANCELLATION_BOUNDARIES:
            raise RuntimeError(f"cancellation boundaries differ: {boundaries!r}")
        if observation.switch_process <= 0:
            raise RuntimeError("cancellation did not retain the transient switch PID")

        ownership = (
            observation.owner_before,
            observation.owner_unsettled,
            observation.owner_after,
        )
        if not all(EFFECT_EVIDENCE._single_owner_inventory(value) for value in ownership):
            raise RuntimeError("cancelled resource admits duplicate or absent ownership")
        resource = operation["target"]["resource"]
        if any(
            owner.get("resource") != resource
            for inventory in ownership
            for owner in inventory["identities"]
        ):
            raise RuntimeError("cancellation ownership names another resource")
        if not (
            observation.foreign_before
            == observation.foreign_unsettled
            == observation.foreign_after
        ):
            raise RuntimeError("foreign sentinel changed during cancellation")
        if (
            observation.dependent_before
            or observation.dependent_after
            or observation.dependent_boundaries
        ):
            raise RuntimeError("dependent effect ran after cancellation")

        provider_implementation = EFFECT_EVIDENCE._provider_implementation(
            bundle, operation
        )
        expected_handler, handler_entry_point = HANDLER_ROUTES[cell["interface"]["name"]]
        if provider_implementation["handler"] != expected_handler:
            raise RuntimeError("cancellation selected another terminal handler")
        native_route = EFFECT_EVIDENCE._native_route(
            bundle,
            operation,
            provider_implementation,
            source_authority,
            candidate_authority,
        )
        evidence = {
            "schema": EVIDENCE_SCHEMA,
            "matrix-spec-digest": self._matrix_spec_digest,
            "cell-digest": EFFECT_EVIDENCE.sha256_bytes(canonical(cell)),
            "plan-bundle": bundle,
            "source-authority": source_authority,
            "candidate-authority": candidate_authority,
        }
        evidence_bytes = canonical(evidence)
        subject = {
            "schema": SUBJECT_SCHEMA,
            "matrix-spec-digest": self._matrix_spec_digest,
            "cell-digest": EFFECT_EVIDENCE.sha256_bytes(canonical(cell)),
            "plan": bundle["plan"],
            "plan-bundle-digest": EFFECT_EVIDENCE.sha256_bytes(plan_bundle),
            "evidence-digest": EFFECT_EVIDENCE.sha256_bytes(evidence_bytes),
            "adapter": cell["adapter"],
            "operation": operation_identity,
            "cancel-route": operation["recovery"]["cancel"],
            "dependent-operation": observation.dependent_operation,
            "provider-implementation": provider_implementation,
            "handler-entry-point": handler_entry_point,
            "native-route": native_route,
        }
        disposition = "cancelled-after-reconciliation"
        self.subjects[cell_id] = subject
        self.plan_bundles[cell_id] = evidence_bytes
        self.probes[cell_id] = {
            "durable-attempt-state-classified": {
                "kind": "journal-timeline",
                "disposition": disposition,
                "detail": (
                    "SIGTERM selected the checked cancellation route after durable "
                    "effect intent and the journal retained its exact outcome."
                ),
                "observations": {
                    "cell": cell_id,
                    "postcondition": "durable-attempt-state-classified",
                    "transaction": observation.transaction,
                    "operation": operation_identity,
                    "switch-process": observation.switch_process,
                    "journal-before-signal": observation.journal_before_signal,
                    "timeline": observation.timeline,
                    "boundary-timeline": observation.boundary_timeline,
                    "cancellation-result": results[0],
                    "live-before": observation.live_before,
                    "live-unsettled": observation.live_unsettled,
                    "live-after": observation.live_after,
                },
            },
            "at-most-one-resource-owner": {
                "kind": "ownership-inventory",
                "disposition": disposition,
                "detail": (
                    "The authoritative native ledger retained exactly one checked "
                    "owner before, during, and after cancellation."
                ),
                "observations": {
                    "cell": cell_id,
                    "postcondition": "at-most-one-resource-owner",
                    "resource": resource,
                    "owner-before": observation.owner_before,
                    "owner-unsettled": observation.owner_unsettled,
                    "owner-after": observation.owner_after,
                },
            },
            "foreign-resources-unchanged": {
                "kind": "foreign-resource-snapshot",
                "disposition": disposition,
                "detail": (
                    "A separately owned provider resource retained exact physical "
                    "state throughout cancellation."
                ),
                "observations": {
                    "cell": cell_id,
                    "postcondition": "foreign-resources-unchanged",
                    "foreign-before": observation.foreign_before,
                    "foreign-unsettled": observation.foreign_unsettled,
                    "foreign-after": observation.foreign_after,
                },
            },
            "dependent-effects-not-executed": {
                "kind": "dependency-barrier",
                "disposition": disposition,
                "detail": (
                    "The checked required-success successor retained no journal or "
                    "provider boundary after its predecessor was cancelled."
                ),
                "observations": {
                    "cell": cell_id,
                    "postcondition": "dependent-effects-not-executed",
                    "predecessor-operation": operation_identity,
                    "dependent-operation": observation.dependent_operation,
                    "dependent-timeline-before": observation.dependent_before,
                    "dependent-timeline-after": observation.dependent_after,
                    "dependent-boundaries": observation.dependent_boundaries,
                    "dependent-effect-count": 0,
                },
            },
        }

    def finish(self) -> tuple[dict[str, Any], dict[str, bytes], dict[str, Any]]:
        """Returns complete cohort maps after checking exact cell coverage."""

        if set(self.probes) != self._qualified:
            missing = sorted(self._qualified - set(self.probes))
            extra = sorted(set(self.probes) - self._qualified)
            raise RuntimeError(
                f"cancellation cohort coverage differs: missing={missing!r}, extra={extra!r}"
            )
        if set(self.subjects) != self._qualified:
            raise RuntimeError("cancellation cohort subject coverage differs")
        if set(self.plan_bundles) != self._qualified:
            raise RuntimeError("cancellation cohort evidence coverage differs")
        return self.subjects, self.plan_bundles, self.probes
