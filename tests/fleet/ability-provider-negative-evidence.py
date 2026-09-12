"""Binds provider-specific negative flights to exact native matrix cells.

The fleet fixture owns the live resource, candidate package-runtime execution,
and boundary injection. This helper accepts only the resulting retained facts.
It emits one foreign-resource cell for the rejected operation and one
required-success cell for the blocked operation on a separate live resource.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


AUDIT_SCHEMA = "aos.qualification.native-adapter-provider-negative-audit/v1"
SUBJECT_SCHEMA = "aos.qualification.native-adapter-provider-negative-subject/v1"
PLAN_SCHEMA = "aos.qualification.native-adapter-provider-negative-plan/v1"
FOREIGN_SCENARIO = "reject-foreign-resource-mutation"
DEPENDENCY_SCENARIO = "block-dependent-effect"
EXCLUDED_CELLS = {
    (
        "managed-configuration/aos.managed-configuration-effects/abi-1/"
        "publish/reject-foreign-resource-mutation"
    ),
    (
        "systemd-service-legacy/aos.systemd-service-effects/abi-1/"
        "reload/block-dependent-effect"
    ),
}
ORACLE_KINDS = {
    "credential-delivery": "credential-view",
    "foreground-process": "foreground-process",
    "host-network-policy": "nft-policy",
    "host-storage": "storage-tree",
    "image-rollout": "boot-slot",
    "kubernetes-object": "kubernetes-object",
    "managed-configuration": "managed-file",
    "network-endpoint": "loopback-listener",
    "nginx-validation": "nginx-association",
    "postgresql": "postgresql-cluster",
    "systemd-bootstrap": "systemd-unit",
    "systemd-manager": "systemd-unit",
    "systemd-service-legacy": "systemd-unit",
}
ENTRY_POINTS = {
    "credential-delivery": "libexec/aos-credential-delivery-handler-v1",
    "foreground-process": "libexec/aos-foreground-process-handler-v1",
    "host-network-policy": "libexec/aos-host-network-policy-handler-v1",
    "host-storage": "libexec/aos-host-storage-handler-v1",
    "image-rollout": "libexec/aos-ab-image-rollout-handler-v1",
    "kubernetes-object": "libexec/aos-kubernetes-object-handler-v1",
    "managed-configuration": "bin/.aos-package-runtime-unwrapped",
    "network-endpoint": "libexec/aos-network-endpoint-handler-v1",
    "nginx-validation": "bin/nginx",
    "postgresql": "libexec/aos-postgresql-handler-v1",
    "systemd-bootstrap": "bin/.aos-package-runtime-unwrapped",
    "systemd-manager": "libexec/aos-systemd-manager-handler-v1",
    "systemd-service-legacy": "bin/.aos-package-runtime-unwrapped",
}


def canonical(value: Any) -> bytes:
    """Encodes one value with the release canonical JSON profile."""

    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def digest(value: Any) -> str:
    """Returns the canonical SHA-256 identity for a JSON value."""

    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def digest_bytes(value: bytes) -> str:
    """Returns the ordinary SHA-256 identity for exact bytes."""

    return "sha256:" + hashlib.sha256(value).hexdigest()


def operation_identity(operation: dict[str, Any], ordinal: int) -> dict[str, Any]:
    """Retains the operation fields needed to bind a matrix cell."""

    return {
        "key": operation["key"],
        "ordinal": ordinal,
        "interface": operation["interface"],
        "method": operation["method"],
        "resource": operation["target"]["resource"],
    }


@dataclass(frozen=True)
class LiveOracle:
    """Carries an independently collected provider resource snapshot."""

    resource: dict[str, Any]
    before: Any
    after: Any
    live: bool


@dataclass(frozen=True)
class PairedFlightObservation:
    """Carries facts from one rejected production operation and its successor."""

    transaction: str
    flight: str
    boundary: str
    journal_digest: str
    failure_record: str
    foreign_timeline: list[dict[str, Any]]
    dependent_timeline: list[dict[str, Any]]
    witness_timeline: list[dict[str, Any]]
    foreign_owner_count_before: int
    foreign_owner_count_after: int
    candidate_owner_count: int
    maximum_owner_count: int
    foreign: LiveOracle
    successor: LiveOracle
    witness: LiveOracle | None = None
    sentinel: LiveOracle | None = None


@dataclass(frozen=True)
class RolloutDependencyObservation:
    """Carries one same-machine dependency rejection and its foreign sentinel."""

    transaction: str
    flight: str
    journal_digest: str
    failure_record: str
    predecessor_timeline: list[dict[str, Any]]
    dependent_timeline: list[dict[str, Any]]
    witness_timeline: list[dict[str, Any]]
    machine: LiveOracle
    sentinel: LiveOracle


class ProviderNegativeEvidence:
    """Collects exact paired-flight evidence for one provider fixture."""

    def __init__(self, matrix_spec: dict[str, Any], qualified_cells: list[str]):
        cells = {cell["id"]: cell for cell in matrix_spec["cells"]}
        if len(cells) != len(matrix_spec["cells"]):
            raise RuntimeError("native-adapter matrix repeats a cell identity")
        if len(set(qualified_cells)) != len(qualified_cells):
            raise RuntimeError("provider-negative cohort repeats a cell identity")
        if any(cell_id not in cells for cell_id in qualified_cells):
            raise RuntimeError("provider-negative cohort names a foreign matrix cell")
        if any(
            cell_id.rsplit("/", 1)[-1]
            not in {FOREIGN_SCENARIO, DEPENDENCY_SCENARIO}
            or cell_id in EXCLUDED_CELLS
            for cell_id in qualified_cells
        ):
            raise RuntimeError("provider-negative cohort exceeds its closed scenario scope")

        self._matrix_spec = matrix_spec
        self._cells = cells
        self._qualified = set(qualified_cells)
        self._records: dict[str, Any] = {}

    def retain(
        self,
        adapter: str,
        method: str,
        plan_bundle: bytes,
        observation: PairedFlightObservation,
    ) -> None:
        """Binds one real rejected operation and blocked successor to two cells."""

        oracle_kind = ORACLE_KINDS.get(adapter)
        if oracle_kind is None:
            raise RuntimeError(f"unknown provider oracle for adapter {adapter!r}")
        bundle = json.loads(plan_bundle)
        if canonical(bundle) != plan_bundle:
            raise RuntimeError("provider-negative plan bundle is not canonical")
        operations = bundle["transition"]["effect_document"]["operations"]
        matches = [
            (ordinal, operation)
            for ordinal, operation in enumerate(operations)
            if operation["interface"] == self._interface(adapter, method)
            and operation["method"] == method
        ]
        foreign_matches = [
            pair
            for pair in matches
            if pair[1]["target"]["resource"] == observation.foreign.resource
        ]
        if len(foreign_matches) != 1:
            raise RuntimeError("provider observation does not select one exact operation")
        foreign_ordinal, foreign = foreign_matches[0]
        outgoing = sorted(
            [
                edge
                for edge in bundle["transition"]["effect_document"]["edges"]
                if edge["from"] == {"kind": "operation", "key": foreign["key"]}
                and edge["kind"] == "required-success"
                and edge["to"]["kind"] == "operation"
            ],
            key=lambda edge: canonical(edge["to"]["key"]),
        )
        if not outgoing:
            raise RuntimeError("provider operation lacks a real RequiredSuccess successor")
        expected_edge = outgoing[0]
        dependent_matches = [
            (ordinal, operation)
            for ordinal, operation in enumerate(operations)
            if operation["key"] == expected_edge["to"]["key"]
        ]
        if len(dependent_matches) != 1:
            raise RuntimeError("RequiredSuccess edge does not select one exact operation")
        dependent_ordinal, dependent = dependent_matches[0]
        foreign_identity = operation_identity(foreign, foreign_ordinal)
        dependent_identity = operation_identity(dependent, dependent_ordinal)
        witness = self._behavioral_witness(bundle, foreign, dependent)
        if observation.foreign.resource != foreign_identity["resource"]:
            raise RuntimeError("foreign oracle observes another logical resource")
        if observation.successor.resource != dependent_identity["resource"]:
            raise RuntimeError("successor oracle observes another logical resource")
        if observation.boundary != "after-durable-intent-before-external-effect":
            raise RuntimeError("foreign authority changed at another boundary")
        if (
            observation.foreign_timeline == []
            or observation.dependent_timeline != []
            or observation.witness_timeline != []
        ):
            raise RuntimeError("paired flight did not reject before its dependent")
        if (
            observation.foreign.before != observation.foreign.after
            or observation.successor.before != observation.successor.after
            or not observation.foreign.live
        ):
            raise RuntimeError("provider live state changed during the rejected flight")
        if witness is None:
            if observation.witness is not None:
                raise RuntimeError("mutation flight unexpectedly carries a behavioral witness")
        elif (
            observation.witness is None
            or observation.witness.resource != witness["resource"]
            or observation.witness.before != observation.witness.after
        ):
            raise RuntimeError("observation flight lacks an unchanged live mutation witness")
        if (
            observation.foreign_owner_count_before,
            observation.foreign_owner_count_after,
            observation.candidate_owner_count,
            observation.maximum_owner_count,
        ) != (1, 1, 0, 1):
            raise RuntimeError("paired flight did not retain one foreign owner")

        provider_route = self._provider_route(bundle, foreign, adapter, method)
        plan = {
            "schema": PLAN_SCHEMA,
            "digest": digest_bytes(plan_bundle),
            "plan": bundle["plan"],
            "foreign-operation": foreign_identity,
            "dependent-operation": dependent_identity,
            "required-success": {
                "from": foreign_identity,
                "to": dependent_identity,
                "kind": "required-success",
            },
            "behavioral-witness": witness,
        }
        evidence = {
            "provider-route": provider_route,
            "boundary": observation.boundary,
            "journal": {
                "digest": observation.journal_digest,
                "failure-record": observation.failure_record,
                "foreign-operation": foreign_identity,
                "foreign-timeline": observation.foreign_timeline,
                "dependent-operation": dependent_identity,
                "dependent-timeline": observation.dependent_timeline,
                "behavioral-witness": witness,
                "witness-timeline": observation.witness_timeline,
                "classified": "foreign-authority-rejected",
            },
            "ownership": {
                "foreign-owner-count-before": observation.foreign_owner_count_before,
                "foreign-owner-count-after": observation.foreign_owner_count_after,
                "candidate-owner-count": observation.candidate_owner_count,
                "maximum-owner-count": observation.maximum_owner_count,
            },
            "foreign-resource": self._oracle(oracle_kind, observation.foreign),
            "blocked-successor": self._oracle(
                ORACLE_KINDS[self._adapter_for_operation(dependent_identity)],
                observation.successor,
            ),
            "blocked-witness": (
                None
                if observation.witness is None
                else self._oracle(
                    ORACLE_KINDS[self._adapter_for_operation(witness)],
                    observation.witness,
                )
            ),
            "provider-sentinel": (
                None
                if observation.sentinel is None
                else self._oracle(oracle_kind, observation.sentinel)
            ),
        }
        for scenario in [FOREIGN_SCENARIO, DEPENDENCY_SCENARIO]:
            cell_id = self._cell_id(adapter, method, scenario)
            if cell_id in EXCLUDED_CELLS:
                continue
            if cell_id not in self._qualified or cell_id in self._records:
                raise RuntimeError(f"unexpected or repeated provider cell {cell_id}")
            cell = self._cells[cell_id]
            subject = {
                "schema": SUBJECT_SCHEMA,
                "cell-id": cell_id,
                "cell-digest": digest(cell),
                "adapter": adapter,
                "interface": cell["interface"],
                "method": method,
                "scenario": scenario,
                "plan": bundle["plan"],
                "transaction": observation.transaction,
                "flight": observation.flight,
            }
            self._records[cell_id] = {
                "cell_digest": digest(cell),
                "subject": subject,
                "plan_bundle": plan,
                "evidence": evidence,
            }

    def finish(self) -> dict[str, Any]:
        """Returns the closed audit only after every declared cell was observed."""

        if set(self._records) != self._qualified:
            missing = sorted(self._qualified - set(self._records))
            unexpected = sorted(set(self._records) - self._qualified)
            raise RuntimeError(
                f"provider-negative evidence is incomplete: missing={missing}, "
                f"unexpected={unexpected}"
            )
        return {
            "schema": AUDIT_SCHEMA,
            "matrix_spec_digest": digest(self._matrix_spec),
            "cells": self._records,
        }

    def retain_rollout_dependency(
        self,
        method: str,
        plan_bundle: bytes,
        observation: RolloutDependencyObservation,
    ) -> None:
        """Retains a real same-machine successor blocked by a fresh slot fence."""

        bundle = json.loads(plan_bundle)
        if canonical(bundle) != plan_bundle:
            raise RuntimeError("rollout dependency plan bundle is not canonical")
        effect = bundle["transition"]["effect_document"]
        predecessor_ordinals = {
            event["node-ordinal"] for event in observation.predecessor_timeline
        }
        if len(predecessor_ordinals) != 1:
            raise RuntimeError("rollout dependency timeline lacks one predecessor")
        predecessor_ordinal = next(iter(predecessor_ordinals))
        predecessor = effect["operations"][predecessor_ordinal]
        dependency_edges = sorted(
            [
            edge
            for edge in effect["edges"]
            if edge["kind"] == "required-success"
            and edge["from"]["kind"] == "operation"
            and edge["to"]["kind"] == "operation"
            and edge["from"]["key"] == predecessor["key"]
            ],
            key=lambda edge: canonical(edge["to"]["key"]),
        )
        if not dependency_edges:
            raise RuntimeError("rollout plan lacks a real selected dependency edge")
        edge = dependency_edges[0]
        indexed = {
            canonical(operation["key"]): (ordinal, operation)
            for ordinal, operation in enumerate(effect["operations"])
        }
        dependent_ordinal, dependent = indexed[canonical(edge["to"]["key"])]
        if (
            predecessor["interface"] != self._interface("image-rollout", method)
            or predecessor["method"] != method
            or dependent["target"]["resource"] != predecessor["target"]["resource"]
        ):
            raise RuntimeError("rollout dependency does not bind the selected method and machine")
        predecessor_identity = operation_identity(predecessor, predecessor_ordinal)
        dependent_identity = operation_identity(dependent, dependent_ordinal)
        witness = self._behavioral_witness(bundle, predecessor, dependent)
        if observation.machine.resource != predecessor_identity["resource"]:
            raise RuntimeError("rollout dependency observed another machine resource")
        if (
            observation.predecessor_timeline == []
            or observation.dependent_timeline != []
            or observation.witness_timeline != []
            or observation.machine.before != observation.machine.after
            or observation.sentinel.before != observation.sentinel.after
            or not observation.machine.live
            or not observation.sentinel.live
        ):
            raise RuntimeError("rollout dependency did not block before downstream effects")
        if witness is not None and witness["resource"] != dependent_identity["resource"]:
            raise RuntimeError("rollout dependency witness names another machine resource")

        plan = {
            "schema": PLAN_SCHEMA,
            "digest": digest_bytes(plan_bundle),
            "plan": bundle["plan"],
            "foreign-operation": predecessor_identity,
            "dependent-operation": dependent_identity,
            "required-success": {
                "from": predecessor_identity,
                "to": dependent_identity,
                "kind": "required-success",
            },
            "behavioral-witness": witness,
        }
        evidence = {
            "provider-route": self._provider_route(
                bundle, predecessor, "image-rollout", method
            ),
            "boundary": "after-durable-intent-before-external-effect",
            "classification": {
                "kind": "execution-journal",
                "digest": observation.journal_digest,
                "failure-record": observation.failure_record,
                "predecessor-timeline": observation.predecessor_timeline,
                "dependent-timeline": observation.dependent_timeline,
                "witness-timeline": observation.witness_timeline,
                "classified": "boot-slot-authority-rejected",
            },
            "ownership": {
                "machine-owner-count-before": 1,
                "machine-owner-count-after": 1,
                "candidate-owner-count": 0,
                "maximum-owner-count": 1,
            },
            "foreign-resource": self._oracle("systemd-unit", observation.sentinel),
            "blocked-successor": self._oracle("boot-slot", observation.machine),
            "blocked-witness": (
                None
                if witness is None
                else self._oracle("boot-slot", observation.machine)
            ),
        }
        self._retain_rollout_cell(
            method,
            DEPENDENCY_SCENARIO,
            "rollout-dependency",
            bundle["plan"],
            observation.transaction,
            observation.flight,
            plan,
            evidence,
        )

    def retain_rollout_foreign(
        self,
        method: str,
        audit_bytes: bytes,
        sentinel_before: Any,
        sentinel_after: Any,
        sentinel_resource: dict[str, Any],
        machine_before: Any,
        machine_after: Any,
    ) -> None:
        """Retains production one-machine map rejection for a forged resource."""

        audit = json.loads(audit_bytes)
        if canonical(audit) != audit_bytes or audit.get("schema") != (
            "aos.qualification.rollout-foreign-map-audit/v1"
        ):
            raise RuntimeError("rollout foreign-map audit is not canonical and typed")
        if audit.get("method") != method or audit.get("rejection") != {
            "class": "physical-resource-collision",
            "resource": "A/B image rollout host",
            "message-digest": audit.get("rejection", {}).get("message-digest"),
        }:
            raise RuntimeError("rollout foreign-map audit lacks the physical collision")
        if not audit["rejection"]["message-digest"].startswith("sha256:"):
            raise RuntimeError("rollout foreign-map rejection lacks a digest")
        foreign = audit["foreign-operation"] | {"ordinal": 0}
        dependent = audit["dependent-operation"] | {"ordinal": 1}
        witness = audit["behavioral-witness"]
        if witness is not None:
            witness = witness | {"ordinal": 2}
        plan_digest = digest_bytes(audit_bytes)
        plan = {
            "schema": PLAN_SCHEMA,
            "digest": plan_digest,
            "plan": plan_digest,
            "foreign-operation": foreign,
            "dependent-operation": dependent,
            "required-success": {
                "from": foreign,
                "to": dependent,
                "kind": "required-success",
            },
            "behavioral-witness": witness,
        }
        mapping = audit["real-mapping"]
        implementation = mapping["implementation"]
        evidence = {
            "provider-route": {
                "adapter": "image-rollout",
                "interface": foreign["interface"],
                "method": method,
                "candidate-linked": True,
                "artifact": implementation["artifact"]["content"],
                "handler": implementation["handler"],
                "entry-point": ENTRY_POINTS["image-rollout"],
            },
            "boundary": "native-resource-map-validation",
            "classification": {
                "kind": "native-resource-map-validation",
                "digest": plan_digest,
                "attempted-map-digest": audit["attempted-map-digest"],
                "failure-record": audit["rejection"]["message-digest"],
                "classified": "foreign-authority-rejected",
                "dependent-timeline": [],
                "witness-timeline": [],
            },
            "ownership": {
                "machine-owner-count-before": 1,
                "machine-owner-count-after": 1,
                "forged-owner-count": 0,
                "maximum-owner-count": 1,
            },
            "foreign-resource": self._oracle(
                "systemd-unit",
                LiveOracle(
                    resource=sentinel_resource,
                    before=sentinel_before,
                    after=sentinel_after,
                    live=True,
                ),
            ),
            "blocked-successor": self._oracle(
                "boot-slot",
                LiveOracle(
                    resource=dependent["resource"],
                    before=machine_before,
                    after=machine_after,
                    live=True,
                ),
            ),
            "blocked-witness": (
                None
                if witness is None
                else self._oracle(
                    "boot-slot",
                    LiveOracle(
                        resource=witness["resource"],
                        before=machine_before,
                        after=machine_after,
                        live=True,
                    ),
                )
            ),
        }
        self._retain_rollout_cell(
            method,
            FOREIGN_SCENARIO,
            "rollout-map-validation",
            plan_digest,
            "map-validation",
            "rollout-foreign-map-" + method,
            plan,
            evidence,
        )

    def _retain_rollout_cell(
        self,
        method: str,
        scenario: str,
        mode: str,
        plan_digest: str,
        transaction: str,
        flight: str,
        plan: dict[str, Any],
        evidence: dict[str, Any],
    ) -> None:
        cell_id = self._cell_id("image-rollout", method, scenario)
        if cell_id not in self._qualified or cell_id in self._records:
            raise RuntimeError(f"unexpected or repeated rollout cell {cell_id}")
        cell = self._cells[cell_id]
        subject = {
            "schema": SUBJECT_SCHEMA,
            "cell-id": cell_id,
            "cell-digest": digest(cell),
            "adapter": "image-rollout",
            "interface": cell["interface"],
            "method": method,
            "scenario": scenario,
            "plan": plan_digest,
            "transaction": transaction,
            "flight": flight,
        }
        self._records[cell_id] = {
            "mode": mode,
            "cell_digest": digest(cell),
            "subject": subject,
            "plan_bundle": plan,
            "evidence": evidence,
        }

    def _interface(self, adapter: str, method: str) -> dict[str, Any]:
        matches = [
            cell["interface"]
            for cell_id, cell in self._cells.items()
            if cell["adapter"] == adapter
            and cell["method"] == method
            and cell_id.rsplit("/", 1)[-1] in {FOREIGN_SCENARIO, DEPENDENCY_SCENARIO}
        ]
        if not matches or any(interface != matches[0] for interface in matches):
            raise RuntimeError("matrix method does not resolve one exact interface")
        return matches[0]

    def _cell_id(self, adapter: str, method: str, scenario: str) -> str:
        matches = [
            cell_id
            for cell_id, cell in self._cells.items()
            if cell["adapter"] == adapter
            and cell["method"] == method
            and cell_id.endswith("/" + scenario)
        ]
        if len(matches) != 1:
            raise RuntimeError("matrix lacks one exact provider-negative cell")
        return matches[0]

    def _adapter_for_operation(self, operation: dict[str, Any]) -> str:
        matches = {
            cell["adapter"]
            for cell in self._cells.values()
            if cell["interface"] == operation["interface"]
            and cell["method"] == operation["method"]
        }
        if len(matches) != 1:
            raise RuntimeError("behavioral witness does not resolve one native adapter")
        return next(iter(matches))

    def _behavioral_witness(
        self,
        bundle: dict[str, Any],
        selected: dict[str, Any],
        dependent: dict[str, Any],
    ) -> dict[str, Any] | None:
        effect_class = {
            cell["effect_class"]
            for cell in self._cells.values()
            if cell["interface"] == selected["interface"]
            and cell["method"] == selected["method"]
        }
        if effect_class != {"observation"}:
            return None
        dependent_class = {
            cell["effect_class"]
            for cell in self._cells.values()
            if cell["interface"] == dependent["interface"]
            and cell["method"] == dependent["method"]
        }
        if dependent_class == {"mutation"}:
            return operation_identity(
                dependent,
                bundle["transition"]["effect_document"]["operations"].index(dependent),
            )
        effect = bundle["transition"]["effect_document"]
        targets = set()
        frontier = {dependent["key"]}
        while frontier:
            source = frontier.pop()
            reached = {
                edge["to"]["key"]
                for edge in effect["edges"]
                if edge.get("from") == {"kind": "operation", "key": source}
                and edge.get("kind") == "required-success"
                and edge.get("to", {}).get("kind") == "operation"
            }
            frontier.update(reached - targets)
            targets.update(reached)
        matches = []
        for ordinal, operation in enumerate(effect["operations"]):
            if operation["key"] not in targets:
                continue
            classes = {
                cell["effect_class"]
                for cell in self._cells.values()
                if cell["interface"] == operation["interface"]
                and cell["method"] == operation["method"]
            }
            if classes == {"mutation"}:
                matches.append(operation_identity(operation, ordinal))
        if not matches:
            return operation_identity(
                dependent,
                effect["operations"].index(dependent),
            )
        matches.sort(key=lambda operation: canonical(operation["key"]))
        return matches[0]

    @staticmethod
    def _oracle(kind: str, oracle: LiveOracle) -> dict[str, Any]:
        snapshot = digest(oracle.before)
        return {
            "kind": kind,
            "resource": oracle.resource,
            "before": snapshot,
            "after": digest(oracle.after),
            "unchanged": oracle.before == oracle.after,
            "live": oracle.live,
        }

    @staticmethod
    def _provider_route(
        bundle: dict[str, Any],
        operation: dict[str, Any],
        adapter: str,
        method: str,
    ) -> dict[str, Any]:
        bindings = []
        for state in (bundle.get("desired"), bundle.get("current")):
            if state is not None:
                bindings.extend(
                    state["snapshot"]["resolution"]["binding_document"]["bindings"]
                )
        selected = [
            binding
            for binding in bindings
            if binding["id"] == operation["binding"]
        ]
        implementations = {
            canonical(binding["implementation"]): binding["implementation"]
            for binding in selected
        }
        if len(implementations) != 1:
            raise RuntimeError("provider operation binding is absent or ambiguous")
        implementation = next(iter(implementations.values()))
        handler = implementation.get("handler")
        if not isinstance(handler, str) or not handler:
            raise RuntimeError("provider operation did not select a terminal handler")
        artifact = implementation["artifact"]
        return {
            "adapter": adapter,
            "interface": operation["interface"],
            "method": method,
            "candidate-linked": True,
            "artifact": artifact["content"],
            "handler": handler,
            "entry-point": ENTRY_POINTS[adapter],
        }
