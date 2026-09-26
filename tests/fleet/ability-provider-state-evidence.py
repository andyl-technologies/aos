"""Collects production provider flights for RFC-0022 state-family cells.

The provider cohorts own generation transitions, process interruption, current
authority capture, and adapter-specific resource observation. This module
serializes those retained facts and submits every completed record to the
canonical qualification provider before exposing it to the cohort aggregator.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


SUBJECT_SCHEMA = "aos.qualification.native-adapter-provider-state-subject/v1"
EVIDENCE_SCHEMA = "aos.qualification.native-adapter-provider-state-evidence/v1"
TRANSFER_CONTRACT_SCHEMA = "aos.ability.provider-state-transfer-contract/v1"
RETAINED_SCENARIO = "activate-retained-target"
UNSUPPORTED_SCENARIO = "reject-unsupported-transfer"
COMPATIBLE_SCENARIO = "adopt-compatible-state"
MAX_DOCUMENT_BYTES = 64 * 1024 * 1024


def canonical(value: Any) -> bytes:
    """Encodes one value with the release evidence canonical JSON profile."""

    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def sha256_bytes(value: bytes) -> str:
    """Returns the ordinary SHA-256 identity of exact retained bytes."""

    return "sha256:" + hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class RetainedTargetObservation:
    """Carries independently captured facts from one recovered generation."""

    retained_generation: int
    predecessor_generation: int
    activated_generation: int
    transaction: str
    operation_key: dict[str, Any]
    journal_before_loss: str
    timeline: list[dict[str, Any]]
    boundary_timeline: list[dict[str, Any]]
    authority_before: dict[str, Any]
    authority_after: dict[str, Any]
    source_authority: dict[str, Any]
    ledger_before: dict[str, Any]
    ledger_unsettled: dict[str, Any]
    ledger_after: dict[str, Any]
    live_before: Any
    live_unsettled: Any
    live_after: Any
    foreign_before: Any
    foreign_unsettled: Any
    foreign_after: Any
    dependent_operation: dict[str, Any]
    dependent_before: list[dict[str, Any]]
    dependent_after: list[dict[str, Any]]


@dataclass(frozen=True)
class UnsupportedTransferObservation:
    """Carries facts retained while a candidate route is held before effect."""

    source_generation: int
    candidate_generation: int
    transaction: str
    operation_key: dict[str, Any]
    journal_at_rejection: str
    timeline_at_rejection: list[dict[str, Any]]
    boundary_timeline: list[dict[str, Any]]
    source_authority: dict[str, Any]
    candidate_authority: dict[str, Any]
    ledger_before: dict[str, Any]
    ledger_after: dict[str, Any]
    live_before: Any
    live_after: Any
    foreign_before: Any
    foreign_after: Any
    dependent_operation: dict[str, Any]
    dependent_timeline: list[dict[str, Any]]


@dataclass(frozen=True)
class CompatibleAdoptionObservation:
    """Carries facts from one completed compatible provider adoption."""

    source_generation: int
    candidate_generation: int
    transaction: str
    operation_key: dict[str, Any]
    journal_before_loss: str
    timeline: list[dict[str, Any]]
    boundary_timeline: list[dict[str, Any]]
    source_authority: dict[str, Any]
    candidate_authority: dict[str, Any]
    ledger_before: dict[str, Any]
    ledger_unsettled: dict[str, Any]
    ledger_after: dict[str, Any]
    live_before: Any
    live_unsettled: Any
    live_after: Any
    foreign_before: Any
    foreign_unsettled: Any
    foreign_after: Any
    dependent_operation: dict[str, Any]
    dependent_after: list[dict[str, Any]]


@dataclass(frozen=True)
class IncompatibleTransferObservation:
    """Carries facts from one rejected incompatible provider replacement."""

    source_generation: int
    generation_after: int
    transaction: str
    operation_key: dict[str, Any]
    activation_error: str
    source_authority: dict[str, Any]
    candidate_policy: dict[str, Any]
    ledger_before: dict[str, Any]
    ledger_after: dict[str, Any]
    live_before: Any
    live_after: Any
    foreign_before: Any
    foreign_after: Any
    dependent_operation: dict[str, Any]


class ProviderStateEvidence:
    """Collects exact provider state evidence from production VM flights."""

    def __init__(
        self,
        matrix_spec: dict[str, Any],
        qualified_cells: list[str],
        validator: Any,
    ) -> None:
        cells = {cell["id"]: cell for cell in matrix_spec["cells"]}
        if len(cells) != len(matrix_spec["cells"]):
            raise RuntimeError("native-adapter matrix repeats a cell identity")
        if len(set(qualified_cells)) != len(qualified_cells):
            raise RuntimeError("provider-state cohort repeats a cell identity")
        if any(cell_id not in cells for cell_id in qualified_cells):
            raise RuntimeError("provider-state cohort names a foreign matrix cell")
        self._cells = cells
        self._qualified = set(qualified_cells)
        self._validator = validator
        self._matrix_spec = matrix_spec
        self.subjects: dict[str, Any] = {}
        self.evidence: dict[str, bytes] = {}
        self.probes: dict[str, Any] = {}

    def retain_retained_target(
        self,
        cell_id: str,
        plan_bundle: bytes,
        observation: RetainedTargetObservation,
    ) -> None:
        """Retains one real recovered activation under current authority."""

        cell, bundle, operation, operation_identity = self._route(
            cell_id, plan_bundle, observation.operation_key, RETAINED_SCENARIO
        )
        source_authority = self._validator.authority(observation.source_authority)
        authority_before = self._validator.authority(observation.authority_before)
        authority_after = self._validator.authority(observation.authority_after)
        _, source_assignment = self._validator.route(source_authority, operation)
        _, assignment_before = self._validator.route(authority_before, operation)
        binding_after, assignment_after = self._validator.route(
            authority_after, operation
        )
        dependency_edge = _dependency_edge(
            operation_identity, observation.dependent_operation
        )

        resource = operation["target"]["resource"]
        current_revision = _resource_revision(bundle, "current_revisions", resource)
        desired_revision = _resource_revision(bundle, "desired_revisions", resource)
        owner_before = self._validator.ledger_claim(
            observation.ledger_before, resource
        )
        owner_unsettled = self._validator.ledger_claim(
            observation.ledger_unsettled, resource
        )
        owner_after = self._validator.ledger_claim(observation.ledger_after, resource)

        subject = _subject(
            cell,
            bundle,
            plan_bundle,
            operation_identity,
            observation.dependent_operation,
            dependency_edge,
            binding_after["implementation"],
            observation.transaction,
            {
                "retained": observation.retained_generation,
                "predecessor": observation.predecessor_generation,
                "activated": observation.activated_generation,
            },
        )
        evidence = {
            "schema": EVIDENCE_SCHEMA,
            "scenario": RETAINED_SCENARIO,
            "plan-bundle": bundle,
            "journal-before-loss": observation.journal_before_loss,
            "authority-before": authority_before,
            "authority-after": authority_after,
            "source-authority": source_authority,
            "ledger-before": observation.ledger_before,
            "ledger-unsettled": observation.ledger_unsettled,
            "ledger-after": observation.ledger_after,
            "live-before": observation.live_before,
            "live-unsettled": observation.live_unsettled,
            "live-after": observation.live_after,
            "foreign-before": observation.foreign_before,
            "foreign-unsettled": observation.foreign_unsettled,
            "foreign-after": observation.foreign_after,
            "timeline": observation.timeline,
            "boundary-timeline": observation.boundary_timeline,
            "dependent-operation": observation.dependent_operation,
            "dependent-before": observation.dependent_before,
            "dependent-after": observation.dependent_after,
            "current-revision": current_revision,
            "desired-revision": desired_revision,
        }
        disposition = "retained-target-activated"
        self._store(
            cell_id,
            subject,
            evidence,
            {
                "durable-attempt-state-classified": _probe(
                    "journal-timeline",
                    disposition,
                    {
                        "transaction": observation.transaction,
                        "plan": bundle["plan"],
                        "operation": operation_identity,
                        "journal-before-loss": observation.journal_before_loss,
                        "timeline": observation.timeline,
                        "boundary-timeline": observation.boundary_timeline,
                        "terminal": "complete",
                    },
                ),
                "at-most-one-resource-owner": _probe(
                    "ownership-inventory",
                    disposition,
                    {
                        "resource": resource,
                        "ledger-before": observation.ledger_before,
                        "ledger-unsettled": observation.ledger_unsettled,
                        "ledger-after": observation.ledger_after,
                    },
                ),
                "foreign-resources-unchanged": _probe(
                    "foreign-resource-snapshot",
                    disposition,
                    {
                        "resource": resource,
                        "snapshot-before": observation.foreign_before,
                        "snapshot-unsettled": observation.foreign_unsettled,
                        "snapshot-after": observation.foreign_after,
                        "unchanged": True,
                    },
                ),
                "current-grants-reauthorized": _probe(
                    "authority-grants",
                    disposition,
                    {
                        "plan": bundle["plan"],
                        "binding": binding_after,
                        "authority-before": sha256_bytes(canonical(authority_before)),
                        "authority-after": sha256_bytes(canonical(authority_after)),
                        "source-authority": sha256_bytes(canonical(source_authority)),
                        "predecessor-incarnation": source_assignment["incarnation"],
                        "candidate-incarnation": assignment_before["incarnation"],
                        "authority-sequence-before": authority_before["sequence"],
                        "authority-sequence-after": authority_after["sequence"],
                        "reauthorized": True,
                    },
                ),
                "retained-target-identity-preserved": _probe(
                    "target-identity",
                    disposition,
                    {
                        "retained-target": resource,
                        "activated-target": operation["target"]["resource"],
                        "current-revision": current_revision,
                        "desired-revision": desired_revision,
                        "live-before": observation.live_before,
                        "live-after": observation.live_after,
                    },
                ),
                "exactly-one-resource-owner": _probe(
                    "exact-ownership-inventory",
                    disposition,
                    {
                        "resource": resource,
                        "owner-before": owner_before,
                        "owner-unsettled": owner_unsettled,
                        "owner-after": owner_after,
                        "same-owner-core": self._validator.claim_core(owner_before)
                        == self._validator.claim_core(owner_after),
                        "authorized-route-count": 1,
                    },
                ),
            },
        )

    def retain_compatible_adoption(
        self,
        cell_id: str,
        plan_bundle: bytes,
        transfer_contract: bytes,
        observation: CompatibleAdoptionObservation,
    ) -> None:
        """Retains one completed transfer between format-compatible providers."""

        cell, bundle, operation, operation_identity = self._route(
            cell_id, plan_bundle, observation.operation_key, COMPATIBLE_SCENARIO
        )
        contract = _canonical_document(transfer_contract, "transfer contract")
        owner = contract.get("disposition", {}).get("owner")
        source_authority = self._validator.authority(observation.source_authority)
        candidate_authority = self._validator.authority(
            observation.candidate_authority
        )
        _, source_assignment = self._validator.route(source_authority, operation)
        candidate_binding, candidate_assignment = self._validator.route(
            candidate_authority, operation
        )
        dependency_edge = _dependency_edge(
            operation_identity, observation.dependent_operation
        )

        adoptions = bundle.get("transition_authority", {}).get(
            "provider_adoptions", []
        )
        resource = operation["target"]["resource"]
        adoption = _matching_resource(adoptions, resource)
        source_format = adoption.get("source", {}).get("state_format")
        candidate_format = adoption.get("candidate", {}).get("state_format")
        owner_before = self._validator.ledger_claim(
            observation.ledger_before, resource
        )
        owner_unsettled = self._validator.ledger_claim(
            observation.ledger_unsettled, resource
        )
        owner_after = self._validator.ledger_claim(observation.ledger_after, resource)

        subject = _subject(
            cell,
            bundle,
            plan_bundle,
            operation_identity,
            observation.dependent_operation,
            dependency_edge,
            candidate_binding["implementation"],
            observation.transaction,
            {
                "source": observation.source_generation,
                "candidate": observation.candidate_generation,
            },
            transfer_contract_digest=sha256_bytes(transfer_contract),
        )
        evidence = {
            "schema": EVIDENCE_SCHEMA,
            "scenario": COMPATIBLE_SCENARIO,
            "plan-bundle": bundle,
            "transfer-contract": contract,
            "journal-before-loss": observation.journal_before_loss,
            "timeline": observation.timeline,
            "boundary-timeline": observation.boundary_timeline,
            "source-authority": source_authority,
            "candidate-authority": candidate_authority,
            "ledger-before": observation.ledger_before,
            "ledger-unsettled": observation.ledger_unsettled,
            "ledger-after": observation.ledger_after,
            "live-before": observation.live_before,
            "live-unsettled": observation.live_unsettled,
            "live-after": observation.live_after,
            "foreign-before": observation.foreign_before,
            "foreign-unsettled": observation.foreign_unsettled,
            "foreign-after": observation.foreign_after,
            "dependent-operation": observation.dependent_operation,
            "dependent-after": observation.dependent_after,
        }
        disposition = "compatible-state-adopted"
        self._store(
            cell_id,
            subject,
            evidence,
            {
                "durable-attempt-state-classified": _probe(
                    "journal-timeline",
                    disposition,
                    {
                        "transaction": observation.transaction,
                        "plan": bundle["plan"],
                        "operation": operation_identity,
                        "journal-before-loss": observation.journal_before_loss,
                        "timeline": observation.timeline,
                        "boundary-timeline": observation.boundary_timeline,
                        "terminal": "complete",
                    },
                ),
                "at-most-one-resource-owner": _probe(
                    "ownership-inventory",
                    disposition,
                    {
                        "resource": resource,
                        "ledger-before": observation.ledger_before,
                        "ledger-unsettled": observation.ledger_unsettled,
                        "ledger-after": observation.ledger_after,
                    },
                ),
                "foreign-resources-unchanged": _probe(
                    "foreign-resource-snapshot",
                    disposition,
                    {
                        "resource": resource,
                        "snapshot-before": observation.foreign_before,
                        "snapshot-unsettled": observation.foreign_unsettled,
                        "snapshot-after": observation.foreign_after,
                        "unchanged": True,
                    },
                ),
                "fresh-receiving-authority": _probe(
                    "authority-incarnation",
                    disposition,
                    {
                        "source-authority": sha256_bytes(canonical(source_authority)),
                        "candidate-authority": sha256_bytes(
                            canonical(candidate_authority)
                        ),
                        "predecessor-incarnation": source_assignment["incarnation"],
                        "candidate-incarnation": candidate_assignment["incarnation"],
                        "authority-sequence-before": source_authority["sequence"],
                        "authority-sequence-after": candidate_authority["sequence"],
                        "fresh": True,
                    },
                ),
                "compatible-state-adopted": _probe(
                    "state-adoption",
                    disposition,
                    {
                        "resource": resource,
                        "contract": contract,
                        "source-state-format": source_format,
                        "candidate-state-format": candidate_format,
                        "live-before": observation.live_before,
                        "live-after": observation.live_after,
                        "adopted": True,
                    },
                ),
                "exactly-one-resource-owner": _probe(
                    "exact-ownership-inventory",
                    disposition,
                    {
                        "resource": resource,
                        "candidate-owner": owner_after,
                        "owners": [owner_after],
                        "authorized-route-count": 1,
                    },
                ),
            },
        )

    def retain_unsupported_transfer(
        self,
        cell_id: str,
        plan_bundle: bytes,
        transfer_contract: bytes,
        observation: UnsupportedTransferObservation,
    ) -> None:
        """Retains one production transfer rejection before provider effect."""

        cell, bundle, operation, operation_identity = self._route(
            cell_id, plan_bundle, observation.operation_key, UNSUPPORTED_SCENARIO
        )
        contract = _canonical_document(transfer_contract, "transfer contract")
        source_authority = self._validator.authority(observation.source_authority)
        candidate_authority = self._validator.authority(
            observation.candidate_authority
        )
        _, source_assignment = self._validator.route(source_authority, operation)
        candidate_binding, candidate_assignment = self._validator.route(
            candidate_authority, operation
        )
        dependency_edge = _dependency_edge(
            operation_identity, observation.dependent_operation
        )

        resource = operation["target"]["resource"]
        predecessor_owner = self._validator.ledger_claim(
            observation.ledger_before, resource
        )
        successor_owner = self._validator.ledger_claim(
            observation.ledger_after, resource
        )
        ledger_owners_before = [predecessor_owner]
        ledger_owners_after = [successor_owner]
        subject = _subject(
            cell,
            bundle,
            plan_bundle,
            operation_identity,
            observation.dependent_operation,
            dependency_edge,
            candidate_binding["implementation"],
            observation.transaction,
            {
                "source": observation.source_generation,
                "candidate": observation.candidate_generation,
            },
            transfer_contract_digest=sha256_bytes(transfer_contract),
        )
        evidence = {
            "schema": EVIDENCE_SCHEMA,
            "scenario": UNSUPPORTED_SCENARIO,
            "plan-bundle": bundle,
            "transfer-contract": contract,
            "journal-at-rejection": observation.journal_at_rejection,
            "timeline-at-rejection": observation.timeline_at_rejection,
            "boundary-timeline": observation.boundary_timeline,
            "source-authority": source_authority,
            "candidate-authority": candidate_authority,
            "ledger-before": observation.ledger_before,
            "ledger-after": observation.ledger_after,
            "live-before": observation.live_before,
            "live-after": observation.live_after,
            "foreign-before": observation.foreign_before,
            "foreign-after": observation.foreign_after,
            "dependent-operation": observation.dependent_operation,
            "dependent-timeline": observation.dependent_timeline,
        }
        disposition = "transfer-rejected-before-effect"
        self._store(
            cell_id,
            subject,
            evidence,
            {
                "durable-attempt-state-classified": _probe(
                    "transfer-contract",
                    disposition,
                    {
                        "transaction": observation.transaction,
                        "plan": bundle["plan"],
                        "operation": operation_identity,
                        "journal-at-rejection": observation.journal_at_rejection,
                        "timeline-at-rejection": observation.timeline_at_rejection,
                        "transfer-contract": sha256_bytes(transfer_contract),
                        "terminal": "rejected-before-effect",
                    },
                ),
                "at-most-one-resource-owner": _probe(
                    "ownership-inventory",
                    disposition,
                    {
                        "resource": resource,
                        "ledger-before": observation.ledger_before,
                        "ledger-after": observation.ledger_after,
                    },
                ),
                "foreign-resources-unchanged": _probe(
                    "foreign-resource-snapshot",
                    disposition,
                    {
                        "resource": resource,
                        "snapshot-before": observation.foreign_before,
                        "snapshot-after": observation.foreign_after,
                        "unchanged": True,
                    },
                ),
                "dependent-effects-not-executed": _probe(
                    "dependency-barrier",
                    disposition,
                    {
                        "operation": operation_identity,
                        "dependent-operation": observation.dependent_operation,
                        "dependent-timeline": observation.dependent_timeline,
                        "blocked": True,
                    },
                ),
                "fresh-receiving-authority": _probe(
                    "authority-incarnation",
                    disposition,
                    {
                        "source-authority": sha256_bytes(canonical(source_authority)),
                        "candidate-authority": sha256_bytes(
                            canonical(candidate_authority)
                        ),
                        "predecessor-incarnation": source_assignment["incarnation"],
                        "candidate-incarnation": candidate_assignment["incarnation"],
                        "authority-sequence-before": source_authority["sequence"],
                        "authority-sequence-after": candidate_authority["sequence"],
                        "fresh": True,
                    },
                ),
                "transfer-rejected-before-candidate-effect": _probe(
                    "transfer-rejection",
                    disposition,
                    {
                        "candidate-operation": operation_identity,
                        "contract": contract,
                        "candidate-effect-boundaries": observation.boundary_timeline,
                        "candidate-effect-count": 0,
                        "rejected-before-effect": True,
                    },
                ),
                "predecessor-remains-sole-owner": _probe(
                    "predecessor-ownership",
                    disposition,
                    {
                        "resource": resource,
                        "predecessor-owner": predecessor_owner,
                        "owners": [predecessor_owner],
                        "ledger-owners-before": ledger_owners_before,
                        "ledger-owners-after": ledger_owners_after,
                        "behavior-before": observation.live_before,
                        "behavior-after": observation.live_after,
                    },
                ),
            },
        )

    def retain_incompatible_transfer(
        self,
        cell_id: str,
        plan_bundle: bytes,
        observation: IncompatibleTransferObservation,
    ) -> None:
        """Retains an authenticated format mismatch rejected before effects."""

        cell, bundle, operation, operation_identity = self._route(
            cell_id, plan_bundle, observation.operation_key, UNSUPPORTED_SCENARIO
        )
        source_authority = self._validator.authority(observation.source_authority)
        source_binding, source_assignment = self._validator.route(
            source_authority, operation
        )
        source_owner = self._validator.ledger_claim(
            observation.ledger_before, operation["target"]["resource"]
        )
        owner_after = self._validator.ledger_claim(
            observation.ledger_after, operation["target"]["resource"]
        )

        policy = observation.candidate_policy
        authority = policy.get("transition_authority", {})
        adoptions = authority.get("provider_adoptions", [])
        resource = operation["target"]["resource"]
        adoption = _matching_resource(adoptions, resource)
        source = adoption.get("source", {})
        candidate = adoption.get("candidate", {})
        source_format = source.get("state_format")
        candidate_format = candidate.get("state_format")
        dependency_edge = _dependency_edge(
            operation_identity, observation.dependent_operation
        )
        authority_digest = sha256_bytes(canonical(authority))
        subject = _subject(
            cell,
            bundle,
            plan_bundle,
            operation_identity,
            observation.dependent_operation,
            dependency_edge,
            source_binding["implementation"],
            observation.transaction,
            {
                "source": observation.source_generation,
                "candidate": observation.generation_after,
            },
            transfer_contract_digest=authority_digest,
        )
        evidence = {
            "schema": EVIDENCE_SCHEMA,
            "scenario": UNSUPPORTED_SCENARIO,
            "rejection-kind": "incompatible-authenticated-state-format",
            "plan-bundle": bundle,
            "candidate-policy": policy,
            "activation-error": observation.activation_error,
            "source-authority": source_authority,
            "ledger-before": observation.ledger_before,
            "ledger-after": observation.ledger_after,
            "live-before": observation.live_before,
            "live-after": observation.live_after,
            "foreign-before": observation.foreign_before,
            "foreign-after": observation.foreign_after,
            "boundary-timeline": [],
            "dependent-operation": observation.dependent_operation,
            "dependent-timeline": [],
        }
        disposition = "transfer-rejected-before-effect"
        rejection_facts = {
            "candidate-operation": operation_identity,
            "source-state-format": source_format,
            "candidate-state-format": candidate_format,
            "candidate-effect-boundaries": [],
            "candidate-effect-count": 0,
            "rejected-before-effect": True,
        }
        self._store(
            cell_id,
            subject,
            evidence,
            {
                "durable-attempt-state-classified": _probe(
                    "journal-timeline",
                    disposition,
                    {
                        "transaction": observation.transaction,
                        "plan": bundle["plan"],
                        "operation": operation_identity,
                        "activation-error": sha256_bytes(
                            observation.activation_error.encode()
                        ),
                        "terminal": "rejected-before-effect",
                    },
                ),
                "at-most-one-resource-owner": _probe(
                    "ownership-inventory",
                    disposition,
                    {
                        "resource": resource,
                        "ledger-before": observation.ledger_before,
                        "ledger-after": observation.ledger_after,
                    },
                ),
                "foreign-resources-unchanged": _probe(
                    "foreign-resource-snapshot",
                    disposition,
                    {
                        "resource": resource,
                        "snapshot-before": observation.foreign_before,
                        "snapshot-after": observation.foreign_after,
                        "unchanged": True,
                    },
                ),
                "dependent-effects-not-executed": _probe(
                    "dependency-barrier",
                    disposition,
                    {
                        "operation": operation_identity,
                        "dependent-operation": observation.dependent_operation,
                        "dependent-timeline": [],
                        "blocked": True,
                    },
                ),
                "fresh-receiving-authority": _probe(
                    "authority-incarnation",
                    disposition,
                    {
                        "source-authority": sha256_bytes(canonical(source_authority)),
                        "candidate-authority": authority_digest,
                        "predecessor-incarnation": source["handler_incarnation"],
                        "candidate-incarnation": candidate["handler_incarnation"],
                        "fresh": True,
                    },
                ),
                "transfer-rejected-before-candidate-effect": _probe(
                    "transfer-rejection", disposition, rejection_facts
                ),
                "predecessor-remains-sole-owner": _probe(
                    "predecessor-ownership",
                    disposition,
                    {
                        "resource": resource,
                        "predecessor-owner": source_owner,
                        "owners": [source_owner],
                        "ledger-owners-before": [source_owner],
                        "ledger-owners-after": [owner_after],
                        "behavior-before": observation.live_before,
                        "behavior-after": observation.live_after,
                    },
                ),
            },
        )

    def finish(self) -> tuple[dict[str, Any], dict[str, bytes], dict[str, Any]]:
        """Returns output maps after proving complete intended coverage."""

        observed = set(self.probes)
        if observed != self._qualified:
            raise RuntimeError(
                "provider-state evidence is incomplete: "
                f"missing={sorted(self._qualified - observed)}, "
                f"unexpected={sorted(observed - self._qualified)}"
            )
        return self.subjects, self.evidence, self.probes

    def _route(
        self,
        cell_id: str,
        plan_bundle: bytes,
        operation_key: dict[str, Any],
        scenario: str,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
        if cell_id not in self._qualified or cell_id in self.probes:
            raise RuntimeError(f"unexpected or repeated provider-state cell {cell_id}")
        cell = self._cells[cell_id]
        if cell_id.rsplit("/", 1)[-1] != scenario:
            raise RuntimeError("provider-state evidence targets another scenario")
        bundle = _canonical_document(plan_bundle, "plan bundle")
        if bundle.get("schema") != "aos.ability.plan-bundle/v1":
            raise RuntimeError("provider-state evidence has another plan-bundle schema")
        matches = [
            (ordinal, operation)
            for ordinal, operation in enumerate(
                bundle["transition"]["effect_document"]["operations"]
            )
            if operation["key"] == operation_key
            and operation["interface"] == cell["interface"]
            and operation["method"] == cell["method"]
        ]
        if len(matches) != 1:
            raise RuntimeError("plan does not contain one exact provider-state operation")
        ordinal, operation = matches[0]
        return cell, bundle, operation, _operation_identity(operation, ordinal)

    def _store(
        self,
        cell_id: str,
        subject: dict[str, Any],
        evidence: dict[str, Any],
        probes: dict[str, Any],
    ) -> None:
        evidence_bytes = canonical(evidence)
        subject["evidence-digest"] = sha256_bytes(evidence_bytes)

        self._validator.validate_collection(
            self._cells[cell_id],
            subject,
            evidence_bytes,
            probes,
            self._matrix_spec,
        )

        self.subjects[cell_id] = subject
        self.evidence[cell_id] = evidence_bytes
        self.probes[cell_id] = probes


def _canonical_document(document: bytes, label: str) -> dict[str, Any]:
    if not isinstance(document, bytes) or len(document) > MAX_DOCUMENT_BYTES:
        raise RuntimeError(f"{label} has an invalid encoded size")
    try:
        value = json.loads(document)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{label} is not JSON") from error
    if not isinstance(value, dict) or canonical(value) != document:
        raise RuntimeError(f"{label} is not canonical")
    return value


def _operation_identity(operation: dict[str, Any], ordinal: int) -> dict[str, Any]:
    return {
        "key": operation["key"],
        "ordinal": ordinal,
        "interface": operation["interface"],
        "method": operation["method"],
        "target": operation["target"],
    }


def _subject(
    cell: dict[str, Any],
    bundle: dict[str, Any],
    plan_bundle: bytes,
    operation: dict[str, Any],
    dependent_operation: dict[str, Any],
    dependency_edge: dict[str, Any],
    provider_implementation: dict[str, Any],
    transaction: str,
    generations: dict[str, int],
    *,
    transfer_contract_digest: str | None = None,
) -> dict[str, Any]:
    subject = {
        "schema": SUBJECT_SCHEMA,
        "cell-id": cell["id"],
        "cell-digest": sha256_bytes(canonical(cell)),
        "plan": bundle["plan"],
        "plan-bundle-digest": sha256_bytes(plan_bundle),
        "transaction": transaction,
        "adapter": cell["adapter"],
        "operation": operation,
        "dependent-operation": dependent_operation,
        "dependency-edge": dependency_edge,
        "provider-implementation": provider_implementation,
        "generations": generations,
    }
    if transfer_contract_digest is not None:
        subject["transfer-contract-digest"] = transfer_contract_digest
    return subject


def _resource_revision(
    bundle: dict[str, Any], field: str, resource: dict[str, Any]
) -> dict[str, Any] | None:
    """Projects the observed revision while leaving acceptance to qualification."""

    revisions = [
        revision
        for revision in bundle["transition"]["effect_document"][field]
        if revision.get("resource") == resource
    ]
    return revisions[0] if len(revisions) == 1 else None


def _dependency_edge(
    operation: dict[str, Any], dependent: dict[str, Any]
) -> dict[str, Any]:
    """Projects the edge identity asserted by the independent dependent probe."""

    return {
        "from": {"kind": "operation", "key": operation["key"]},
        "to": {"kind": "operation", "key": dependent["key"]},
        "kind": "required-success",
    }


def _matching_resource(
    records: list[dict[str, Any]], resource: dict[str, Any]
) -> dict[str, Any]:
    """Projects the sole retained row for a resource identity."""

    matches = [record for record in records if record.get("resource") == resource]
    if len(matches) != 1:
        raise RuntimeError("provider-state observation has no unique resource row")
    return matches[0]


def _probe(kind: str, disposition: str, observations: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": kind,
        "disposition": disposition,
        "detail": "Production provider-state evidence for the exact checked matrix operation.",
        "observations": observations,
    }
