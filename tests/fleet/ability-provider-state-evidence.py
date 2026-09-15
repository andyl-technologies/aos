"""Binds production provider flights to RFC-0022 state-family cells.

The provider cohorts own generation transitions, process interruption, current
authority capture, and adapter-specific resource observation. This module
accepts only those retained facts and checks that they describe the exact
candidate operation in the canonical production plan bundle.
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
MAX_RETAINED_ENTRIES = 65_536


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

    def __init__(self, matrix_spec: dict[str, Any], qualified_cells: list[str]):
        cells = {cell["id"]: cell for cell in matrix_spec["cells"]}
        if len(cells) != len(matrix_spec["cells"]):
            raise RuntimeError("native-adapter matrix repeats a cell identity")
        if len(set(qualified_cells)) != len(qualified_cells):
            raise RuntimeError("provider-state cohort repeats a cell identity")
        if any(cell_id not in cells for cell_id in qualified_cells):
            raise RuntimeError("provider-state cohort names a foreign matrix cell")
        adapters = matrix_spec.get("surface", {}).get("adapters")
        if not isinstance(adapters, list):
            raise RuntimeError("provider-state cohort has no provider contracts")
        contracts = {
            adapter["adapter"]: adapter["provider_contract"] for adapter in adapters
        }
        if len(contracts) != len(adapters):
            raise RuntimeError("provider-state cohort repeats a provider contract")
        if any(cell["adapter"] not in contracts for cell in cells.values()):
            raise RuntimeError("provider-state cell has no provider contract")

        self._cells = cells
        self._contracts = contracts
        self._qualified = set(qualified_cells)
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
        _retained_generation_transition(
            observation.retained_generation,
            observation.predecessor_generation,
            observation.activated_generation,
        )
        _same_foreign_observation(
            observation.foreign_before,
            observation.foreign_unsettled,
            observation.foreign_after,
        )
        first_effect_boundary = _first_effect_boundary(observation.boundary_timeline)
        if first_effect_boundary is None:
            raise RuntimeError("retained-target flight has no provider boundary")
        if first_effect_boundary != "resources-acquired":
            raise RuntimeError("retained-target flight started at another boundary")
        if not observation.timeline or not observation.dependent_after:
            raise RuntimeError("retained-target recovery did not settle its real graph")
        if observation.dependent_before:
            raise RuntimeError("retained-target dependent ran before recovery")
        timeline_kinds = [event.get("kind") for event in observation.timeline]
        if "effect-started" not in timeline_kinds or "effect-completed" not in timeline_kinds:
            raise RuntimeError("retained-target method did not complete durably")
        dependent_kinds = [event.get("kind") for event in observation.dependent_after]
        if "effect-completed" not in dependent_kinds:
            raise RuntimeError("retained-target dependent did not settle after the method")

        authority_before = _current_authority(
            observation.authority_before,
            bundle["plan"],
            observation.transaction,
        )
        authority_after = _current_authority(
            observation.authority_after,
            bundle["plan"],
            observation.transaction,
        )
        binding_before, assignment_before = _exact_authorized_route(
            authority_before, operation
        )
        binding_after, assignment_after = _exact_authorized_route(
            authority_after, operation
        )
        if binding_after != binding_before:
            raise RuntimeError("current grant changed while retained work recovered")
        if _assignment_core(assignment_after) != _assignment_core(assignment_before):
            raise RuntimeError("recovery selected another terminal provider")
        if authority_after["sequence"] <= authority_before["sequence"]:
            raise RuntimeError("current authority was not republished for recovery")
        if authority_after["observed_at_restart_millis"] < authority_before[
            "observed_at_restart_millis"
        ]:
            raise RuntimeError("recovered authority predates its retained authority")

        source_authority = _current_authority(
            observation.source_authority, None, None
        )
        _fresh_receiving_authority(source_authority, authority_before)
        source_binding, source_assignment = _unique_authorized_route(
            source_authority, operation
        )
        if _assignment_core(source_assignment) != _assignment_core(assignment_before):
            raise RuntimeError("retained target selected another provider route")
        if source_assignment["incarnation"] == assignment_before["incarnation"]:
            raise RuntimeError("retained target reused the predecessor incarnation")

        _exact_resource_observation(authority_before, operation, usable=False)
        _exact_resource_observation(authority_after, operation, usable=False)
        dependency_edge = _exact_dependent(
            bundle, operation_identity, observation.dependent_operation
        )

        resource = operation["target"]["resource"]
        current_revision = _exact_resource_revision(
            bundle, "current_revisions", resource, required=False
        )
        desired_revision = _exact_resource_revision(
            bundle, "desired_revisions", resource, required=False
        )
        if current_revision is None and desired_revision is None:
            raise RuntimeError("retained transition has no exact resource revision")
        route_owner_before = _route_owner(binding_before, assignment_before)
        route_owner_after = _route_owner(binding_after, assignment_after)
        owner_before = _exact_ledger_claim(observation.ledger_before, resource)
        owner_unsettled = _exact_ledger_claim(
            observation.ledger_unsettled, resource
        )
        owner_after = _exact_ledger_claim(observation.ledger_after, resource)
        _ledger_claim_matches_route(owner_before, binding_before, assignment_before)
        _ledger_claim_matches_route(owner_unsettled, binding_before, assignment_before)
        _ledger_claim_matches_route(owner_after, binding_after, assignment_after)
        if _ledger_claim_core(owner_before) != _ledger_claim_core(owner_after):
            raise RuntimeError("retained activation changed the resource owner identity")
        if observation.live_before is None or observation.live_after is None:
            raise RuntimeError("retained-target provider observation is absent")

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
                        "same-owner-core": (
                            _owner_core(route_owner_before)
                            == _owner_core(route_owner_after)
                        ),
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
        if (
            contract.get("schema") != TRANSFER_CONTRACT_SCHEMA
            or contract.get("plan") != bundle["plan"]
            or contract.get("operation") != operation
            or contract.get("disposition", {}).get("status") != "supported"
            or not isinstance(owner, dict)
        ):
            raise RuntimeError("production transfer contract does not support the candidate route")
        provider_contract = self._contracts[cell["adapter"]]
        if (
            provider_contract["resource_lifetime"] != "persistent"
            or provider_contract["state_format"] is None
            or owner.get("state_format", {}).get("descriptor")
            != provider_contract["state_format"]
        ):
            raise RuntimeError("supported transfer differs from the matrix provider contract")

        _ordered_generations(
            observation.source_generation, observation.candidate_generation
        )
        if observation.foreign_before != observation.foreign_unsettled:
            raise RuntimeError("compatible adoption changed a foreign resource while unsettled")
        if observation.foreign_before != observation.foreign_after:
            raise RuntimeError("compatible adoption changed a foreign resource")
        timeline_kinds = [event.get("kind") for event in observation.timeline]
        if "effect-started" not in timeline_kinds or "effect-completed" not in timeline_kinds:
            raise RuntimeError("compatible adoption did not complete its exact method")
        if "effect-completed" not in [
            event.get("kind") for event in observation.dependent_after
        ]:
            raise RuntimeError("compatible adoption did not settle its successor")

        source_authority = _current_authority(
            observation.source_authority, expected_plan=None, expected_transaction=None
        )
        candidate_authority = _current_authority(
            observation.candidate_authority, bundle["plan"], observation.transaction
        )
        _fresh_receiving_authority(source_authority, candidate_authority)
        source_binding, source_assignment = _unique_authorized_route(
            source_authority, operation
        )
        candidate_binding, candidate_assignment = _exact_authorized_route(
            candidate_authority, operation
        )
        if source_assignment["incarnation"] == candidate_assignment["incarnation"]:
            raise RuntimeError("compatible adoption reused the source incarnation")
        dependency_edge = _exact_dependent(
            bundle, operation_identity, observation.dependent_operation
        )

        adoptions = bundle.get("transition_authority", {}).get(
            "provider_adoptions", []
        )
        resource = operation["target"]["resource"]
        matching_adoptions = [
            adoption for adoption in adoptions if adoption.get("resource") == resource
        ]
        if len(matching_adoptions) != 1:
            raise RuntimeError("compatible transfer lacks one exact adoption authorization")
        adoption = matching_adoptions[0]
        source_format = adoption.get("source", {}).get("state_format")
        candidate_format = adoption.get("candidate", {}).get("state_format")
        if (
            source_format != owner.get("state_format")
            or candidate_format != owner.get("state_format")
            or source_format.get("descriptor") != provider_contract["state_format"]
        ):
            raise RuntimeError("compatible adoption endpoints do not share the declared format")

        owner_before = _exact_ledger_claim(observation.ledger_before, resource)
        owner_unsettled = _exact_ledger_claim(observation.ledger_unsettled, resource)
        owner_after = _exact_ledger_claim(observation.ledger_after, resource)
        _ledger_claim_matches_route(owner_before, source_binding, source_assignment)
        _ledger_claim_matches_route(
            owner_unsettled, candidate_binding, candidate_assignment
        )
        _ledger_claim_matches_route(owner_after, candidate_binding, candidate_assignment)
        if observation.live_before is None or observation.live_after is None:
            raise RuntimeError("compatible adoption lacks provider state observations")

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
        if (
            contract.get("schema") != TRANSFER_CONTRACT_SCHEMA
            or contract.get("plan") != bundle["plan"]
            or contract.get("operation") != operation
            or contract.get("disposition", {}).get("status") != "unsupported"
        ):
            raise RuntimeError("production transfer contract differs from the candidate route")
        rejection = contract["disposition"].get("rejection")
        if not isinstance(rejection, dict) or rejection.get("reason") not in {
            "non-persistent-lifetime",
            "missing-authenticated-state-format",
        }:
            raise RuntimeError("transfer contract has no truthful unsupported reason")
        provider_contract = self._contracts[cell["adapter"]]
        expected_lifetime = provider_contract["resource_lifetime"]
        expected_reason = (
            "non-persistent-lifetime"
            if expected_lifetime != "persistent"
            else (
                "missing-authenticated-state-format"
                if provider_contract["state_format"] is None
                else None
            )
        )
        if (
            expected_reason is not None
            and rejection.get("reason") != expected_reason
        ) or any(
            rejection.get(field) != expected_lifetime
            for field in ("target_lifetime", "request_lifetime", "binding_lifetime")
        ):
            raise RuntimeError("transfer rejection differs from the provider contract")

        _ordered_generations(
            observation.source_generation, observation.candidate_generation
        )
        if observation.live_after != observation.live_before:
            raise RuntimeError("candidate provider changed the resource before rejection")
        if observation.foreign_after != observation.foreign_before:
            raise RuntimeError("candidate transfer attempt changed a foreign resource")
        if observation.dependent_timeline:
            raise RuntimeError("candidate dependent ran after transfer rejection")
        effect_boundaries = [
            boundary.get("boundary")
            for boundary in observation.boundary_timeline
            if boundary.get("purpose") == "effect"
        ]
        if effect_boundaries != ["resources-acquired"]:
            raise RuntimeError(
                "transfer rejection was not retained at the sole pre-effect boundary"
            )
        if not observation.timeline_at_rejection:
            raise RuntimeError("transfer rejection has no durable operation attempt")
        if any(
            event.get("kind") in {"effect-started", "effect-completed"}
            for event in observation.timeline_at_rejection
        ):
            raise RuntimeError("candidate journal records an effect before rejection")

        source_authority = _current_authority(
            observation.source_authority,
            expected_plan=None,
            expected_transaction=None,
        )
        candidate_authority = _current_authority(
            observation.candidate_authority,
            bundle["plan"],
            observation.transaction,
        )
        candidate_binding, candidate_assignment = _exact_authorized_route(
            candidate_authority, operation
        )
        source_binding, source_assignment = _unique_authorized_route(
            source_authority, operation
        )
        _fresh_receiving_authority(source_authority, candidate_authority)
        if source_assignment["incarnation"] == candidate_assignment["incarnation"]:
            raise RuntimeError("candidate reused the predecessor provider incarnation")
        source_resource = _exact_resource_observation(
            source_authority, operation, usable=True
        )
        if source_resource["state"].get("state") != "present":
            raise RuntimeError("transfer predecessor resource is not present and healthy")
        _exact_resource_observation(candidate_authority, operation, usable=False)
        dependency_edge = _exact_dependent(
            bundle, operation_identity, observation.dependent_operation
        )

        resource = operation["target"]["resource"]
        predecessor_owner = _exact_ledger_claim(observation.ledger_before, resource)
        successor_owner = _exact_ledger_claim(observation.ledger_after, resource)
        _ledger_claim_matches_route(
            predecessor_owner, source_binding, source_assignment
        )
        _ledger_claim_matches_route(
            successor_owner, source_binding, source_assignment
        )
        if successor_owner != predecessor_owner:
            raise RuntimeError("transfer rejection changed durable ownership")
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
        if observation.generation_after != observation.source_generation:
            raise RuntimeError("incompatible transfer changed the active generation")
        if "state-format descriptors are incompatible" not in observation.activation_error:
            raise RuntimeError("incompatible transfer failed for another reason")
        _same_foreign_observation(
            observation.foreign_before,
            observation.foreign_before,
            observation.foreign_after,
        )
        if observation.live_before != observation.live_after:
            raise RuntimeError("incompatible transfer changed live provider state")

        source_authority = _current_authority(
            observation.source_authority, bundle["plan"], observation.transaction
        )
        source_binding, source_assignment = _exact_authorized_route(
            source_authority, operation
        )
        source_owner = _exact_ledger_claim(
            observation.ledger_before, operation["target"]["resource"]
        )
        owner_after = _exact_ledger_claim(
            observation.ledger_after, operation["target"]["resource"]
        )
        _ledger_claim_matches_route(source_owner, source_binding, source_assignment)
        if owner_after != source_owner:
            raise RuntimeError("incompatible transfer changed the sole owner")

        policy = observation.candidate_policy
        authority = policy.get("transition_authority")
        if (
            policy.get("schema") != "aos.ability.authenticated-policy-set/v1"
            or not isinstance(authority, dict)
            or authority.get("current_planning")
            != bundle.get("desired", {}).get("snapshot_digest")
        ):
            raise RuntimeError("incompatible transfer lacks transition authority")
        adoptions = authority.get("provider_adoptions", [])
        resource = operation["target"]["resource"]
        matches = [
            adoption for adoption in adoptions if adoption.get("resource") == resource
        ]
        if len(matches) != 1:
            raise RuntimeError("incompatible transfer lacks one exact adoption")
        adoption = matches[0]
        source = adoption.get("source", {})
        candidate = adoption.get("candidate", {})
        source_format = source.get("state_format")
        candidate_format = candidate.get("state_format")
        if (
            source_format is None
            or candidate_format is None
            or source_format.get("descriptor") == candidate_format.get("descriptor")
            or source.get("handler_method") != operation["method"]
            or candidate.get("handler_method") != operation["method"]
            or source.get("handler_incarnation")
            == candidate.get("handler_incarnation")
        ):
            raise RuntimeError("incompatible transfer endpoints are not exact")

        dependency_edge = _exact_dependent(
            bundle, operation_identity, observation.dependent_operation
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
        if operation["target"]["interface"] != cell["interface"]:
            raise RuntimeError("provider-state operation targets another interface")
        if (
            operation["target"]["lifetime"]
            != self._contracts[cell["adapter"]]["resource_lifetime"]
        ):
            raise RuntimeError("provider-state operation differs from its contract lifetime")
        return cell, bundle, operation, _operation_identity(operation, ordinal)

    def _store(
        self,
        cell_id: str,
        subject: dict[str, Any],
        evidence: dict[str, Any],
        probes: dict[str, Any],
    ) -> None:
        expected = set(self._cells[cell_id]["postconditions"])
        if set(probes) != expected:
            raise RuntimeError("provider-state probes differ from matrix postconditions")
        evidence_bytes = canonical(evidence)
        subject["evidence-digest"] = sha256_bytes(evidence_bytes)
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
    if not isinstance(provider_implementation, dict):
        raise RuntimeError("provider-state subject lacks an implementation identity")
    return subject


def _ordered_generations(source: int, candidate: int) -> None:
    if isinstance(source, bool) or isinstance(candidate, bool):
        raise RuntimeError("provider-state generations are not integers")
    if not isinstance(source, int) or not isinstance(candidate, int):
        raise RuntimeError("provider-state generations are not integers")
    if source <= 0 or candidate <= source:
        raise RuntimeError("candidate generation does not follow its source")


def _retained_generation_transition(
    retained: int, predecessor: int, activated: int
) -> None:
    if any(isinstance(value, bool) for value in (retained, predecessor, activated)):
        raise RuntimeError("retained-target generations are not integers")
    if not all(isinstance(value, int) for value in (retained, predecessor, activated)):
        raise RuntimeError("retained-target generations are not integers")
    if retained <= 0 or predecessor <= retained or activated != retained:
        raise RuntimeError("activation did not select the exact retained generation")


def _current_authority(
    authority: dict[str, Any],
    expected_plan: str | None,
    expected_transaction: str | None,
) -> dict[str, Any]:
    required = {
        "schema",
        "authority_epoch",
        "policy_fence",
        "policy_revision",
        "resolution_policy",
        "sequence",
        "observed_at_restart_millis",
        "plan",
        "bindings",
        "provider_assignments",
        "resource_observations",
    }
    if not isinstance(authority, dict) or not required <= set(authority):
        raise RuntimeError("current provider authority is malformed")
    if any(
        not isinstance(authority[field], list)
        or len(authority[field]) > MAX_RETAINED_ENTRIES
        for field in ("bindings", "provider_assignments", "resource_observations")
    ):
        raise RuntimeError("current provider authority exceeds its entry bounds")
    if authority["schema"] != "aos.ability.current-authority/v1":
        raise RuntimeError("current provider authority has another schema")
    if expected_plan is not None and authority["plan"] != expected_plan:
        raise RuntimeError("current provider authority names another plan")
    if (
        expected_transaction is not None
        and authority.get("transaction") != expected_transaction
    ):
        raise RuntimeError("current provider authority names another transaction")
    if (
        not isinstance(authority["sequence"], int)
        or authority["sequence"] <= 0
        or not isinstance(authority["authority_epoch"], int)
        or authority["authority_epoch"] <= 0
    ):
        raise RuntimeError("current provider authority has no monotonic identity")
    return authority


def _fresh_receiving_authority(
    source: dict[str, Any], candidate: dict[str, Any]
) -> None:
    source_scope = (source["plan"], source.get("transaction"))
    candidate_scope = (candidate["plan"], candidate.get("transaction"))
    if source_scope == candidate_scope:
        raise RuntimeError("candidate authority reused the predecessor scope")
    if canonical(source) == canonical(candidate):
        raise RuntimeError("candidate authority reused the predecessor document")
    if candidate["sequence"] <= source["sequence"]:
        raise RuntimeError("candidate authority sequence did not advance")
    if candidate["observed_at_restart_millis"] < source[
        "observed_at_restart_millis"
    ]:
        raise RuntimeError("candidate authority predates the predecessor observation")


def _exact_resource_observation(
    authority: dict[str, Any], operation: dict[str, Any], *, usable: bool
) -> dict[str, Any]:
    resource = operation["target"]["resource"]
    matches = [
        observation
        for observation in authority["resource_observations"]
        if observation.get("resource") == resource
    ]
    if len(matches) != 1:
        raise RuntimeError("current authority lacks one exact resource observation")
    state = matches[0].get("state")
    allowed_states = (
        {"present", "stopped"}
        if usable
        else {"absent", "present", "stopped"}
    )
    if not isinstance(state, dict) or state.get("state") not in allowed_states:
        raise RuntimeError("current authority has an inadmissible target state")
    return matches[0]


def _exact_dependent(
    bundle: dict[str, Any],
    operation: dict[str, Any],
    dependent: dict[str, Any],
) -> dict[str, Any]:
    effect = bundle["transition"]["effect_document"]
    edges = [
        edge
        for edge in effect["edges"]
        if edge.get("from") == {"kind": "operation", "key": operation["key"]}
        and edge.get("to", {}).get("kind") == "operation"
        and edge.get("kind") == "required-success"
    ]
    candidates = [
        (_operation_identity(candidate, ordinal), edge)
        for edge in edges
        for ordinal, candidate in enumerate(effect["operations"])
        if candidate["key"] == edge["to"]["key"]
    ]
    matches = [edge for identity, edge in candidates if identity == dependent]
    if len(matches) != 1:
        raise RuntimeError("observation lacks an exact required-success dependent")
    return matches[0]


def _exact_authorized_route(
    authority: dict[str, Any], operation: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    matches = [
        binding
        for binding in authority["bindings"]
        if binding["id"] == operation["binding"]
    ]
    if len(matches) != 1:
        raise RuntimeError("current authority lacks the exact operation binding")
    binding = matches[0]
    _validate_binding_route(binding, operation)
    return binding, _exact_assignment(authority, binding)


def _unique_authorized_route(
    authority: dict[str, Any], operation: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    matches = []
    for binding in authority["bindings"]:
        try:
            _validate_binding_route(binding, operation)
        except RuntimeError:
            continue
        matches.append(binding)
    if len(matches) != 1:
        raise RuntimeError("source authority lacks one exact method/resource route")
    return matches[0], _exact_assignment(authority, matches[0])


def _validate_binding_route(
    binding: dict[str, Any], operation: dict[str, Any]
) -> None:
    if (
        binding.get("interface") != operation["interface"]
        or operation["method"] not in binding.get("caller_grant", {}).get("methods", [])
    ):
        raise RuntimeError("authority binding names another method route")
    permissions = [
        permission
        for permission in binding["caller_grant"].get("resources", [])
        if permission.get("resource") == operation["target"]["resource"]
        and operation["method"] in permission.get("operations", [])
    ]
    if len(permissions) != 1:
        raise RuntimeError("authority binding lacks the exact resource grant")


def _exact_assignment(
    authority: dict[str, Any], binding: dict[str, Any]
) -> dict[str, Any]:
    matches = [
        assignment
        for assignment in authority["provider_assignments"]
        if assignment.get("provider") == binding["provider"]
        and assignment.get("interface") == binding["interface"]
        and assignment.get("implementation") == binding["implementation"]
    ]
    if len(matches) != 1 or not matches[0].get("incarnation"):
        raise RuntimeError("current authority lacks one exact live provider assignment")
    return matches[0]


def _assignment_core(assignment: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": assignment["provider"],
        "interface": assignment["interface"],
        "implementation": assignment["implementation"],
    }


def _route_owner(
    binding: dict[str, Any], assignment: dict[str, Any]
) -> dict[str, Any]:
    return {
        "binding": binding["id"],
        "provider-package": binding["provider_package"],
        "provider": assignment["provider"],
        "interface": assignment["interface"],
        "implementation": assignment["implementation"],
        "incarnation": assignment["incarnation"],
        "policy-revision": binding["policy_revision"],
    }


def _owner_core(owner: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in owner.items() if key != "incarnation"}


def _ledger_claim_core(owner: dict[str, Any]) -> dict[str, Any]:
    """Returns stable physical, logical, provider, and handler ownership."""

    if owner["kind"] == "provider-owner":
        record = owner["record"]
        return {
            "kind": owner["kind"],
            **{
                key: record.get(key)
                for key in ("resource", "physical", "identity", "handler")
            },
        }
    return {
        "kind": owner["kind"],
        **owner["identity"],
    }


def _ledger_claim_matches_route(
    owner: dict[str, Any],
    binding: dict[str, Any],
    assignment: dict[str, Any],
) -> None:
    """Requires the durable owner row to name the authenticated terminal route."""

    if owner["kind"] == "terminal-consumer":
        matches = [
            consumer
            for consumer in owner["records"]
            if consumer.get("binding") == binding["id"]
            and consumer.get("provider") == assignment["provider"]
        ]
        if not matches:
            raise RuntimeError(
                "durable consumer claim names another authenticated handler route"
            )
        return

    record = owner["record"]
    expected_handler = {
        "package": binding["provider_package"],
        "provider": assignment["provider"],
        "interface": assignment["interface"],
        "implementation": assignment["implementation"],
    }
    if record.get("handler") != expected_handler:
        raise RuntimeError("durable owner names another authenticated handler route")


def _at_most_one_ledger_owner(
    ledger: dict[str, Any], resource: dict[str, Any]
) -> None:
    if (
        not isinstance(ledger, dict)
        or ledger.get("schema") != "aos.ability.native-resource-ledger/v1"
        or not isinstance(ledger.get("owners"), list)
        or not isinstance(ledger.get("consumers"), list)
        or len(ledger["owners"]) > MAX_RETAINED_ENTRIES
        or len(ledger["consumers"]) > MAX_RETAINED_ENTRIES
    ):
        raise RuntimeError("native provider ledger is malformed")
    owners = _ledger_owners(ledger, resource)
    if len(owners) > 1:
        raise RuntimeError("native provider ledger admits multiple resource owners")


def _exact_ledger_claim(
    ledger: dict[str, Any], resource: dict[str, Any]
) -> dict[str, Any]:
    """Returns the sole durable provider or terminal claim for a resource."""

    _at_most_one_ledger_owner(ledger, resource)
    owners = _ledger_owners(ledger, resource)
    consumers = [
        consumer
        for consumer in ledger["consumers"]
        if consumer.get("logical") == resource
    ]
    if owners:
        if consumers and any(
            consumer.get("physical") != owners[0].get("physical")
            for consumer in consumers
        ):
            raise RuntimeError("provider owner and terminal consumer claims disagree")
        return {"kind": "provider-owner", "record": owners[0]}
    if not consumers:
        raise RuntimeError("native provider ledger lacks one exact resource claim")

    identities = {
        canonical(
            {
                "logical": consumer.get("logical"),
                "physical": consumer.get("physical"),
                "owner": consumer.get("owner"),
                "provider": consumer.get("provider"),
            }
        )
        for consumer in consumers
    }
    if len(identities) != 1:
        raise RuntimeError("native resource has conflicting terminal consumer claims")
    return {
        "kind": "terminal-consumer",
        "identity": json.loads(next(iter(identities))),
        "records": consumers,
    }


def _ledger_owners(
    ledger: dict[str, Any], resource: dict[str, Any]
) -> list[dict[str, Any]]:
    return [owner for owner in ledger["owners"] if owner.get("resource") == resource]


def _exact_resource_revision(
    bundle: dict[str, Any],
    field: str,
    resource: dict[str, Any],
    *,
    required: bool,
) -> dict[str, Any] | None:
    revisions = [
        revision
        for revision in bundle["transition"]["effect_document"][field]
        if revision.get("resource") == resource
    ]
    if len(revisions) > 1 or (required and len(revisions) != 1):
        raise RuntimeError(f"plan has an invalid exact {field} resource revision")
    return revisions[0] if revisions else None


def _same_foreign_observation(before: Any, unsettled: Any, after: Any) -> None:
    if before != unsettled or before != after:
        raise RuntimeError("foreign provider resource changed across recovery")


def _first_effect_boundary(timeline: list[dict[str, Any]]) -> str | None:
    return next(
        (
            event.get("boundary")
            for event in timeline
            if event.get("purpose") == "effect"
        ),
        None,
    )


def _probe(kind: str, disposition: str, observations: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": kind,
        "disposition": disposition,
        "detail": "Production provider-state evidence for the exact checked matrix operation.",
        "observations": observations,
    }
