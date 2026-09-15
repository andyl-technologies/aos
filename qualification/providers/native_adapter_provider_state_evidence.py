"""Validates provider-state transfer and adoption evidence."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from native_adapter_evidence_common import (
    CELL_SUBJECT_SCHEMA,
    DIGEST,
    LOCAL_KEY,
    PROBE_SCHEMA,
    RAW_DIGEST,
    SCENARIO_DISPOSITIONS,
    _adapter_claim,
    _adapter_claim_by_interface,
    _bound_cohort_subject,
    _canonical_evidence,
    _cell_scenario,
    _distinct_nonempty_strings,
    _effect_boundary_native_route,
    _effect_boundary_policy,
    _expected_disposition,
    _is_nonnegative_int,
    _is_ordered_boundary_timeline,
    _is_ordered_operation_timeline,
    _matches,
    _observer_result_value,
    _operation_key,
    _postcondition_kind,
    _project_operation,
    _required_success_dependents,
    _scoped_operation_key,
    _single_owner_inventory,
    _strictly_increasing_nonnegative,
    canonical,
    sha256,
)



PROVIDER_STATE_COHORT_SUBJECT_SCHEMA = (
    "aos.qualification.native-adapter-provider-state-subject/v1"
)

PROVIDER_STATE_EVIDENCE_SCHEMA = (
    "aos.qualification.native-adapter-provider-state-evidence/v1"
)

PROVIDER_STATE_TRANSFER_CONTRACT_SCHEMA = (
    "aos.ability.provider-state-transfer-contract/v1"
)

def _cancellation_oracle_kinds(spec: dict[str, Any]) -> set[str]:
    """Returns live-state kinds from package-owned observer descriptors."""

    return {
        _observer_result_value(adapter, "kind")
        for adapter in spec.get("surface", {}).get("adapters", [])
        if isinstance(adapter, dict)
    }

def _validate_provider_state_subject(
    cell: dict[str, Any],
    subject: Any,
    evidence_bytes: Any,
    matrix_spec: dict[str, Any] | None,
) -> None:
    """Rebuilds a provider-state subject from its production flight evidence."""

    if matrix_spec is None:
        raise RuntimeError("provider-state validation lacks its matrix specification")

    evidence = _canonical_evidence(evidence_bytes, "provider-state flight")
    scenario = _cell_scenario(cell)
    incompatible_rejection = (
        evidence.get("rejection-kind")
        == "incompatible-authenticated-state-format"
    )
    common_evidence_fields = {
        "schema",
        "scenario",
        "plan-bundle",
        "source-authority",
        "ledger-before",
        "ledger-after",
        "live-before",
        "live-after",
        "foreign-before",
        "foreign-after",
        "boundary-timeline",
        "dependent-operation",
    }
    if scenario == "activate-retained-target":
        expected_evidence_fields = common_evidence_fields | {
            "journal-before-loss",
            "authority-before",
            "authority-after",
            "ledger-unsettled",
            "live-unsettled",
            "foreign-unsettled",
            "timeline",
            "dependent-before",
            "dependent-after",
            "current-revision",
            "desired-revision",
        }
        expected_subject_fields = {
            "schema",
            "cell-id",
            "cell-digest",
            "plan",
            "plan-bundle-digest",
            "evidence-digest",
            "transaction",
            "adapter",
            "operation",
            "dependent-operation",
            "dependency-edge",
            "provider-implementation",
            "generations",
        }
    elif scenario == "adopt-compatible-state":
        expected_evidence_fields = common_evidence_fields | {
            "transfer-contract",
            "journal-before-loss",
            "timeline",
            "candidate-authority",
            "ledger-unsettled",
            "live-unsettled",
            "foreign-unsettled",
            "dependent-after",
        }
        expected_subject_fields = {
            "schema",
            "cell-id",
            "cell-digest",
            "plan",
            "plan-bundle-digest",
            "evidence-digest",
            "transaction",
            "adapter",
            "operation",
            "dependent-operation",
            "dependency-edge",
            "provider-implementation",
            "generations",
            "transfer-contract-digest",
        }
    elif scenario == "reject-unsupported-transfer":
        if incompatible_rejection:
            expected_evidence_fields = common_evidence_fields | {
                "rejection-kind",
                "candidate-policy",
                "activation-error",
                "dependent-timeline",
            }
        else:
            expected_evidence_fields = common_evidence_fields | {
                "transfer-contract",
                "journal-at-rejection",
                "timeline-at-rejection",
                "candidate-authority",
                "dependent-timeline",
            }
        expected_subject_fields = {
            "schema",
            "cell-id",
            "cell-digest",
            "plan",
            "plan-bundle-digest",
            "evidence-digest",
            "transaction",
            "adapter",
            "operation",
            "dependent-operation",
            "dependency-edge",
            "provider-implementation",
            "generations",
            "transfer-contract-digest",
        }
    else:
        raise RuntimeError("provider-state cohort names another scenario")

    try:
        if (
            not isinstance(evidence, dict)
            or set(evidence) != expected_evidence_fields
            or evidence.get("schema") != PROVIDER_STATE_EVIDENCE_SCHEMA
            or evidence.get("scenario") != scenario
            or not isinstance(subject, dict)
            or set(subject) != expected_subject_fields
        ):
            raise RuntimeError("provider-state evidence or subject is malformed")
        bundle = evidence["plan-bundle"]
        operation = subject["operation"]
        effect = bundle["transition"]["effect_document"]
        operation_document = effect["operations"][operation["ordinal"]]
        if _project_operation(operation_document, operation["ordinal"]) != operation:
            raise RuntimeError("provider-state operation is absent from its plan")
        dependents = _required_success_dependents(effect, operation)
        dependent = subject["dependent-operation"]
        if dependent not in dependents:
            raise RuntimeError("provider-state successor is not RequiredSuccess")
        bindings = [
            binding
            for state in (bundle.get("desired"), bundle.get("current"))
            if state is not None
            for binding in state["snapshot"]["resolution"]["binding_document"]["bindings"]
            if binding["id"] == operation_document["binding"]
        ]
        implementations = {
            canonical(binding["implementation"]): binding["implementation"]
            for binding in bindings
        }
        if len(implementations) != 1:
            raise RuntimeError("provider-state implementation is ambiguous")
        implementation = next(iter(implementations.values()))
    except RuntimeError:
        raise
    except (AttributeError, IndexError, KeyError, TypeError) as error:
        raise RuntimeError("provider-state plan evidence is malformed") from error

    expected_edge = {
        "from": {"kind": "operation", "key": operation["key"]},
        "to": {"kind": "operation", "key": dependent["key"]},
        "kind": "required-success",
    }
    generations = subject["generations"]
    if (
        subject["schema"] != PROVIDER_STATE_COHORT_SUBJECT_SCHEMA
        or subject["cell-id"] != cell["id"]
        or subject["cell-digest"] != sha256(cell)
        or subject["plan"] != bundle.get("plan")
        or subject["plan-bundle-digest"] != sha256(bundle)
        or subject["evidence-digest"]
        != "sha256:" + hashlib.sha256(evidence_bytes).hexdigest()
        or subject["adapter"] != cell["adapter"]
        or operation.get("interface") != cell["interface"]
        or operation.get("method") != cell["method"]
        or operation.get("target", {}).get("interface") != cell["interface"]
        or evidence["dependent-operation"] != dependent
        or subject["dependency-edge"] != expected_edge
        or expected_edge not in effect["edges"]
        or subject["provider-implementation"] != implementation
        or not isinstance(subject.get("transaction"), str)
        or not subject["transaction"]
        or not isinstance(generations, dict)
    ):
        raise RuntimeError("provider-state subject differs from its exact matrix route")

    if matrix_spec is None:
        raise RuntimeError("provider-state evidence has no matrix provider contract")
    adapters = matrix_spec.get("surface", {}).get("adapters")
    if not isinstance(adapters, list):
        raise RuntimeError("provider-state evidence has no matrix provider contract")
    provider_contracts = {
        adapter.get("adapter"): adapter.get("provider_contract")
        for adapter in adapters
        if isinstance(adapter, dict)
    }
    provider_contract = provider_contracts.get(cell["adapter"])
    if not isinstance(provider_contract, dict):
        raise RuntimeError("provider-state evidence has no matrix provider contract")
    expected_lifetime = provider_contract.get("resource_lifetime")
    if operation_document.get("target", {}).get("lifetime") != expected_lifetime:
        raise RuntimeError("provider-state operation differs from its provider contract")

    live_snapshots = [
        value for name, value in evidence.items() if name.startswith("live-")
    ]
    foreign_snapshots = [
        value for name, value in evidence.items() if name.startswith("foreign-")
    ]
    if (
        not live_snapshots
        or any(
            not _provider_state_oracle_snapshot(matrix_spec, cell["adapter"], snapshot)
            for snapshot in live_snapshots
        )
        or not foreign_snapshots
        or any(
            not isinstance(snapshot, dict)
            or snapshot.get("kind") not in _cancellation_oracle_kinds(matrix_spec)
            for snapshot in foreign_snapshots
        )
    ):
        raise RuntimeError("provider-state evidence lacks its provider-specific oracle")

    source = _provider_state_authority(evidence["source-authority"])
    source_assignment = _provider_state_assignment(source, operation_document)
    if scenario == "activate-retained-target":
        before = _provider_state_authority(evidence["authority-before"])
        after = _provider_state_authority(evidence["authority-after"])
        before_assignment = _provider_state_assignment(before, operation_document)
        after_assignment = _provider_state_assignment(after, operation_document)
        if (
            set(generations) != {"retained", "predecessor", "activated"}
            or generations["retained"] <= 0
            or generations["predecessor"] <= generations["retained"]
            or generations["activated"] != generations["retained"]
            or source["sequence"] >= before["sequence"]
            or before["sequence"] >= after["sequence"]
            or source_assignment["incarnation"] == before_assignment["incarnation"]
            or before_assignment != after_assignment
            or not (
                _provider_state_ledger_claim(
                    evidence["ledger-before"], operation["target"]["resource"]
                )
                == _provider_state_ledger_claim(
                    evidence["ledger-unsettled"], operation["target"]["resource"]
                )
                == _provider_state_ledger_claim(
                    evidence["ledger-after"], operation["target"]["resource"]
                )
            )
            or evidence["foreign-before"] != evidence["foreign-unsettled"]
            or evidence["foreign-before"] != evidence["foreign-after"]
        ):
            raise RuntimeError("retained-target authority or ownership is not monotonic")
    elif scenario == "adopt-compatible-state":
        candidate = _provider_state_authority(evidence["candidate-authority"])
        candidate_assignment = _provider_state_assignment(
            candidate, operation_document
        )
        contract = evidence["transfer-contract"]
        owner = contract.get("disposition", {}).get("owner", {})
        state_format = provider_contract.get("state_format")
        adoptions = bundle.get("transition_authority", {}).get(
            "provider_adoptions", []
        )
        matching_adoptions = [
            adoption
            for adoption in adoptions
            if adoption.get("resource") == operation["target"]["resource"]
        ]
        if len(matching_adoptions) != 1:
            raise RuntimeError("compatible adoption lacks one exact authorization")
        adoption = matching_adoptions[0]
        source_format = adoption.get("source", {}).get("state_format")
        candidate_format = adoption.get("candidate", {}).get("state_format")
        owner_before = _provider_state_ledger_claim(
            evidence["ledger-before"], operation["target"]["resource"]
        )
        owner_unsettled = _provider_state_ledger_claim(
            evidence["ledger-unsettled"], operation["target"]["resource"]
        )
        owner_after = _provider_state_ledger_claim(
            evidence["ledger-after"], operation["target"]["resource"]
        )
        if (
            set(generations) != {"source", "candidate"}
            or generations["source"] <= 0
            or generations["candidate"] <= generations["source"]
            or source["sequence"] >= candidate["sequence"]
            or source_assignment["incarnation"]
            == candidate_assignment["incarnation"]
            or expected_lifetime != "persistent"
            or state_format is None
            or contract.get("schema")
            != PROVIDER_STATE_TRANSFER_CONTRACT_SCHEMA
            or contract.get("plan") != bundle.get("plan")
            or contract.get("operation") != operation_document
            or contract.get("disposition", {}).get("status") != "supported"
            or owner.get("state_format", {}).get("descriptor") != state_format
            or source_format != owner.get("state_format")
            or candidate_format != owner.get("state_format")
            or subject["transfer-contract-digest"] != sha256(contract)
            or _provider_state_claim_core(owner_before)
            == _provider_state_claim_core(owner_after)
            or _provider_state_claim_core(owner_unsettled)
            != _provider_state_claim_core(owner_after)
            or evidence["foreign-before"] != evidence["foreign-unsettled"]
            or evidence["foreign-before"] != evidence["foreign-after"]
            or "effect-completed"
            not in [event.get("kind") for event in evidence["timeline"]]
            or "effect-completed"
            not in [event.get("kind") for event in evidence["dependent-after"]]
        ):
            raise RuntimeError("compatible transfer lacks a real adopted owner")
    elif incompatible_rejection:
        policy = evidence["candidate-policy"]
        authority = policy.get("transition_authority", {})
        adoptions = authority.get("provider_adoptions", [])
        resource = operation["target"]["resource"]
        matching_adoptions = [
            adoption
            for adoption in adoptions
            if adoption.get("resource") == resource
        ]
        if len(matching_adoptions) != 1:
            raise RuntimeError("incompatible transfer lacks one exact adoption")
        adoption = matching_adoptions[0]
        source_endpoint = adoption.get("source", {})
        candidate_endpoint = adoption.get("candidate", {})
        source_format = source_endpoint.get("state_format", {})
        candidate_format = candidate_endpoint.get("state_format", {})
        if (
            policy.get("schema") != "aos.ability.authenticated-policy-set/v1"
            or authority.get("current_planning")
            != bundle.get("desired", {}).get("snapshot_digest")
            or
            set(generations) != {"source", "candidate"}
            or generations["source"] <= 0
            or generations["candidate"] != generations["source"]
            or expected_lifetime != "persistent"
            or provider_contract.get("state_format")
            != source_format.get("descriptor")
            or source_format.get("descriptor")
            == candidate_format.get("descriptor")
            or source_endpoint.get("handler_method") != operation["method"]
            or candidate_endpoint.get("handler_method") != operation["method"]
            or source_endpoint.get("handler_incarnation")
            == candidate_endpoint.get("handler_incarnation")
            or "state-format descriptors are incompatible"
            not in evidence["activation-error"]
            or subject["transfer-contract-digest"] != sha256(authority)
            or _provider_state_ledger_claim(evidence["ledger-before"], resource)
            != _provider_state_ledger_claim(evidence["ledger-after"], resource)
            or evidence["live-before"] != evidence["live-after"]
            or evidence["foreign-before"] != evidence["foreign-after"]
            or evidence["boundary-timeline"] != []
            or evidence["dependent-timeline"] != []
        ):
            raise RuntimeError("incompatible transfer lacks a real pre-effect rejection")
    else:
        expected_reason = (
            "non-persistent-lifetime"
            if expected_lifetime != "persistent"
            else (
                "missing-authenticated-state-format"
                if provider_contract.get("state_format") is None
                else None
            )
        )
        candidate = _provider_state_authority(evidence["candidate-authority"])
        candidate_assignment = _provider_state_assignment(candidate, operation_document)
        contract = evidence["transfer-contract"]
        rejection = contract.get("disposition", {}).get("rejection", {})
        if (
            set(generations) != {"source", "candidate"}
            or generations["source"] <= 0
            or generations["candidate"] <= generations["source"]
            or source["sequence"] >= candidate["sequence"]
            or source_assignment["incarnation"] == candidate_assignment["incarnation"]
            or contract.get("schema") != PROVIDER_STATE_TRANSFER_CONTRACT_SCHEMA
            or contract.get("plan") != bundle.get("plan")
            or contract.get("operation") != operation_document
            or rejection.get("reason") != expected_reason
            or any(
                rejection.get(field) != expected_lifetime
                for field in (
                    "target_lifetime",
                    "request_lifetime",
                    "binding_lifetime",
                )
            )
            or subject["transfer-contract-digest"] != sha256(contract)
            or _provider_state_ledger_claim(
                evidence["ledger-before"], operation["target"]["resource"]
            )
            != _provider_state_ledger_claim(
                evidence["ledger-after"], operation["target"]["resource"]
            )
            or evidence["live-before"] != evidence["live-after"]
            or evidence["foreign-before"] != evidence["foreign-after"]
            or evidence["dependent-timeline"] != []
        ):
            raise RuntimeError("unsupported transfer lacks a real pre-effect rejection")

def _provider_state_authority(value: Any) -> dict[str, Any]:
    """Validates the bounded current-authority subset used by state flights."""

    required = {
        "schema",
        "sequence",
        "plan",
        "bindings",
        "provider_assignments",
        "resource_observations",
    }
    if (
        not isinstance(value, dict)
        or not required <= set(value)
        or value.get("schema") != "aos.ability.current-authority/v1"
        or not _is_nonnegative_int(value.get("sequence"))
        or value["sequence"] == 0
        or any(not isinstance(value.get(field), list) for field in (
            "bindings",
            "provider_assignments",
            "resource_observations",
        ))
    ):
        raise RuntimeError("provider-state current authority is malformed")
    return value

def _provider_state_assignment(
    authority: dict[str, Any], operation: dict[str, Any]
) -> dict[str, Any]:
    """Selects the unique authenticated assignment for an exact operation route."""

    route_bindings = [
        binding
        for binding in authority["bindings"]
        if binding.get("interface") == operation["interface"]
        and operation["method"] in binding.get("caller_grant", {}).get("methods", [])
        and any(
            permission.get("resource") == operation["target"]["resource"]
            and operation["method"] in permission.get("operations", [])
            for permission in binding.get("caller_grant", {}).get("resources", [])
        )
    ]
    assignments = [
        assignment
        for binding in route_bindings
        for assignment in authority["provider_assignments"]
        if assignment.get("provider") == binding.get("provider")
        and assignment.get("interface") == binding.get("interface")
        and assignment.get("implementation") == binding.get("implementation")
        and isinstance(assignment.get("incarnation"), str)
        and assignment["incarnation"]
    ]
    if len(assignments) != 1:
        raise RuntimeError("provider-state authority lacks one exact assignment")
    return assignments[0]

def _provider_state_ledger_claim(ledger: Any, resource: dict[str, Any]) -> Any:
    """Returns one stable physical ownership identity from the production ledger."""

    if (
        not isinstance(ledger, dict)
        or ledger.get("schema") != "aos.ability.native-resource-ledger/v1"
        or not isinstance(ledger.get("owners"), list)
        or not isinstance(ledger.get("consumers"), list)
    ):
        raise RuntimeError("provider-state ownership ledger is malformed")
    owners = [owner for owner in ledger["owners"] if owner.get("resource") == resource]
    if len(owners) > 1:
        raise RuntimeError("provider-state ledger has multiple owners")
    if owners:
        owner = owners[0]
        return {
            "kind": "owner",
            "resource": owner.get("resource"),
            "physical": owner.get("physical"),
            "identity": owner.get("identity"),
            "handler": owner.get("handler"),
        }
    consumers = [
        consumer for consumer in ledger["consumers"]
        if consumer.get("logical") == resource
    ]
    claims = {
        canonical({
            "kind": "consumer",
            "logical": consumer.get("logical"),
            "physical": consumer.get("physical"),
            "owner": consumer.get("owner"),
            "provider": consumer.get("provider"),
        })
        for consumer in consumers
    }
    if len(claims) != 1:
        raise RuntimeError("provider-state ledger lacks one exact resource claim")
    return json.loads(next(iter(claims)))

def _provider_state_claim_core(claim: Any) -> Any:
    """Projects the stable identity from a retained state-flight claim."""

    if not isinstance(claim, dict):
        return None
    if claim.get("kind") == "provider-owner" and isinstance(claim.get("record"), dict):
        record = claim["record"]
        return {
            "kind": claim["kind"],
            "resource": record.get("resource"),
            "physical": record.get("physical"),
            "identity": record.get("identity"),
            "handler": record.get("handler"),
        }
    if claim.get("kind") == "terminal-consumer":
        return {"kind": claim["kind"], "identity": claim.get("identity")}
    return claim

def _provider_state_oracle_snapshot(
    matrix_spec: dict[str, Any], adapter: str, value: Any
) -> bool:
    """Checks that state evidence came from the adapter's live substrate oracle."""

    return (
        isinstance(value, dict)
        and value.get("kind") == _observer_result_value(
            _adapter_claim(matrix_spec, adapter), "kind"
        )
    )

def _validate_provider_state_probe_facts(
    postcondition: str,
    observations: dict[str, Any],
    subject: dict[str, Any],
    cell: dict[str, Any],
    matrix_spec: dict[str, Any],
) -> None:
    """Validates state-family probes against the exact candidate operation."""

    scenario = _cell_scenario(cell)
    operation = subject["operation"]
    resource = operation["target"]["resource"]
    if postcondition == "durable-attempt-state-classified":
        if scenario in {"activate-retained-target", "adopt-compatible-state"}:
            expected = {
                "transaction",
                "plan",
                "operation",
                "journal-before-loss",
                "timeline",
                "boundary-timeline",
                "terminal",
            }
            timeline = observations.get("timeline", [])
            valid = (
                set(observations) == expected
                and observations.get("transaction") == subject["transaction"]
                and observations.get("plan") == subject["plan"]
                and observations.get("operation") == operation
                and _matches(RAW_DIGEST, observations.get("journal-before-loss"))
                and observations.get("terminal") == "complete"
                and "effect-started" in [event.get("kind") for event in timeline]
                and "effect-completed" in [event.get("kind") for event in timeline]
                and any(
                    event.get("boundary") == "resources-acquired"
                    and event.get("purpose") == "effect"
                    for event in observations.get("boundary-timeline", [])
                )
            )
        elif "activation-error" in observations:
            expected = {
                "transaction",
                "plan",
                "operation",
                "activation-error",
                "terminal",
            }
            valid = (
                set(observations) == expected
                and observations.get("transaction") == subject["transaction"]
                and observations.get("plan") == subject["plan"]
                and observations.get("operation") == operation
                and _matches(DIGEST, observations.get("activation-error"))
                and observations.get("terminal") == "rejected-before-effect"
            )
        else:
            expected = {
                "transaction",
                "plan",
                "operation",
                "journal-at-rejection",
                "timeline-at-rejection",
                "transfer-contract",
                "terminal",
            }
            timeline = observations.get("timeline-at-rejection", [])
            valid = (
                set(observations) == expected
                and observations.get("transaction") == subject["transaction"]
                and observations.get("plan") == subject["plan"]
                and observations.get("operation") == operation
                and _matches(RAW_DIGEST, observations.get("journal-at-rejection"))
                and observations.get("transfer-contract")
                == subject.get("transfer-contract-digest")
                and observations.get("terminal") == "rejected-before-effect"
                and bool(timeline)
                and not any(
                    event.get("kind") in {"effect-started", "effect-completed"}
                    for event in timeline
                )
            )
        if not valid:
            raise RuntimeError("provider-state journal facts are invalid")
    elif postcondition == "at-most-one-resource-owner":
        ledgers = [
            value for name, value in observations.items() if name.startswith("ledger-")
        ]
        if (
            observations.get("resource") != resource
            or set(observations)
            not in [
                {"resource", "ledger-before", "ledger-after"},
                {"resource", "ledger-before", "ledger-unsettled", "ledger-after"},
            ]
            or not ledgers
        ):
            raise RuntimeError("provider-state ownership inventory is malformed")
        claims = [_provider_state_ledger_claim(ledger, resource) for ledger in ledgers]
        if scenario == "adopt-compatible-state":
            valid_claims = (
                len(claims) == 3
                and _provider_state_claim_core(claims[0])
                != _provider_state_claim_core(claims[-1])
                and _provider_state_claim_core(claims[1])
                == _provider_state_claim_core(claims[-1])
            )
        else:
            valid_claims = all(claim == claims[0] for claim in claims[1:])
        if not valid_claims:
            raise RuntimeError("provider-state ownership changed during the flight")
    elif postcondition == "foreign-resources-unchanged":
        snapshots = [
            value for name, value in observations.items() if name.startswith("snapshot-")
        ]
        if (
            observations.get("resource") != resource
            or observations.get("unchanged") is not True
            or not snapshots
            or any(
                not isinstance(snapshot, dict)
                or snapshot.get("kind") not in _cancellation_oracle_kinds(matrix_spec)
                for snapshot in snapshots
            )
            or any(snapshot != snapshots[0] for snapshot in snapshots[1:])
        ):
            raise RuntimeError("provider-state foreign resource changed")
    elif postcondition == "dependent-effects-not-executed":
        if (
            set(observations)
            != {"operation", "dependent-operation", "dependent-timeline", "blocked"}
            or observations.get("operation") != operation
            or observations.get("dependent-operation") != subject["dependent-operation"]
            or observations.get("dependent-timeline") != []
            or observations.get("blocked") is not True
        ):
            raise RuntimeError("provider-state dependent was not blocked")
    elif postcondition == "fresh-receiving-authority":
        common_valid = (
            not _matches(DIGEST, observations.get("source-authority"))
            or not _matches(DIGEST, observations.get("candidate-authority"))
            or not _distinct_nonempty_strings(
                observations.get("predecessor-incarnation"),
                observations.get("candidate-incarnation"),
            )
            or observations.get("fresh") is not True
        )
        if "authority-sequence-before" not in observations:
            valid = set(observations) == {
                "source-authority",
                "candidate-authority",
                "predecessor-incarnation",
                "candidate-incarnation",
                "fresh",
            }
        else:
            valid = set(observations) == {
                "source-authority",
                "candidate-authority",
                "predecessor-incarnation",
                "candidate-incarnation",
                "authority-sequence-before",
                "authority-sequence-after",
                "fresh",
            } and _strictly_increasing_nonnegative(
                observations.get("authority-sequence-before"),
                observations.get("authority-sequence-after"),
            )
        if common_valid or not valid:
            raise RuntimeError("provider-state receiving authority is not fresh")
    elif postcondition == "compatible-state-adopted":
        contract = observations.get("contract")
        source_format = observations.get("source-state-format")
        candidate_format = observations.get("candidate-state-format")
        if (
            set(observations)
            != {
                "resource",
                "contract",
                "source-state-format",
                "candidate-state-format",
                "live-before",
                "live-after",
                "adopted",
            }
            or observations.get("resource") != resource
            or not isinstance(contract, dict)
            or contract.get("schema") != PROVIDER_STATE_TRANSFER_CONTRACT_SCHEMA
            or contract.get("disposition", {}).get("status") != "supported"
            or source_format != candidate_format
            or source_format
            != contract.get("disposition", {}).get("owner", {}).get("state_format")
            or not _provider_state_oracle_snapshot(
                matrix_spec, cell["adapter"], observations.get("live-before")
            )
            or not _provider_state_oracle_snapshot(
                matrix_spec, cell["adapter"], observations.get("live-after")
            )
            or observations.get("adopted") is not True
        ):
            raise RuntimeError("provider-state adoption is not compatible and live")
    elif postcondition == "transfer-rejected-before-candidate-effect":
        contract = observations.get("contract")
        if "source-state-format" in observations:
            valid = (
                set(observations)
                == {
                    "candidate-operation",
                    "source-state-format",
                    "candidate-state-format",
                    "candidate-effect-boundaries",
                    "candidate-effect-count",
                    "rejected-before-effect",
                }
                and observations.get("candidate-operation") == operation
                and observations.get("source-state-format")
                != observations.get("candidate-state-format")
                and observations.get("candidate-effect-boundaries") == []
                and observations.get("candidate-effect-count") == 0
                and observations.get("rejected-before-effect") is True
            )
        else:
            valid = (
                set(observations)
                == {
                    "candidate-operation",
                    "contract",
                    "candidate-effect-boundaries",
                    "candidate-effect-count",
                    "rejected-before-effect",
                }
                and observations.get("candidate-operation") == operation
                and isinstance(contract, dict)
                and contract.get("schema")
                == PROVIDER_STATE_TRANSFER_CONTRACT_SCHEMA
                and contract.get("disposition", {}).get("status") == "unsupported"
                and observations.get("candidate-effect-count") == 0
                and observations.get("rejected-before-effect") is True
                and [
                    event.get("boundary")
                    for event in observations.get("candidate-effect-boundaries", [])
                    if event.get("purpose") == "effect"
                ]
                == ["resources-acquired"]
            )
        if not valid:
            raise RuntimeError("provider-state transfer rejection is not pre-effect")
    elif postcondition == "predecessor-remains-sole-owner":
        if (
            set(observations)
            != {
                "resource",
                "predecessor-owner",
                "owners",
                "ledger-owners-before",
                "ledger-owners-after",
                "behavior-before",
                "behavior-after",
            }
            or observations.get("resource") != resource
            or observations.get("owners") != [observations.get("predecessor-owner")]
            or observations.get("ledger-owners-before") != observations.get("owners")
            or observations.get("ledger-owners-after") != observations.get("owners")
            or observations.get("behavior-before") is None
            or not _provider_state_oracle_snapshot(
                matrix_spec, cell["adapter"], observations.get("behavior-before")
            )
            or observations.get("behavior-after") != observations.get("behavior-before")
        ):
            raise RuntimeError("provider-state predecessor ownership was not retained")
    elif postcondition == "current-grants-reauthorized":
        if (
            set(observations)
            != {
                "plan",
                "binding",
                "authority-before",
                "authority-after",
                "source-authority",
                "predecessor-incarnation",
                "candidate-incarnation",
                "authority-sequence-before",
                "authority-sequence-after",
                "reauthorized",
            }
            or observations.get("plan") != subject["plan"]
            or not isinstance(observations.get("binding"), dict)
            or any(
                not _matches(DIGEST, observations.get(name))
                for name in ("authority-before", "authority-after", "source-authority")
            )
            or not _distinct_nonempty_strings(
                observations.get("predecessor-incarnation"),
                observations.get("candidate-incarnation"),
            )
            or not _strictly_increasing_nonnegative(
                observations.get("authority-sequence-before"),
                observations.get("authority-sequence-after"),
            )
            or observations.get("reauthorized") is not True
        ):
            raise RuntimeError("retained target grant was not freshly authorized")
    elif postcondition == "retained-target-identity-preserved":
        if (
            set(observations)
            != {
                "retained-target",
                "activated-target",
                "current-revision",
                "desired-revision",
                "live-before",
                "live-after",
            }
            or observations.get("retained-target") != resource
            or observations.get("activated-target") != resource
            or observations.get("current-revision") is None
            and observations.get("desired-revision") is None
            or not _provider_state_oracle_snapshot(
                matrix_spec, cell["adapter"], observations.get("live-before")
            )
            or not _provider_state_oracle_snapshot(
                matrix_spec, cell["adapter"], observations.get("live-after")
            )
        ):
            raise RuntimeError("retained target identity was not preserved")
    elif postcondition == "exactly-one-resource-owner":
        if scenario == "activate-retained-target":
            expected = {
                "resource",
                "owner-before",
                "owner-unsettled",
                "owner-after",
                "same-owner-core",
                "authorized-route-count",
            }
            owners = [
                observations.get("owner-before"),
                observations.get("owner-unsettled"),
                observations.get("owner-after"),
            ]
            valid = owners[0] is not None and all(
                _provider_state_claim_core(owner)
                == _provider_state_claim_core(owners[0])
                for owner in owners[1:]
            )
        elif scenario == "adopt-compatible-state":
            expected = {
                "resource",
                "candidate-owner",
                "owners",
                "authorized-route-count",
            }
            candidate_owner = observations.get("candidate-owner")
            valid = (
                candidate_owner is not None
                and observations.get("owners") == [candidate_owner]
            )
        else:
            expected = set()
            valid = False
        same_owner = observations.get("same-owner-core")
        if (
            set(observations) != expected
            or observations.get("resource") != resource
            or scenario == "activate-retained-target"
            and same_owner is not True
            or observations.get("authorized-route-count") != 1
            or not valid
        ):
            raise RuntimeError("provider-state route does not have one exact owner")
    else:
        raise RuntimeError("provider-state cohort carries another postcondition")


def accepts_subject(subject: Any) -> bool:
    """Returns whether this module owns the provider-state subject schema."""

    return (
        isinstance(subject, dict)
        and subject.get("schema") == PROVIDER_STATE_COHORT_SUBJECT_SCHEMA
    )


def validate_subject(
    cell: dict[str, Any],
    subject: Any,
    evidence_bytes: Any,
    matrix_spec: dict[str, Any] | None,
    routes: list[dict[str, Any]],
) -> None:
    """Validates one provider-state subject and retained evidence document."""

    del routes
    _validate_provider_state_subject(cell, subject, evidence_bytes, matrix_spec)


def validate_probe(
    postcondition: str,
    observations: dict[str, Any],
    subject: dict[str, Any],
    cell: dict[str, Any],
    matrix_spec: dict[str, Any] | None,
) -> None:
    """Validates one provider-state postcondition observation."""

    if matrix_spec is None:
        raise RuntimeError("provider-state probe lacks its matrix specification")
    _validate_provider_state_probe_facts(
        postcondition, observations, subject, cell, matrix_spec
    )
