"""Shared canonical primitives for native-adapter evidence validators."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


PROBE_SCHEMA = "aos.release.native-adapter-postcondition-probe/v1"

CELL_SUBJECT_SCHEMA = "aos.release.native-adapter-cell-cohort-subject/v1"

TOKEN = re.compile(r"[a-z0-9.-]{1,96}").fullmatch

LOCAL_KEY = re.compile(r"[A-Za-z0-9._-]{1,128}").fullmatch

DIGEST = re.compile(r"sha256:[0-9a-f]{64}").fullmatch

RAW_DIGEST = re.compile(r"[0-9a-f]{64}").fullmatch

MAX_PROBE_FACTS = 32

MAX_PROBE_BYTES = 64 * 1024

SCENARIO_DISPOSITIONS = {
    "interrupt-before-acquisition": "rejected-before-acquisition",
    "interrupt-after-acquisition": "unsettled-after-acquisition",
    "interrupt-after-durable-intent": "reconciled-after-interruption",
    "lose-external-result": "reconciled-completed",
    "interrupt-after-durable-outcome": "completed-before-interruption",
    "expire-attempt-deadline": "deadline-exceeded-retains-ownership",
    "fail-cleanup": "cleanup-failed-retains-ownership",
    "fail-release": "release-failed-retains-ownership",
    "revoke-caller-before-acquisition": "rejected-before-effect",
    "revoke-caller-after-acquisition": "rejected-before-effect",
    "revoke-caller-before-external-effect": "rejected-before-effect",
    "revoke-provider-before-acquisition": "rejected-before-effect",
    "revoke-provider-after-acquisition": "rejected-before-effect",
    "revoke-provider-before-external-effect": "rejected-before-effect",
    "revoke-enforcement-before-acquisition": "rejected-before-effect",
    "revoke-enforcement-after-acquisition": "rejected-before-effect",
    "revoke-enforcement-before-external-effect": "rejected-before-effect",
    "revoke-assignment-before-acquisition": "rejected-before-effect",
    "revoke-assignment-after-acquisition": "rejected-before-effect",
    "revoke-assignment-before-external-effect": "rejected-before-effect",
    "replace-executor-incarnation": "stale-executor-rejected",
    "replace-provider-incarnation": "stale-provider-rejected",
    "adopt-compatible-state": "compatible-state-adopted",
    "reject-unsupported-transfer": "transfer-rejected-before-effect",
    "activate-retained-target": "retained-target-activated",
    "block-dependent-effect": "dependent-effect-blocked",
    "reject-foreign-resource-mutation": "foreign-mutation-rejected",
}


def _postcondition_kind(cell: dict[str, Any], name: str) -> str:
    """Returns the evidence kind projected from the scenario policy."""

    postconditions = cell.get("postconditions")
    kinds = cell.get("postcondition_kinds")
    if (
        not isinstance(postconditions, list)
        or not isinstance(kinds, dict)
        or set(kinds) != set(postconditions)
        or not isinstance(kinds.get(name), str)
        or not kinds[name]
    ):
        raise RuntimeError("matrix cell postcondition policy is malformed")
    return kinds[name]

def _adapter_claim(spec: dict[str, Any], adapter_name: str) -> dict[str, Any]:
    """Returns one generated typed provider claim from the matrix surface."""

    adapters = spec.get("surface", {}).get("adapters", [])
    matches = [
        adapter
        for adapter in adapters
        if isinstance(adapter, dict) and adapter.get("adapter") == adapter_name
    ]
    if len(matches) != 1:
        raise RuntimeError("matrix surface lacks one exact adapter claim")
    return matches[0]

def _adapter_claim_by_interface(
    spec: dict[str, Any], interface_name: Any
) -> dict[str, Any]:
    """Resolves one generated provider claim by its selected interface name."""

    adapters = spec.get("surface", {}).get("adapters", [])
    matches = [
        adapter
        for adapter in adapters
        if isinstance(adapter, dict)
        and adapter.get("interface_name") == interface_name
    ]
    if len(matches) != 1:
        raise RuntimeError("matrix surface lacks one exact interface claim")
    return matches[0]

def _observer_result_value(adapter_claim: dict[str, Any], field: str) -> str:
    """Returns one closed value from the package-owned observer result type."""

    descriptor = adapter_claim.get("provider_implementation", {}).get("observer", {})
    result_field = descriptor.get("result", {}).get("fields", {}).get(field, {})
    values = result_field.get("values")
    if result_field.get("kind") != "string-enum" or not isinstance(values, list):
        raise RuntimeError("matrix observer result is not a closed typed descriptor")
    if len(values) != 1 or not _matches(LOCAL_KEY, values[0]):
        raise RuntimeError("matrix observer result does not select one value")
    return values[0]

def canonical(value: Any) -> bytes:
    """Encodes one value in the canonical JSON dialect used by evidence."""

    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()

def sha256(value: Any) -> str:
    """Computes the raw canonical SHA-256 identity of one value."""

    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()

def _cell_scenario(cell: dict[str, Any]) -> str:
    """Returns the scenario suffix carried by an exact matrix cell."""

    return cell["id"].rsplit("/", 1)[-1]

def _bound_cohort_subject(
    cell: dict[str, Any], cohort_subject: dict[str, Any]
) -> dict[str, Any]:
    """Binds the dynamic production subject to one immutable matrix cell."""

    return {
        "schema": CELL_SUBJECT_SCHEMA,
        "cell_id": cell["id"],
        "cell_digest": sha256(cell),
        "boundary": cell["boundary"],
        "failure": cell["failure"],
        "candidate": cell["candidate"],
        "predecessor": cell["predecessor"],
        "subject": cohort_subject,
    }

def _expected_disposition(
    cell: dict[str, Any], cohort_subject: dict[str, Any] | None = None
) -> str:
    scenario = cell["id"].rsplit("/", 1)[-1]
    if scenario == "cancel-unsettled-attempt":
        if cohort_subject is None or "cancel-route" not in cohort_subject:
            raise RuntimeError(
                "cancellation disposition requires its concrete operation route"
            )
        if cohort_subject["cancel-route"] is None:
            return "unsupported-cancellation-retains-ownership"
        return "cancelled-after-reconciliation"
    try:
        return SCENARIO_DISPOSITIONS[scenario]
    except KeyError as error:
        raise RuntimeError("matrix cell has no expected disposition") from error

def _scoped_operation_key(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"scope", "key"}
        and isinstance(value.get("scope"), list)
        and all(_matches(LOCAL_KEY, segment) for segment in value["scope"])
        and _matches(LOCAL_KEY, value.get("key"))
    )

def _operation_key(value: Any) -> bool:
    return isinstance(value, dict) and isinstance(value.get("key"), dict)

def _distinct_nonempty_strings(left: Any, right: Any) -> bool:
    return (
        isinstance(left, str)
        and bool(left)
        and isinstance(right, str)
        and bool(right)
        and left != right
    )

def _strictly_increasing_nonnegative(before: Any, after: Any) -> bool:
    return _is_nonnegative_int(before) and _is_nonnegative_int(after) and before < after

def _effect_boundary_policy(authority: Any) -> dict[str, Any]:
    """Validates one retained generation's exact authenticated native policy."""

    if not isinstance(authority, dict) or set(authority) != {
        "generation",
        "manifest-path",
        "policy-pin",
        "policy-document",
    }:
        raise RuntimeError("effect-boundary generation authority is malformed")
    policy = authority["policy-document"]
    pin = authority["policy-pin"]
    policy_bytes = canonical(policy)
    if (
        not _is_nonnegative_int(authority.get("generation"))
        or not isinstance(authority.get("manifest-path"), str)
        or not isinstance(pin, dict)
        or not isinstance(policy, dict)
        or policy.get("schema") != "aos.ability.authenticated-policy-set/v1"
        or pin.get("document_sha256")
        != "sha256:" + hashlib.sha256(policy_bytes).hexdigest()
        or pin.get("document_size") != len(policy_bytes)
        or policy.get("native_resource_map", {}).get("schema")
        != "aos.ability.native-resource-map/v1"
    ):
        raise RuntimeError("effect-boundary generation authority is not exact")
    return policy

def _effect_boundary_native_route(
    bundle: dict[str, Any],
    operation: dict[str, Any],
    implementation: dict[str, Any],
    source_authority: dict[str, Any],
    candidate_authority: dict[str, Any],
) -> dict[str, Any]:
    """Rebuilds the authoritative resource route used by NativeDispatcher."""

    source_policy = _effect_boundary_policy(source_authority)
    candidate_policy = _effect_boundary_policy(candidate_authority)
    transition_authority = bundle.get("transition_authority") or {}
    teardown = [
        entry
        for entry in transition_authority.get("teardown_bindings", [])
        if entry.get("binding", {}).get("id") == operation["binding"]
    ]
    if len(teardown) > 1:
        raise RuntimeError("effect-boundary teardown route is ambiguous")
    if teardown:
        role = "current"
        authority = source_authority
        policy = source_policy
        binding = teardown[0]["source_binding"]
    else:
        role = "desired"
        authority = candidate_authority
        policy = candidate_policy
        binding = operation["binding"]
    resource_map = policy["native_resource_map"]
    mappings = [
        mapping
        for mapping in resource_map["entries"]
        if mapping.get("resource") == operation["target"]["resource"]
        and mapping.get("binding") == binding
    ]
    if len(mappings) != 1 or mappings[0].get("implementation") != implementation:
        raise RuntimeError("effect-boundary native route is absent or ambiguous")
    return {
        "authority-role": role,
        "generation": authority["generation"],
        "policy-document-sha256": sha256(policy),
        "resource-map-desired-state": resource_map["desired_state"],
        "source-binding": binding,
        "mapping": mappings[0],
    }

def _is_ordered_operation_timeline(value: Any, ordinal: int) -> bool:
    if not isinstance(value, list) or not value:
        return False
    sequences = []
    for event in value:
        if (
            not isinstance(event, dict)
            or set(event) != {"sequence", "kind", "node-ordinal"}
            or event.get("node-ordinal") != ordinal
            or not _is_nonnegative_int(event.get("sequence"))
            or not isinstance(event.get("kind"), str)
            or not event["kind"]
        ):
            return False
        sequences.append(event["sequence"])
    return sequences == sorted(set(sequences))

def _single_owner_inventory(inventory: Any) -> bool:
    """Validates one bounded authoritative ownership inventory."""

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

def _is_ordered_boundary_timeline(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    positions = []
    for event in value:
        if (
            not isinstance(event, dict)
            or set(event) != {"transcript-position", "purpose", "boundary"}
            or not _is_nonnegative_int(event.get("transcript-position"))
            or event.get("purpose") not in {"effect", "reconcile", "cancel"}
            or not isinstance(event.get("boundary"), str)
            or not event["boundary"]
        ):
            return False
        positions.append(event["transcript-position"])
    return positions == sorted(set(positions))

def _required_success_dependents(
    effect_document: dict[str, Any], operation: dict[str, Any]
) -> list[dict[str, Any]]:
    """Projects exact required-success successors for one planned operation."""

    operations = effect_document["operations"]
    by_key = {
        canonical(candidate["key"]): _project_operation(candidate, ordinal)
        for ordinal, candidate in enumerate(operations)
    }
    if len(by_key) != len(operations):
        raise RuntimeError("checked plan repeats an operation key")

    dependent_keys = [
        edge["to"]["key"]
        for edge in effect_document["edges"]
        if edge.get("kind") == "required-success"
        and edge.get("from") == {"kind": "operation", "key": operation["key"]}
        and edge.get("to", {}).get("kind") == "operation"
    ]
    try:
        return [by_key[canonical(key)] for key in dependent_keys]
    except KeyError as error:
        raise RuntimeError("checked plan dependency names an unknown operation") from error

def _canonical_evidence(evidence_bytes: Any, label: str) -> dict[str, Any]:
    if not isinstance(evidence_bytes, bytes):
        raise RuntimeError(f"{label} evidence is not an exact byte string")
    try:
        value = json.loads(evidence_bytes)
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"{label} evidence is not JSON") from error
    if not isinstance(value, dict) or canonical(value) != evidence_bytes:
        raise RuntimeError(f"{label} evidence is not canonical JSON")
    return value

def _project_operation(value: Any, ordinal: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError("cohort effect operation is malformed")
    return {
        "key": value["key"],
        "ordinal": ordinal,
        "interface": value["interface"],
        "method": value["method"],
        "target": value["target"],
    }

def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0

def _matches(pattern: Any, value: Any) -> bool:
    return isinstance(value, str) and pattern(value) is not None
