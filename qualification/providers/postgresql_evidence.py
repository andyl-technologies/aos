"""Validates PostgreSQL native qualification evidence.

This module owns PostgreSQL plan, state-transfer, and live-resource evidence
interpretation. The provider-neutral aggregator receives only its normalized
validation result.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


LOCAL_KEY = re.compile(r"[A-Za-z0-9._-]{1,128}").fullmatch
DIGEST = re.compile(r"sha256:[0-9a-f]{64}").fullmatch
RAW_DIGEST = re.compile(r"[0-9a-f]{64}").fullmatch
COHORT_SUBJECT_SCHEMA = (
    "aos.qualification.postgresql-provider-replacement-cohort-subject/v1"
)
REJECTION_EVIDENCE_SCHEMA = (
    "aos.qualification.postgresql-provider-rejection-evidence/v1"
)
ORDERED_METHOD_EVIDENCE_SCHEMA = (
    "aos.qualification.postgresql-ordered-method-evidence/v1"
)
VALIDATION_RESULT_SCHEMA = "aos.qualification.provider-evidence-validation/v1"

def canonical(value: Any) -> bytes:
    """Encodes one value in the canonical evidence JSON dialect."""

    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _matches(pattern: Any, value: Any) -> bool:
    return isinstance(value, str) and pattern(value) is not None


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


def _claim_interface(adapter_claim: dict[str, Any]) -> dict[str, Any]:
    """Projects an interface identity from one generated adapter claim."""

    return {
        "name": adapter_claim.get("interface_name"),
        "abi": adapter_claim.get("interface_abi"),
        "descriptor": adapter_claim.get("interface_descriptor"),
    }


def _validate_postgresql_probe_facts(
    postcondition: str,
    observations: dict[str, Any],
    subject: dict[str, Any],
    cell: dict[str, Any],
) -> None:
    """Checks one PostgreSQL replacement observation against its exact subject."""

    scenario = cell["id"].rsplit("/", 1)[-1]
    operation = subject["operation"]
    resource = subject["resource"]
    observations = dict(observations)
    if observations.pop("matrix-operation", None) != operation:
        raise RuntimeError("PostgreSQL probe is not bound to its exact matrix operation")

    if postcondition == "durable-attempt-state-classified":
        expected_timelines = {
            "adopt-compatible-state": [
                "operation-admitted",
                "effect-started",
                "effect-completed",
            ],
            "reject-unsupported-transfer": [],
            "lose-external-result": [
                "operation-admitted",
                "effect-started",
                "operation-admitted",
                "reconciliation-started",
                "reconciled-completed",
            ],
            "activate-retained-target": [
                "operation-admitted",
                "effect-started",
                "effect-completed",
            ],
        }
        timeline = observations.get("timeline")
        adoption_operation = observations.pop("adoption-operation", None)
        adoption_timeline = observations.pop("adoption-timeline", None)
        adoption_generation = observations.pop("adoption-generation", None)
        method_generation = observations.pop("method-generation", None)
        requires_ordered_adoption = (
            scenario in {"adopt-compatible-state", "activate-retained-target"}
            and operation["method"] != subject["candidate"]["handler_method"]
        )
        ordered_adoption = (
            isinstance(adoption_operation, dict)
            and adoption_operation.get("interface") == operation["interface"]
            and adoption_operation.get("method")
            == subject["candidate"]["handler_method"]
            and adoption_operation.get("target", {}).get("interface")
            == operation["target"]["interface"]
            and adoption_operation.get("target", {}).get("resource")
            == operation["target"]["resource"]
            and isinstance(adoption_timeline, list)
            and [event.get("kind") for event in adoption_timeline]
            == ["operation-admitted", "effect-started", "effect-completed"]
            and all(
                isinstance(event, dict)
                and set(event) == {"sequence", "kind", "node-ordinal"}
                and _is_nonnegative_int(event.get("sequence"))
                and event.get("node-ordinal") == adoption_operation.get("ordinal")
                for event in adoption_timeline
            )
            and bool(timeline)
            and (
                adoption_timeline[-1]["sequence"] < timeline[0]["sequence"]
                or (
                    _is_nonnegative_int(adoption_generation)
                    and _is_nonnegative_int(method_generation)
                    and adoption_generation < method_generation
                )
            )
        )
        expected = expected_timelines.get(scenario)
        if (
            set(observations)
            != {
                "transaction",
                "plan",
                "operation",
                "timeline",
                "record-digest",
                "terminal",
                "classified",
            }
            or not _matches(LOCAL_KEY, observations.get("transaction"))
            or observations.get("plan") != subject["plan"]
            or observations.get("operation") != operation
            or not _matches(DIGEST, observations.get("record-digest"))
            or observations.get("classified") is not True
            or requires_ordered_adoption != ordered_adoption
            or (not requires_ordered_adoption and adoption_operation is not None)
            or (not requires_ordered_adoption and adoption_timeline is not None)
            or (adoption_generation is None) != (method_generation is None)
            or expected is None
            or [event.get("kind") for event in timeline or []] != expected
            or any(
                not isinstance(event, dict)
                or set(event) != {"sequence", "kind", "node-ordinal"}
                or not _is_nonnegative_int(event.get("sequence"))
                or event.get("node-ordinal") != operation["ordinal"]
                for event in timeline or []
            )
            or observations.get("terminal")
            != (
                "rejected-before-effect"
                if scenario == "reject-unsupported-transfer"
                else "complete"
            )
        ):
            raise RuntimeError("PostgreSQL journal does not classify the exact transition")
    elif postcondition == "at-most-one-resource-owner":
        inventories = [
            observations.get("owners-before"),
            observations.get("owners-unsettled"),
            observations.get("owners-after"),
        ]
        if (
            set(observations)
            != {"resource", "owners-before", "owners-unsettled", "owners-after"}
            or observations.get("resource") != resource
            or any(not isinstance(owners, list) or len(owners) > 1 for owners in inventories)
            or not inventories[0]
            or not inventories[2]
        ):
            raise RuntimeError("PostgreSQL ownership evidence permits multiple owners")
    elif postcondition == "foreign-resources-unchanged":
        if (
            set(observations)
            != {"resource", "snapshot-before", "snapshot-after", "unchanged"}
            or not isinstance(observations.get("resource"), dict)
            or observations.get("resource") == resource
            or not _matches(DIGEST, observations.get("snapshot-before"))
            or observations.get("snapshot-after") != observations.get("snapshot-before")
            or observations.get("unchanged") is not True
        ):
            raise RuntimeError("PostgreSQL transition changed its independent resource")
    elif postcondition == "dependent-effects-not-executed":
        if (
            set(observations)
            != {
                "predecessor-operation",
                "dependent-operations",
                "dependent-timelines-before-settlement",
                "dependent-effect-count-before-settlement",
                "blocked",
            }
            or observations.get("predecessor-operation") != operation
            or observations.get("dependent-operations")
            != subject["dependent-operations"]
            or observations.get("dependent-timelines-before-settlement") != []
            or observations.get("dependent-effect-count-before-settlement") != 0
            or observations.get("blocked") is not True
        ):
            raise RuntimeError("PostgreSQL rejection or recovery ran a dependent effect")
    elif postcondition == "fresh-receiving-authority":
        authorization = subject.get("adoption-authorization", {})
        expected_policy_revision = authorization.get(
            "authorization-policy-revision", subject["authorization-policy-revision"]
        )
        expected_current = authorization.get("current-planning", subject["current-planning"])
        expected_desired = authorization.get("desired-planning", subject["desired-planning"])
        if (
            set(observations)
            != {
                "source-handler-incarnation",
                "candidate-handler-incarnation",
                "authorization-policy-revision",
                "current-planning",
                "desired-planning",
                "fresh",
            }
            or observations.get("source-handler-incarnation")
            != subject["source"]["handler_incarnation"]
            or observations.get("candidate-handler-incarnation")
            != subject["candidate"]["handler_incarnation"]
            or observations.get("source-handler-incarnation")
            == observations.get("candidate-handler-incarnation")
            or observations.get("authorization-policy-revision")
            != expected_policy_revision
            or observations.get("current-planning") != expected_current
            or observations.get("desired-planning") != expected_desired
            or observations.get("fresh") is not True
        ):
            raise RuntimeError("PostgreSQL transition lacks fresh receiving authority")
    elif postcondition == "compatible-state-adopted":
        if (
            set(observations)
            != {
                "resource",
                "source-state-format",
                "candidate-state-format",
                "system-identifier-before",
                "system-identifier-after",
                "row-digest-before",
                "row-digest-after",
                "adopted",
            }
            or observations.get("resource") != resource
            or observations.get("source-state-format")
            != subject["source"]["state_format"]
            or observations.get("candidate-state-format")
            != subject["candidate"]["state_format"]
            or observations.get("source-state-format", {}).get("descriptor")
            != observations.get("candidate-state-format", {}).get("descriptor")
            or observations.get("system-identifier-before")
            != observations.get("system-identifier-after")
            or not _matches(DIGEST, observations.get("row-digest-before"))
            or observations.get("row-digest-after")
            != observations.get("row-digest-before")
            or observations.get("adopted") is not True
        ):
            raise RuntimeError("PostgreSQL evidence does not prove compatible adoption")
    elif postcondition == "exactly-one-resource-owner":
        if (
            set(observations) != {"resource", "expected-owner", "owners"}
            or observations.get("resource") != resource
            or observations.get("owners") != [observations.get("expected-owner")]
            or observations.get("expected-owner", {}).get("identity")
            != endpoint_identity(subject["candidate"])
        ):
            raise RuntimeError("PostgreSQL transition lacks its one exact candidate owner")
    elif postcondition == "transfer-rejected-before-candidate-effect":
        if (
            set(observations)
            != {
                "candidate-operation",
                "source-state-format",
                "candidate-state-format",
                "rejection",
                "candidate-effect-count",
                "generation-before",
                "generation-after",
                "rejected-before-effect",
            }
            or observations.get("candidate-operation") != operation
            or observations.get("source-state-format")
            != subject["source"]["state_format"]
            or observations.get("candidate-state-format")
            != subject["candidate"]["state_format"]
            or observations.get("source-state-format", {}).get("descriptor")
            == observations.get("candidate-state-format", {}).get("descriptor")
            or observations.get("rejection") != cell["failure"]
            or observations.get("candidate-effect-count") != 0
            or observations.get("generation-before")
            != observations.get("generation-after")
            or observations.get("rejected-before-effect") is not True
        ):
            raise RuntimeError("PostgreSQL transfer was not rejected before effect")
    elif postcondition == "predecessor-remains-sole-owner":
        if (
            set(observations)
            != {
                "resource",
                "predecessor-owner-before",
                "predecessor-owner-after",
                "system-identifier-before",
                "system-identifier-after",
                "row-digest-before",
                "row-digest-after",
            }
            or observations.get("resource") != resource
            or observations.get("predecessor-owner-after")
            != observations.get("predecessor-owner-before")
            or observations.get("system-identifier-after")
            != observations.get("system-identifier-before")
            or observations.get("row-digest-after")
            != observations.get("row-digest-before")
        ):
            raise RuntimeError("PostgreSQL rejection did not preserve its predecessor")
    elif postcondition == "current-grants-reauthorized":
        if (
            set(observations)
            != {
                "authorization-policy-revision",
                "source-handler-incarnation",
                "candidate-handler-incarnation",
                "current-planning",
                "desired-planning",
                "reauthorized",
            }
            or observations.get("authorization-policy-revision")
            != subject["authorization-policy-revision"]
            or observations.get("source-handler-incarnation")
            != subject["source"]["handler_incarnation"]
            or observations.get("candidate-handler-incarnation")
            != subject["candidate"]["handler_incarnation"]
            or observations.get("source-handler-incarnation")
            == observations.get("candidate-handler-incarnation")
            or observations.get("current-planning") != subject["current-planning"]
            or observations.get("desired-planning") != subject["desired-planning"]
            or observations.get("current-planning")
            == observations.get("desired-planning")
            or observations.get("reauthorized") is not True
        ):
            raise RuntimeError("PostgreSQL retained target lacks current grants")
    elif postcondition == "retained-target-identity-preserved":
        if (
            set(observations)
            != {
                "resource",
                "data-path-before",
                "data-path-after",
                "system-identifier-before",
                "system-identifier-after",
                "row-digest-before",
                "row-digest-after",
            }
            or observations.get("resource") != resource
            or observations.get("data-path-after") != observations.get("data-path-before")
            or observations.get("system-identifier-after")
            != observations.get("system-identifier-before")
            or observations.get("row-digest-after")
            != observations.get("row-digest-before")
        ):
            raise RuntimeError("PostgreSQL retained target identity changed")
    else:
        raise RuntimeError("PostgreSQL matrix postcondition has no semantic validator")


def endpoint_identity(endpoint: dict[str, Any]) -> dict[str, Any]:
    """Projects the durable provider identity carried by an adoption endpoint."""

    return {
        "provider": endpoint["provider"],
        "package": endpoint["package"],
        "interface": endpoint["interface"],
        "implementation": endpoint["implementation"],
        "state_format": endpoint["state_format"],
    }


def _validate_postgresql_cohort_subject(
    cell: dict[str, Any],
    subject: Any,
    evidence_bytes: Any,
    matrix_spec: dict[str, Any] | None,
) -> None:
    if matrix_spec is None:
        raise RuntimeError("PostgreSQL validation lacks its matrix specification")
    adapter_claim = _adapter_claim(matrix_spec, cell.get("adapter"))
    expected_interface = _claim_interface(adapter_claim)
    claimed_methods = {method["method"] for method in adapter_claim["methods"]}
    if (
        cell.get("interface") != expected_interface
        or cell.get("method") not in claimed_methods
    ):
        raise RuntimeError("PostgreSQL cohort is bound to another adapter method")

    scenario = cell["id"].rsplit("/", 1)[-1]
    if scenario == "reject-unsupported-transfer":
        expected = _postgresql_rejection_subject(evidence_bytes)
    else:
        expected = _postgresql_plan_subject(evidence_bytes, cell["method"])
    if subject != expected or subject.get("schema") != COHORT_SUBJECT_SCHEMA:
        raise RuntimeError("PostgreSQL cohort subject differs from its exact evidence")
    if (
        subject.get("operation", {}).get("interface") != cell["interface"]
        or subject.get("operation", {}).get("method") != cell["method"]
        or subject.get("operation", {}).get("target", {}).get("interface")
        != cell["interface"]
        or subject.get("operation", {}).get("target", {}).get("resource")
        != subject.get("resource")
    ):
        raise RuntimeError("PostgreSQL evidence operation differs from its matrix cell")

    source_format = subject.get("source", {}).get("state_format")
    candidate_format = subject.get("candidate", {}).get("state_format")
    compatible = (
        isinstance(source_format, dict)
        and isinstance(candidate_format, dict)
        and source_format.get("descriptor") == candidate_format.get("descriptor")
    )
    if compatible != (scenario != "reject-unsupported-transfer"):
        raise RuntimeError("PostgreSQL cohort state-format disposition is inconsistent")


def _postgresql_plan_subject(evidence_bytes: Any, method: str) -> dict[str, Any]:
    bundle = _canonical_evidence(evidence_bytes, "PostgreSQL plan bundle")
    if bundle.get("schema") == ORDERED_METHOD_EVIDENCE_SCHEMA:
        return _postgresql_ordered_method_subject(bundle, evidence_bytes, method)
    try:
        if bundle.get("schema") != "aos.ability.plan-bundle/v1":
            raise RuntimeError("PostgreSQL evidence has another plan-bundle schema")
        authority = bundle["transition_authority"]
        adoptions = authority["provider_adoptions"]
        if len(adoptions) != 1:
            raise RuntimeError("PostgreSQL plan does not carry one adoption contract")
        adoption = adoptions[0]
        effect_document = bundle["transition"]["effect_document"]
        operations = effect_document["operations"]
        matches = [
            _project_operation(operation, ordinal)
            for ordinal, operation in enumerate(operations)
            if operation.get("method") == method
            and operation.get("target", {}).get("resource") == adoption["resource"]
        ]
        if len(matches) != 1:
            raise RuntimeError("PostgreSQL plan lacks one exact cohort operation")
        dependent_operations = _required_success_dependents(
            effect_document, matches[0]
        )
    except RuntimeError:
        raise
    except (AttributeError, KeyError, TypeError) as error:
        raise RuntimeError("PostgreSQL plan evidence is malformed") from error

    return _postgresql_subject(
        plan=bundle["plan"],
        evidence_bytes=evidence_bytes,
        operation=matches[0],
        dependent_operations=dependent_operations,
        authority=authority,
        adoption=adoption,
    )


def _postgresql_ordered_method_subject(
    evidence: dict[str, Any], evidence_bytes: bytes, method: str
) -> dict[str, Any]:
    """Rebuilds a post-adoption method subject from both retained plans."""

    try:
        if set(evidence) != {"schema", "adoption", "method", "observation"}:
            raise RuntimeError("ordered PostgreSQL evidence is malformed")
        adoption_bundle = evidence["adoption"]
        method_bundle = evidence["method"]
        observation = evidence["observation"]
        if (
            adoption_bundle.get("schema") != "aos.ability.plan-bundle/v1"
            or method_bundle.get("schema") != "aos.ability.plan-bundle/v1"
            or set(observation)
            != {
                "adoption-generation",
                "method-generation",
                "transaction",
                "journal-digest",
                "resource-state",
            }
            or observation["method-generation"] <= observation["adoption-generation"]
            or not _matches(RAW_DIGEST, observation["journal-digest"])
            or not _matches(DIGEST, observation["resource-state"])
        ):
            raise RuntimeError("ordered PostgreSQL observation is not durable")
        adoptions = adoption_bundle["transition_authority"]["provider_adoptions"]
        if len(adoptions) != 1:
            raise RuntimeError("ordered PostgreSQL evidence lacks one adoption")
        adoption = adoptions[0]
        effect = method_bundle["transition"]["effect_document"]
        matches = [
            _project_operation(operation, ordinal)
            for ordinal, operation in enumerate(effect["operations"])
            if operation.get("method") == method
            and operation.get("target", {}).get("resource") == adoption["resource"]
        ]
        if len(matches) != 1:
            raise RuntimeError("ordered PostgreSQL method is absent or ambiguous")
        authority = method_bundle["transition_authority"]
        subject = _postgresql_subject(
            plan=method_bundle["plan"],
            evidence_bytes=evidence_bytes,
            operation=matches[0],
            dependent_operations=_required_success_dependents(effect, matches[0]),
            authority=authority,
            adoption=adoption,
        )
        subject["adoption-authorization"] = {
            "authorization-policy-revision": adoption_bundle["transition_authority"][
                "authorization_policy_revision"
            ],
            "current-planning": adoption_bundle["transition_authority"]["current_planning"],
            "desired-planning": adoption_bundle["transition_authority"]["desired_planning"],
        }
        return subject
    except RuntimeError:
        raise
    except (AttributeError, KeyError, TypeError) as error:
        raise RuntimeError("ordered PostgreSQL state evidence is malformed") from error


def _postgresql_rejection_subject(evidence_bytes: Any) -> dict[str, Any]:
    evidence = _canonical_evidence(evidence_bytes, "PostgreSQL rejection")
    try:
        if (
            evidence.get("schema") != REJECTION_EVIDENCE_SCHEMA
            or set(evidence) != {"schema", "activation", "policy", "observation"}
        ):
            raise RuntimeError("PostgreSQL rejection evidence has another schema")
        activation = evidence["activation"]
        policy = evidence["policy"]
        policy_bytes = canonical(policy)
        pinned = activation["authenticated_policy_set"]
        if (
            pinned["document_sha256"]
            != "sha256:" + hashlib.sha256(policy_bytes).hexdigest()
            or pinned["document_size"] != len(policy_bytes)
        ):
            raise RuntimeError("PostgreSQL rejection policy is not the pinned input")
        observation = evidence["observation"]
        if (
            not isinstance(observation, dict)
            or set(observation)
            != {
                "error",
                "generation-before",
                "generation-after",
                "owner-ledger-before",
                "owner-ledger-after",
                "persistent-state-before",
                "persistent-state-after",
                "candidate-effect-count",
            }
            or "state-format descriptors are incompatible"
            not in observation.get("error", "")
            or observation.get("generation-before")
            != observation.get("generation-after")
            or observation.get("owner-ledger-before")
            != observation.get("owner-ledger-after")
            or observation.get("persistent-state-before")
            != observation.get("persistent-state-after")
            or observation.get("candidate-effect-count") != 0
        ):
            raise RuntimeError("PostgreSQL rejection evidence lacks the exact outcome")
        authority = policy["transition_authority"]
        adoptions = authority["provider_adoptions"]
        if len(adoptions) != 1:
            raise RuntimeError("PostgreSQL rejection lacks one adoption contract")
        adoption = adoptions[0]
        candidate = adoption["candidate"]
        operation = {
            "key": candidate["handler_binding"],
            "ordinal": 0,
            "interface": candidate["handler_interface"],
            "method": candidate["handler_method"],
            "target": {
                "interface": candidate["handler_interface"],
                "resource": adoption["resource"],
                "operations": [candidate["handler_method"]],
                "lifetime": "persistent",
            },
        }
    except RuntimeError:
        raise
    except (AttributeError, KeyError, TypeError) as error:
        raise RuntimeError("PostgreSQL rejection evidence is malformed") from error

    return _postgresql_subject(
        plan=authority["desired_planning"],
        evidence_bytes=evidence_bytes,
        operation=operation,
        dependent_operations=[],
        authority=authority,
        adoption=adoption,
    )


def _postgresql_subject(
    *,
    plan: str,
    evidence_bytes: bytes,
    operation: dict[str, Any],
    dependent_operations: list[dict[str, Any]],
    authority: dict[str, Any],
    adoption: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema": COHORT_SUBJECT_SCHEMA,
        "plan": plan,
        "evidence-digest": "sha256:" + hashlib.sha256(evidence_bytes).hexdigest(),
        "operation": operation,
        "dependent-operations": dependent_operations,
        "resource": adoption["resource"],
        "resource-interface": adoption["resource_interface"],
        "source": adoption["source"],
        "candidate": adoption["candidate"],
        "current-planning": authority["current_planning"],
        "desired-planning": authority["desired_planning"],
        "authorization-policy-revision": authority[
            "authorization_policy_revision"
        ],
    }


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
        raise RuntimeError("PostgreSQL plan repeats an operation key")

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
        raise RuntimeError("PostgreSQL plan dependency names an unknown operation") from error


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


def accepts_subject(subject: Any) -> bool:
    """Returns whether this validator owns the subject schema."""

    return isinstance(subject, dict) and subject.get("schema") == COHORT_SUBJECT_SCHEMA


def validate_subject(
    cell: dict[str, Any],
    subject: Any,
    evidence_bytes: Any,
    matrix_spec: dict[str, Any] | None,
) -> None:
    """Validates one PostgreSQL cohort subject."""

    _validate_postgresql_cohort_subject(cell, subject, evidence_bytes, matrix_spec)


def validate_probe(
    postcondition: str,
    observations: dict[str, Any],
    subject: dict[str, Any],
    cell: dict[str, Any],
) -> None:
    """Validates one PostgreSQL cohort postcondition."""

    _validate_postgresql_probe_facts(postcondition, observations, subject, cell)


postgresql_plan_subject = _postgresql_plan_subject
postgresql_rejection_subject = _postgresql_rejection_subject
