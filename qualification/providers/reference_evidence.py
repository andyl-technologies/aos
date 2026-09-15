"""Validates reference-stack native qualification evidence.

This module owns the reference managed-configuration plan shape and live
resource observations. It returns only normalized results to the generic
matrix aggregator.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


LOCAL_KEY = re.compile(r"[A-Za-z0-9._-]{1,128}").fullmatch
DIGEST = re.compile(r"sha256:[0-9a-f]{64}").fullmatch
RAW_DIGEST = re.compile(r"[0-9a-f]{64}").fullmatch
COHORT_SUBJECT_SCHEMA = "aos.qualification.host-resource-cohort-subject/v1"
VALIDATION_RESULT_SCHEMA = "aos.qualification.provider-evidence-validation/v1"
PUBLISH_ORDINAL = 5
DEPENDENT_ORDINAL = 2
FIXTURE_ENVIRONMENT = {
    "authority": "reference",
    "key": "host",
    "stage": "host",
}

EXPECTED_ATTEMPT_TIMELINES = {
    "interrupt-after-durable-intent": [
        "operation-admitted",
        "effect-started",
        "operation-admitted",
        "reconciliation-started",
        "reconciled-completed",
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
EXPECTED_ATTEMPT_BOUNDARIES = {
    "interrupt-after-durable-intent": [
        ("effect", "effect-intent-durable"),
        ("reconcile", "reconciliation-intent-durable"),
        ("reconcile", "reconciliation-returned"),
        ("reconcile", "reconciliation-outcome-durable"),
        ("effect", "effect-intent-durable"),
        ("effect", "effect-returned"),
        ("effect", "effect-outcome-durable"),
    ],
    "lose-external-result": [
        ("effect", "effect-intent-durable"),
        ("effect", "effect-returned"),
        ("reconcile", "reconciliation-intent-durable"),
        ("reconcile", "reconciliation-returned"),
        ("reconcile", "reconciliation-outcome-durable"),
    ],
    "interrupt-after-durable-outcome": [
        ("effect", "effect-intent-durable"),
        ("effect", "effect-returned"),
        ("effect", "effect-outcome-durable"),
    ],
}
DEPENDENT_EFFECT_TIMELINE = [
    "operation-admitted",
    "effect-started",
    "effect-completed",
]
DEPENDENT_EFFECT_BOUNDARY_TIMELINE = [
    ("effect", "effect-intent-durable"),
    ("effect", "effect-returned"),
    ("effect", "effect-outcome-durable"),
]
REJECTED_EFFECT_TIMELINE = [
    "operation-admitted",
    "effect-started",
    "rejected-before-effect",
]
REJECTED_EFFECT_BOUNDARY_TIMELINE = [
    ("effect", "effect-intent-durable"),
    ("effect", "effect-returned"),
    ("effect", "effect-outcome-durable"),
]


def canonical(value: Any) -> bytes:
    """Encodes one value in the canonical evidence JSON dialect."""

    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def sha256(value: Any) -> str:
    """Hashes one value through the qualification canonical JSON dialect."""

    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _matches(pattern: Any, value: Any) -> bool:
    return isinstance(value, str) and pattern(value) is not None


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


def _claim_interface(adapter_claim: dict[str, Any]) -> dict[str, Any]:
    """Projects an interface identity from one generated adapter claim."""

    return {
        "name": adapter_claim.get("interface_name"),
        "abi": adapter_claim.get("interface_abi"),
        "descriptor": adapter_claim.get("interface_descriptor"),
    }


def _validate_managed_configuration_subject(
    cell: dict[str, Any],
    subject: Any,
    plan_bundle_bytes: Any,
    matrix_spec: dict[str, Any] | None,
) -> None:
    if matrix_spec is None:
        raise RuntimeError("cohort validation lacks its matrix specification")

    scenario = cell["id"].rsplit("/", 1)[-1]
    if not isinstance(subject, dict) or set(subject) != {
        "schema",
        "plan",
        "plan-bundle-digest",
        "authoring-evaluations",
        "publish-operation",
        "dependent-operation",
    }:
        raise RuntimeError("cohort operation subject is malformed")
    expected_subject = _subject_from_plan_bundle(plan_bundle_bytes)
    authors = subject.get("authoring-evaluations")
    publish_operation = subject.get("publish-operation", {})
    dependent_operation = subject.get("dependent-operation", {})
    publish_claim = _adapter_claim_by_interface(
        matrix_spec, publish_operation.get("interface", {}).get("name")
    )
    dependent_claim = _adapter_claim_by_interface(
        matrix_spec, dependent_operation.get("interface", {}).get("name")
    )
    publish_interface = _claim_interface(publish_claim)
    dependent_interface = _claim_interface(dependent_claim)
    publish_method = publish_operation.get("method")
    dependent_method = dependent_operation.get("method")
    publish_methods = {method["method"] for method in publish_claim["methods"]}
    dependent_methods = {method["method"] for method in dependent_claim["methods"]}
    expected_cell_operation = (
        dependent_operation
        if scenario == "block-dependent-effect"
        else publish_operation
    )
    publish_target = {
        "interface": publish_interface,
        "resource": {
            "provider": {
                "environment": FIXTURE_ENVIRONMENT,
                "key": "shared-configuration",
            },
            "key": "nginx-secondary-configuration",
        },
        "operations": [publish_method],
        "lifetime": "instance",
    }
    dependent_target = {
        "interface": dependent_interface,
        "resource": {
            "provider": {
                "environment": FIXTURE_ENVIRONMENT,
                "key": "shared-service",
            },
            "key": "nginx-secondary-service",
        },
        "operations": [dependent_method],
        "lifetime": "instance",
    }
    if (
        subject != expected_subject
        or subject.get("schema") != COHORT_SUBJECT_SCHEMA
        or not _matches(DIGEST, subject.get("plan"))
        or not _matches(DIGEST, subject.get("plan-bundle-digest"))
        or not isinstance(authors, dict)
        or set(authors) != {"publish", "dependent"}
        or publish_operation.get("interface") != publish_interface
        or dependent_operation.get("interface") != dependent_interface
        or publish_method not in publish_methods
        or dependent_method not in dependent_methods
        or cell.get("adapter")
        != (
            dependent_claim["adapter"]
            if scenario == "block-dependent-effect"
            else publish_claim["adapter"]
        )
        or cell.get("interface") != expected_cell_operation.get("interface")
        or cell.get("method") != expected_cell_operation.get("method")
        or not _is_expected_author(authors.get("publish"), "shared-configuration")
        or not _is_expected_author(authors.get("dependent"), "nginx-secondary")
        or not _is_expected_operation(
            subject.get("publish-operation"),
            authors["publish"],
            "publish-nginx-secondary-configuration",
            PUBLISH_ORDINAL,
            publish_interface,
            publish_method,
            publish_target,
        )
        or not _is_expected_operation(
            subject.get("dependent-operation"),
            authors["dependent"],
            "reload-nginx-secondary-service",
            DEPENDENT_ORDINAL,
            dependent_interface,
            dependent_method,
            dependent_target,
        )
    ):
        raise RuntimeError("cohort operation subject differs from the fixed fixture")


def _subject_from_plan_bundle(plan_bundle_bytes: Any) -> dict[str, Any]:
    if not isinstance(plan_bundle_bytes, bytes):
        raise RuntimeError("cohort plan bundle is not an exact byte string")
    try:
        bundle = json.loads(plan_bundle_bytes)
        if canonical(bundle) != plan_bundle_bytes:
            raise RuntimeError("cohort plan bundle is not canonical JSON")
        if bundle.get("schema") != "aos.ability.plan-bundle/v1":
            raise RuntimeError("cohort plan bundle has another schema")

        transition = bundle["transition"]
        if transition.get("schema") != "aos.ability.transition-snapshot/v1":
            raise RuntimeError("cohort transition snapshot has another schema")
        evaluations = transition["evaluations"]
        operations = transition["effect_document"]["operations"]
        publish_author = _author_from_evaluations(
            evaluations, "shared-configuration"
        )
        dependent_author = _author_from_evaluations(evaluations, "nginx-secondary")
        publish_operation = _project_operation(
            operations[PUBLISH_ORDINAL], PUBLISH_ORDINAL
        )
        dependent_operation = _project_operation(
            operations[DEPENDENT_ORDINAL], DEPENDENT_ORDINAL
        )
        plan = bundle["plan"]
    except RuntimeError:
        raise
    except (AttributeError, IndexError, KeyError, TypeError, ValueError) as error:
        raise RuntimeError("cohort plan bundle cannot authenticate its subject") from error

    return {
        "schema": COHORT_SUBJECT_SCHEMA,
        "plan": plan,
        "plan-bundle-digest": "sha256:"
        + hashlib.sha256(plan_bundle_bytes).hexdigest(),
        "authoring-evaluations": {
            "publish": publish_author,
            "dependent": dependent_author,
        },
        "publish-operation": publish_operation,
        "dependent-operation": dependent_operation,
    }


def _author_from_evaluations(evaluations: Any, provider_key: str) -> dict[str, Any]:
    provider = {
        "environment": FIXTURE_ENVIRONMENT,
        "key": provider_key,
    }
    if not isinstance(evaluations, list):
        raise RuntimeError("cohort transition evaluations are malformed")
    matches = [
        evaluation
        for evaluation in evaluations
        if isinstance(evaluation, dict) and evaluation.get("provider") == provider
    ]
    if len(matches) != 1:
        raise RuntimeError("cohort transition lacks one exact authoring evaluation")
    evaluation = matches[0]
    implementation = evaluation.get("implementation")
    result = evaluation.get("result")
    descriptor = (
        implementation.get("descriptor")
        if isinstance(implementation, dict)
        else None
    )
    if (
        not _matches(DIGEST, descriptor)
        or not isinstance(result, dict)
        or result.get("status") != "returned"
    ):
        raise RuntimeError("cohort authoring evaluation is not an exact success")
    return {
        "provider": provider,
        "implementation-descriptor": descriptor,
    }


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


def _is_expected_author(value: Any, provider_key: str) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"provider", "implementation-descriptor"}
        and value.get("provider")
        == {"environment": FIXTURE_ENVIRONMENT, "key": provider_key}
        and _matches(DIGEST, value.get("implementation-descriptor"))
    )


def _is_expected_operation(
    value: Any,
    author: dict[str, Any],
    local_key: str,
    ordinal: int,
    interface: dict[str, Any],
    method: str,
    target: dict[str, Any],
) -> bool:
    descriptor = author["implementation-descriptor"]
    expected_key = {
        "scope": [author["provider"]["key"], descriptor.removeprefix("sha256:")],
        "key": local_key,
    }
    return value == {
        "key": expected_key,
        "ordinal": ordinal,
        "interface": interface,
        "method": method,
        "target": target,
    }


def _cell_scenario(cell: dict[str, Any]) -> str:
    return cell["id"].rsplit("/", 1)[-1]


def _interruption_position(
    scenario: str, boundary_timeline: list[dict[str, Any]]
) -> Any:
    indexes = {
        "interrupt-after-durable-intent": 0,
        "lose-external-result": 1,
        "interrupt-after-durable-outcome": 2,
    }
    try:
        return boundary_timeline[indexes[scenario]]["transcript-position"]
    except (IndexError, KeyError, TypeError) as error:
        raise RuntimeError("matrix crash scenario has no interruption boundary") from error


def _cohort_operation(cohort_subject: dict[str, Any]) -> Any:
    return cohort_subject.get("operation", cohort_subject.get("publish-operation"))


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


def _is_exact_timeline(
    value: Any, expected_kinds: list[str], expected_ordinal: Any
) -> bool:
    if not _is_nonnegative_int(expected_ordinal):
        return False
    if not isinstance(value, list) or len(value) != len(expected_kinds):
        return False
    if any(
        not isinstance(event, dict)
        or set(event) != {"sequence", "kind", "node-ordinal"}
        or not _is_nonnegative_int(event.get("sequence"))
        or not isinstance(event.get("kind"), str)
        or event.get("node-ordinal") != expected_ordinal
        for event in value
    ):
        return False
    sequences = [event["sequence"] for event in value]
    return (
        [event["kind"] for event in value] == expected_kinds
        and sequences == sorted(sequences)
        and len(set(sequences)) == len(sequences)
    )


def _is_exact_boundary_timeline(
    value: Any, expected_boundaries: list[tuple[str, str]]
) -> bool:
    if not isinstance(value, list) or len(value) != len(expected_boundaries):
        return False
    if any(
        not isinstance(event, dict)
        or set(event) != {"transcript-position", "purpose", "boundary"}
        or not _is_nonnegative_int(event.get("transcript-position"))
        or not isinstance(event.get("purpose"), str)
        or not isinstance(event.get("boundary"), str)
        for event in value
    ):
        return False
    positions = [event["transcript-position"] for event in value]
    actual_boundaries = [(event["purpose"], event["boundary"]) for event in value]
    return (
        actual_boundaries == expected_boundaries
        and positions == sorted(positions)
        and len(set(positions)) == len(positions)
    )


def validate_probe(
    postcondition: str,
    observations: dict[str, Any],
    cohort_subject: dict[str, Any],
    cell: dict[str, Any],
) -> dict[str, Any]:
    """Validates one provider-owned normalized postcondition result."""

    scenario = _cell_scenario(cell)
    if postcondition == "durable-attempt-state-classified":
        operation = observations.get("operation")
        timeline = observations.get("timeline")
        boundary_timeline = observations.get("boundary-timeline")
        if scenario in {
            "block-dependent-effect",
            "reject-foreign-resource-mutation",
        }:
            cause = observations.get("cause-operation")
            expected_operation = (
                cohort_subject["dependent-operation"]
                if scenario == "block-dependent-effect"
                else cohort_subject["publish-operation"]
            )
            if (
                set(observations)
                != {
                    "transaction",
                    "plan",
                    "operation",
                    "timeline",
                    "cause-operation",
                    "cause-timeline",
                    "boundary-timeline",
                    "failure-record",
                    "classified",
                }
                or not _matches(LOCAL_KEY, observations.get("transaction"))
                or observations.get("plan") != cohort_subject["plan"]
                or operation != expected_operation
                or cause != cohort_subject["publish-operation"]
                or (
                    scenario == "block-dependent-effect"
                    and timeline != []
                )
                or (
                    scenario == "reject-foreign-resource-mutation"
                    and not _is_exact_timeline(
                        timeline, REJECTED_EFFECT_TIMELINE, operation.get("ordinal")
                    )
                )
                or not _is_exact_timeline(
                    observations.get("cause-timeline"),
                    REJECTED_EFFECT_TIMELINE,
                    cause.get("ordinal"),
                )
                or not _is_exact_boundary_timeline(
                    boundary_timeline, REJECTED_EFFECT_BOUNDARY_TIMELINE
                )
                or not _matches(RAW_DIGEST, observations.get("failure-record"))
                or observations.get("classified") is not True
            ):
                raise RuntimeError("journal probe does not prove durable negative classification")
            return _validation_result(cell, "postcondition", postcondition)

        expected_fields = {
            "transaction",
            "plan",
            "journal-before-loss",
            "operation",
            "timeline",
            "boundary-timeline",
            "interruption-position",
            "settlement-position",
        }
        if (
            set(observations) != expected_fields
            or not _matches(LOCAL_KEY, observations.get("transaction"))
            or not _matches(DIGEST, observations.get("plan"))
            or observations.get("plan") != cohort_subject["plan"]
            or not _matches(RAW_DIGEST, observations.get("journal-before-loss"))
            or operation != cohort_subject["publish-operation"]
            or not _is_exact_timeline(
                timeline, EXPECTED_ATTEMPT_TIMELINES.get(scenario), operation.get("ordinal")
            )
            or not _is_exact_boundary_timeline(
                boundary_timeline, EXPECTED_ATTEMPT_BOUNDARIES.get(scenario)
            )
            or observations.get("interruption-position")
            != _interruption_position(scenario, boundary_timeline)
            or observations.get("settlement-position")
            != boundary_timeline[-1]["transcript-position"]
        ):
            raise RuntimeError("journal probe does not prove exact crash recovery")
    elif postcondition == "at-most-one-resource-owner":
        if scenario in {
            "block-dependent-effect",
            "reject-foreign-resource-mutation",
        }:
            if (
                set(observations)
                != {
                    "resource",
                    "owner-count-before",
                    "owner-count-after",
                    "one-owner-throughout",
                    "owner-evidence-before",
                    "owner-evidence-after",
                }
                or not isinstance(observations.get("resource"), dict)
                or observations.get("owner-count-before") != 1
                or observations.get("owner-count-after") != 1
                or observations.get("one-owner-throughout") is not True
                or not isinstance(observations.get("owner-evidence-before"), str)
                or not observations.get("owner-evidence-before")
                or observations.get("owner-evidence-after")
                != observations.get("owner-evidence-before")
            ):
                raise RuntimeError("ownership probe does not prove one negative-flight owner")
            return _validation_result(cell, "postcondition", postcondition)

        if (
            set(observations)
            != {"resource", "destination", "revision", "matching-markers", "selected-after-gc"}
            or observations.get("matching-markers") != 1
            or observations.get("selected-after-gc") is not True
            or not isinstance(observations.get("resource"), dict)
            or not isinstance(observations.get("destination"), str)
            or not observations["destination"].startswith("/")
            or not isinstance(observations.get("revision"), str)
            or not observations["revision"]
        ):
            raise RuntimeError("ownership probe does not prove one retained owner")
    elif postcondition == "foreign-resources-unchanged":
        if scenario in {
            "block-dependent-effect",
            "reject-foreign-resource-mutation",
        }:
            allowed_fields = {
                "resource",
                "snapshot-before",
                "snapshot-after",
                "unchanged",
            }
            if scenario == "block-dependent-effect":
                allowed_fields.add("cell")
            if (
                set(observations) != allowed_fields
                or not isinstance(observations.get("resource"), dict)
                or not isinstance(observations.get("snapshot-before"), str)
                or observations.get("snapshot-after")
                != observations.get("snapshot-before")
                or observations.get("unchanged") is not True
                or (
                    scenario == "block-dependent-effect"
                    and observations.get("cell") != cell["id"]
                )
            ):
                raise RuntimeError("foreign-resource probe changed during negative flight")
            return _validation_result(cell, "postcondition", postcondition)

        snapshots = [
            observations.get("content-before"),
            observations.get("content-unsettled"),
            observations.get("content-after-gc"),
            observations.get("content-after-recovery"),
        ]
        if (
            set(observations)
            != {
                "resource",
                "revision",
                "content-before",
                "content-unsettled",
                "content-after-gc",
                "content-after-recovery",
            }
            or snapshots[0] is None
            or any(snapshot != snapshots[0] for snapshot in snapshots[1:])
            or not isinstance(observations.get("resource"), dict)
        ):
            raise RuntimeError("foreign-resource probe changed across the cohort")
    elif postcondition == "dependent-effects-not-executed":
        if scenario in {
            "block-dependent-effect",
            "reject-foreign-resource-mutation",
        }:
            allowed_fields = {
                "predecessor-operation",
                "dependent-operation",
                "dependency-edge",
                "dependent-timeline",
                "dependent-effect-boundaries",
                "behavior-before",
                "behavior-after",
                "blocked",
            }
            if scenario == "block-dependent-effect":
                allowed_fields.add("cell")
            predecessor = observations.get("predecessor-operation")
            dependent = observations.get("dependent-operation")
            if (
                set(observations) != allowed_fields
                or predecessor != cohort_subject["publish-operation"]
                or dependent != cohort_subject["dependent-operation"]
                or observations.get("dependency-edge")
                != {
                    "from": {"kind": "operation", "key": predecessor["key"]},
                    "to": {"kind": "operation", "key": dependent["key"]},
                    "kind": "required-success",
                }
                or observations.get("dependent-timeline") != []
                or observations.get("dependent-effect-boundaries") != []
                or observations.get("behavior-before")
                != observations.get("behavior-after")
                or observations.get("blocked") is not True
                or (
                    scenario == "block-dependent-effect"
                    and observations.get("cell") != cell["id"]
                )
            ):
                raise RuntimeError("dependency probe does not prove negative-flight blocking")
            return _validation_result(cell, "postcondition", postcondition)

        before = observations.get("route-while-unsettled")
        after = observations.get("route-after-recovery")
        publish = observations.get("publish-operation")
        dependent = observations.get("dependent-operation")
        edge = observations.get("dependency-edge")
        timeline_after = observations.get("timeline-after-recovery")
        boundary_after = observations.get("effect-boundary-timeline")
        expected_fields = {
            "publish-operation",
            "dependent-operation",
            "dependency-edge",
            "timeline-before-completion",
            "effect-boundaries-before-completion",
            "publish-settlement-sequence",
            "publish-settlement-position",
            "timeline-after-recovery",
            "effect-boundary-timeline",
            "dependent-effect-return-position",
            "route-while-unsettled",
            "route-after-recovery",
            "changed-only-after-recovery",
        }
        if (
            set(observations) != expected_fields
            or publish != cohort_subject["publish-operation"]
            or dependent != cohort_subject["dependent-operation"]
            or edge
            != {
                "from": {"kind": "operation", "key": publish["key"]},
                "to": {"kind": "operation", "key": dependent["key"]},
                "kind": "required-success",
            }
            or observations.get("timeline-before-completion") != []
            or observations.get("effect-boundaries-before-completion") != []
            or not _is_exact_timeline(
                timeline_after, DEPENDENT_EFFECT_TIMELINE, dependent["ordinal"]
            )
            or not _is_exact_boundary_timeline(
                boundary_after, DEPENDENT_EFFECT_BOUNDARY_TIMELINE
            )
            or not _is_nonnegative_int(observations.get("publish-settlement-sequence"))
            or observations["publish-settlement-sequence"] >= timeline_after[0]["sequence"]
            or not _is_nonnegative_int(
                observations.get("publish-settlement-position")
            )
            or observations["publish-settlement-position"]
            >= boundary_after[0]["transcript-position"]
            or observations.get("dependent-effect-return-position")
            != boundary_after[1]["transcript-position"]
            or not isinstance(before, str)
            or not isinstance(after, str)
            or before == after
            or observations.get("changed-only-after-recovery") is not True
        ):
            raise RuntimeError("dependency probe does not retain the predecessor result")
    elif postcondition == "fresh-receiving-authority":
        predecessor = observations.get("predecessor-authority")
        candidate = observations.get("candidate-authority")
        if (
            set(observations)
            != {
                "predecessor-authority",
                "candidate-authority",
                "predecessor-incarnation",
                "candidate-incarnation",
                "authority-sequence-before",
                "authority-sequence-after",
                "fresh",
            }
            or not _matches(DIGEST, predecessor)
            or not _matches(DIGEST, candidate)
            or predecessor == candidate
            or not _distinct_nonempty_strings(
                observations.get("predecessor-incarnation"),
                observations.get("candidate-incarnation"),
            )
            or not _strictly_increasing_nonnegative(
                observations.get("authority-sequence-before"),
                observations.get("authority-sequence-after"),
            )
            or observations.get("fresh") is not True
        ):
            raise RuntimeError("authority probe does not prove a fresh receiving authority")
    elif postcondition == "compatible-state-adopted":
        if (
            set(observations)
            != {
                "resource",
                "compatibility-contract",
                "predecessor-state",
                "adopted-state",
                "adoption-record",
                "candidate-effect-count",
                "adopted",
            }
            or not isinstance(observations.get("resource"), dict)
            or not _matches(DIGEST, observations.get("compatibility-contract"))
            or not _matches(DIGEST, observations.get("predecessor-state"))
            or observations.get("adopted-state") != observations.get("predecessor-state")
            or not _matches(DIGEST, observations.get("adoption-record"))
            or observations.get("candidate-effect-count") != 0
            or observations.get("adopted") is not True
        ):
            raise RuntimeError("adoption probe does not prove compatible state adoption")
    elif postcondition == "exactly-one-resource-owner":
        owners = observations.get("owners")
        if (
            set(observations)
            != {"resource", "expected-owner", "owners", "matching-markers"}
            or not isinstance(observations.get("resource"), dict)
            or not isinstance(observations.get("expected-owner"), dict)
            or owners != [observations.get("expected-owner")]
            or observations.get("matching-markers") != 1
        ):
            raise RuntimeError("ownership probe does not prove one exact owner")
    elif postcondition == "transfer-rejected-before-candidate-effect":
        if (
            set(observations)
            != {
                "candidate-operation",
                "rejection",
                "candidate-effect-count",
                "rejected-before-effect",
            }
            or observations.get("candidate-operation") != _cohort_operation(cohort_subject)
            or observations.get("rejection") != cell.get("failure")
            or observations.get("candidate-effect-count") != 0
            or observations.get("rejected-before-effect") is not True
        ):
            raise RuntimeError("transfer probe does not prove pre-effect rejection")
    elif postcondition == "predecessor-remains-sole-owner":
        predecessor = observations.get("predecessor-owner")
        if (
            set(observations)
            != {
                "resource",
                "predecessor-owner",
                "owners",
                "behavior-before",
                "behavior-after",
            }
            or not isinstance(observations.get("resource"), dict)
            or not isinstance(predecessor, dict)
            or observations.get("owners") != [predecessor]
            or observations.get("behavior-before") is None
            or observations.get("behavior-after") != observations.get("behavior-before")
        ):
            raise RuntimeError("predecessor probe does not prove sole retained ownership")
    elif postcondition == "current-grants-reauthorized":
        if (
            set(observations)
            != {
                "plan",
                "retained-grant",
                "current-grant",
                "authority-sequence-before",
                "authority-sequence-after",
                "reauthorized",
            }
            or observations.get("plan") != cohort_subject.get("plan")
            or not _matches(DIGEST, observations.get("retained-grant"))
            or not _matches(DIGEST, observations.get("current-grant"))
            or observations.get("retained-grant") == observations.get("current-grant")
            or not _strictly_increasing_nonnegative(
                observations.get("authority-sequence-before"),
                observations.get("authority-sequence-after"),
            )
            or observations.get("reauthorized") is not True
        ):
            raise RuntimeError("grant probe does not prove current reauthorization")
    elif postcondition == "retained-target-identity-preserved":
        if (
            set(observations)
            != {
                "retained-target",
                "activated-target",
                "retained-revision",
                "activated-revision",
            }
            or not isinstance(observations.get("retained-target"), dict)
            or observations.get("activated-target") != observations.get("retained-target")
            or not _matches(DIGEST, observations.get("retained-revision"))
            or observations.get("activated-revision")
            != observations.get("retained-revision")
        ):
            raise RuntimeError("target probe does not preserve retained identity")
    elif postcondition == "prerequisite-failure-recorded":
        predecessor = observations.get("predecessor-operation")
        dependent = observations.get("dependent-operation")
        edge = observations.get("dependency-edge")
        if (
            set(observations)
            != {
                "predecessor-operation",
                "dependent-operation",
                "dependency-edge",
                "failure-record",
                "dependent-effect-count",
            }
            or not _operation_key(predecessor)
            or not _operation_key(dependent)
            or edge
            not in [
                {
                    "from": {"kind": "operation", "key": predecessor.get("key")},
                    "to": {"kind": "operation", "key": dependent.get("key")},
                    "kind": kind,
                }
                for kind in ["data", "required-success", "readiness"]
            ]
            or not _matches(DIGEST, observations.get("failure-record"))
            or observations.get("dependent-effect-count") != 0
        ):
            raise RuntimeError("prerequisite probe does not prove durable dependent blocking")
    elif postcondition == "foreign-attempt-rejected-before-mutation":
        foreign = observations.get("foreign-resource")
        authorized = observations.get("authorized-resources")
        if (
            set(observations)
            != {
                "foreign-resource",
                "attempted-resource",
                "authorized-resources",
                "rejection",
                "mutation-count",
                "rejected-before-mutation",
            }
            or not isinstance(foreign, dict)
            or observations.get("attempted-resource") != foreign
            or not isinstance(authorized, list)
            or foreign in authorized
            or observations.get("rejection") != cell.get("failure")
            or observations.get("mutation-count") != 0
            or observations.get("rejected-before-mutation") is not True
        ):
            raise RuntimeError("foreign-resource probe does not prove pre-mutation rejection")
    else:
        raise RuntimeError("matrix postcondition has no semantic validator")

    return _validation_result(cell, "postcondition", postcondition)


def _validation_result(
    cell: dict[str, Any], kind: str, postcondition: str | None = None
) -> dict[str, Any]:
    """Returns the closed result consumed by the provider-neutral aggregator."""

    result = {
        "schema": VALIDATION_RESULT_SCHEMA,
        "cell-id": cell["id"],
        "kind": kind,
    }
    if postcondition is not None:
        result["postcondition"] = postcondition
    return result


def accepts_subject(subject: Any) -> bool:
    """Returns whether this validator owns the subject schema."""

    return isinstance(subject, dict) and subject.get("schema") == COHORT_SUBJECT_SCHEMA


def validate_subject(
    cell: dict[str, Any],
    subject: Any,
    evidence_bytes: Any,
    matrix_spec: dict[str, Any] | None,
) -> None:
    """Validates one reference-stack cohort subject."""

    _validate_managed_configuration_subject(cell, subject, evidence_bytes, matrix_spec)
