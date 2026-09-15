"""Validates effect, cancellation, and provider-state operation evidence."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import native_adapter_evidence as provider_evidence

from native_adapter_evidence_common import (
    CELL_SUBJECT_SCHEMA,
    DIGEST,
    LOCAL_KEY,
    PROBE_SCHEMA,
    RAW_DIGEST,
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
    _observation_kind,
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


EFFECT_BOUNDARY_ATTEMPT_TIMELINES = {
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

EFFECT_BOUNDARY_COHORT_SUBJECT_SCHEMA = (
    "aos.qualification.native-adapter-effect-cohort-subject/v1"
)

EFFECT_BOUNDARY_EVIDENCE_SCHEMA = (
    "aos.qualification.native-adapter-effect-flight/v1"
)

CANCELLATION_COHORT_SUBJECT_SCHEMA = (
    "aos.qualification.native-adapter-cancellation-subject/v1"
)

CANCELLATION_EVIDENCE_SCHEMA = (
    "aos.qualification.native-adapter-cancellation-flight/v1"
)


CANCELLATION_RESULTS = {
    "cancellation-rejected-before-effect",
    "cancellation-observed-completion",
    "cancellation-indeterminate",
}

CANCELLATION_BOUNDARIES = [
    ("effect", "resources-acquired"),
    ("effect", "effect-intent-durable"),
    ("cancel", "cancellation-intent-durable"),
    ("cancel", "final-dispatch"),
    ("cancel", "cancellation-returned"),
    ("cancel", "cancellation-outcome-durable"),
]


def _effect_boundary_attempt_timeline(
    scenario: str, required_target_access: str
) -> list[str]:
    """Returns the exact recovery classification for one effect class."""

    if (
        scenario == "interrupt-after-durable-intent"
        and required_target_access == "read"
    ):
        return [
            "operation-admitted",
            "effect-started",
            "operation-admitted",
            "reconciliation-started",
            "reconciled-completed",
        ]
    return EFFECT_BOUNDARY_ATTEMPT_TIMELINES[scenario]

def _validate_cancellation_subject(
    cell: dict[str, Any],
    subject: Any,
    evidence_bytes: Any,
    matrix_spec: dict[str, Any] | None,
    routes: list[dict[str, Any]],
) -> None:
    """Rebuilds a cancellation subject from its exact production plan and route."""

    evidence = _canonical_evidence(evidence_bytes, "cancellation flight")
    try:
        if not isinstance(evidence, dict) or set(evidence) != {
            "schema",
            "matrix-spec-digest",
            "cell-digest",
            "plan-bundle",
            "source-authority",
            "candidate-authority",
        }:
            raise RuntimeError("cancellation evidence is malformed")
        if evidence.get("schema") != CANCELLATION_EVIDENCE_SCHEMA:
            raise RuntimeError("cancellation evidence has another schema")
        bundle = evidence["plan-bundle"]
        if bundle.get("schema") != "aos.ability.plan-bundle/v1":
            raise RuntimeError("cancellation evidence has another plan schema")
        expected_subject_fields = {
            "schema",
            "matrix-spec-digest",
            "cell-digest",
            "plan",
            "plan-bundle-digest",
            "evidence-digest",
            "adapter",
            "operation",
            "cancel-route",
            "dependent-operation",
            "provider-implementation",
            "native-route",
        }
        if not isinstance(subject, dict) or set(subject) != expected_subject_fields:
            raise RuntimeError("cancellation subject is malformed")

        effect = bundle["transition"]["effect_document"]
        operation = subject["operation"]
        operation_matches = [
            (candidate, _project_operation(candidate, ordinal))
            for ordinal, candidate in enumerate(effect["operations"])
            if _project_operation(candidate, ordinal) == operation
        ]
        if len(operation_matches) != 1:
            raise RuntimeError("cancellation operation is absent or ambiguous")
        operation_document, _ = operation_matches[0]
        dependents = _required_success_dependents(effect, operation)
        dependent = subject["dependent-operation"]
        if dependent not in dependents:
            raise RuntimeError("cancellation successor is not RequiredSuccess")

        implementations = {}
        for state in (bundle.get("desired"), bundle.get("current")):
            if state is None:
                continue
            for binding in state["snapshot"]["resolution"]["binding_document"][
                "bindings"
            ]:
                if binding["id"] == operation_document["binding"]:
                    implementation = binding["implementation"]
                    implementations[canonical(implementation)] = implementation
        if len(implementations) != 1:
            raise RuntimeError("cancellation terminal implementation is ambiguous")
        implementation = next(iter(implementations.values()))
        native_route = _effect_boundary_native_route(
            bundle,
            operation_document,
            implementation,
            evidence["source-authority"],
            evidence["candidate-authority"],
        )
        if matrix_spec is None:
            raise RuntimeError("cancellation validation lacks its matrix specification")
    except RuntimeError:
        raise
    except (AttributeError, KeyError, TypeError) as error:
        raise RuntimeError("cancellation plan evidence is malformed") from error

    cell_digest = sha256(cell)
    matrix_digest = subject["matrix-spec-digest"]
    cancel_route = operation_document.get("recovery", {}).get("cancel")
    if cancel_route is not None and (
        not isinstance(cancel_route, dict)
        or cancel_route.get("interface") != cell["interface"]
        or not _matches(LOCAL_KEY, cancel_route.get("method"))
    ):
        raise RuntimeError("cancellation operation carries an invalid route")
    if matrix_spec is not None and matrix_digest != sha256(matrix_spec):
        raise RuntimeError("cancellation subject names another matrix specification")
    if (
        _cell_scenario(cell) != "cancel-unsettled-attempt"
        or subject["schema"] != CANCELLATION_COHORT_SUBJECT_SCHEMA
        or matrix_digest != evidence["matrix-spec-digest"]
        or subject["cell-digest"] != cell_digest
        or evidence["cell-digest"] != cell_digest
        or subject["plan"] != bundle["plan"]
        or subject["plan-bundle-digest"] != sha256(bundle)
        or subject["evidence-digest"]
        != "sha256:" + hashlib.sha256(evidence_bytes).hexdigest()
        or subject["adapter"] != cell["adapter"]
        or operation["interface"] != cell["interface"]
        or operation["method"] != cell["method"]
        or operation["target"]["interface"] != cell["interface"]
        or subject["cancel-route"] != operation_document["recovery"]["cancel"]
        or subject["provider-implementation"] != implementation
        or not implementation.get("handler")
        or subject["native-route"] != native_route
    ):
        raise RuntimeError("cancellation subject differs from its production plan")

def _validate_effect_boundary_subject(
    cell: dict[str, Any], subject: Any, evidence_bytes: Any
) -> None:
    """Rebuilds an effect-boundary subject from its canonical production plan."""

    evidence = _canonical_evidence(evidence_bytes, "effect-boundary flight")
    try:
        if not isinstance(evidence, dict) or set(evidence) != {
            "schema",
            "plan-bundle",
            "source-authority",
            "candidate-authority",
        }:
            raise RuntimeError("effect-boundary evidence is malformed")
        if evidence.get("schema") != EFFECT_BOUNDARY_EVIDENCE_SCHEMA:
            raise RuntimeError("effect-boundary evidence has another schema")
        bundle = evidence["plan-bundle"]
        if bundle.get("schema") != "aos.ability.plan-bundle/v1":
            raise RuntimeError("effect-boundary evidence has another plan schema")
        if not isinstance(subject, dict) or set(subject) != {
            "schema",
            "plan",
            "plan-bundle-digest",
            "evidence-digest",
            "adapter",
            "operation",
            "dependent-operation",
            "dependency-edge",
            "provider-implementation",
            "native-route",
        }:
            raise RuntimeError("effect-boundary subject is malformed")
        effect = bundle["transition"]["effect_document"]
        operation = subject["operation"]
        matches = [
            _project_operation(candidate, ordinal)
            for ordinal, candidate in enumerate(effect["operations"])
            if _project_operation(candidate, ordinal) == operation
        ]
        if len(matches) != 1:
            raise RuntimeError("effect-boundary operation is absent or ambiguous")
        dependents = _required_success_dependents(effect, operation)
        dependent = subject["dependent-operation"]
        if dependent not in dependents:
            raise RuntimeError("effect-boundary successor is not RequiredSuccess")
        implementations = {}
        for state in (bundle.get("desired"), bundle.get("current")):
            if state is None:
                continue
            for binding in state["snapshot"]["resolution"]["binding_document"][
                "bindings"
            ]:
                if binding["id"] == effect["operations"][operation["ordinal"]]["binding"]:
                    implementation = binding["implementation"]
                    implementations[canonical(implementation)] = implementation
        if len(implementations) != 1:
            raise RuntimeError("effect-boundary terminal implementation is ambiguous")
        implementation = next(iter(implementations.values()))
        operation_document = effect["operations"][operation["ordinal"]]
        native_route = _effect_boundary_native_route(
            bundle,
            operation_document,
            implementation,
            evidence["source-authority"],
            evidence["candidate-authority"],
        )
    except RuntimeError:
        raise
    except (AttributeError, KeyError, TypeError) as error:
        raise RuntimeError("effect-boundary plan evidence is malformed") from error

    expected_edge = {
        "from": {"kind": "operation", "key": operation["key"]},
        "to": {"kind": "operation", "key": dependent["key"]},
        "kind": "required-success",
    }
    if (
        subject["schema"] != EFFECT_BOUNDARY_COHORT_SUBJECT_SCHEMA
        or subject["plan"] != bundle["plan"]
        or subject["plan-bundle-digest"]
        != sha256(bundle)
        or subject["evidence-digest"]
        != "sha256:" + hashlib.sha256(evidence_bytes).hexdigest()
        or subject["adapter"] != cell["adapter"]
        or operation["interface"] != cell["interface"]
        or operation["method"] != cell["method"]
        or operation["target"]["interface"] != cell["interface"]
        or subject["dependency-edge"] != expected_edge
        or expected_edge not in effect["edges"]
        or subject["provider-implementation"] != implementation
        or not implementation.get("handler")
        or subject["native-route"] != native_route
    ):
        raise RuntimeError("effect-boundary subject differs from its production plan")


def _validate_effect_boundary_probe_facts(
    postcondition: str,
    observations: dict[str, Any],
    subject: dict[str, Any],
    cell: dict[str, Any],
) -> None:
    """Validates independently observed facts for actual provider effects."""

    scenario = _cell_scenario(cell)
    expected_boundary = {
        "interrupt-after-acquisition": "resources-acquired",
        "interrupt-after-durable-intent": "effect-intent-durable",
        "lose-external-result": "effect-returned",
        "interrupt-after-durable-outcome": "effect-outcome-durable",
    }.get(scenario)
    if expected_boundary is None:
        raise RuntimeError("effect-boundary cohort names another scenario")

    if postcondition == "durable-attempt-state-classified":
        expected_fields = {
            "transaction",
            "plan",
            "operation",
            "provider-implementation",
            "journal-before-loss",
            "timeline",
            "boundary-timeline",
            "interruption-position",
            "settlement-sequence",
            "settlement-position",
        }
        boundaries = observations.get("boundary-timeline")
        interruption = observations.get("interruption-position")
        timeline = observations.get("timeline")
        expected_timeline = _effect_boundary_attempt_timeline(
            scenario, cell["required_target_access"]
        )
        if (
            set(observations) != expected_fields
            or not _matches(LOCAL_KEY, observations.get("transaction"))
            or observations.get("plan") != subject["plan"]
            or observations.get("operation") != subject["operation"]
            or observations.get("provider-implementation")
            != subject["provider-implementation"]
            or not _matches(RAW_DIGEST, observations.get("journal-before-loss"))
            or not _is_ordered_operation_timeline(
                timeline, subject["operation"]["ordinal"]
            )
            or [event.get("kind") for event in timeline or []]
            != expected_timeline
            or not _is_ordered_boundary_timeline(boundaries)
            or not any(
                entry["transcript-position"] == interruption
                and entry["purpose"] == "effect"
                and entry["boundary"] == expected_boundary
                for entry in boundaries
            )
            or observations.get("settlement-sequence") != timeline[-1]["sequence"]
            or observations.get("settlement-position")
            != boundaries[-1]["transcript-position"]
        ):
            raise RuntimeError("effect-boundary journal facts are invalid")
    elif postcondition == "at-most-one-resource-owner":
        if (
            set(observations)
            != {
                "resource",
                "owner-baseline",
                "owner-unsettled",
                "owner-after",
                "one-owner-throughout",
                "live-observation-baseline",
                "live-observation-unsettled",
                "live-observation-after",
                "live-digest-baseline",
                "live-digest-unsettled",
                "live-digest-after",
                "external-effect-returned",
                "mutation-observed-before-loss",
            }
            or observations.get("resource") != subject["operation"]["target"]["resource"]
            or not all(
                _single_owner_inventory(observations.get(field))
                for field in ("owner-baseline", "owner-unsettled", "owner-after")
            )
            or any(
                owner.get("resource")
                != subject["operation"]["target"]["resource"]
                for inventory in (
                    observations.get("owner-baseline"),
                    observations.get("owner-unsettled"),
                    observations.get("owner-after"),
                )
                for owner in inventory["identities"]
            )
            or observations.get("one-owner-throughout") is not True
            or observations.get("live-digest-baseline")
            != sha256(observations.get("live-observation-baseline"))
            or observations.get("live-digest-unsettled")
            != sha256(observations.get("live-observation-unsettled"))
            or observations.get("live-digest-after")
            != sha256(observations.get("live-observation-after"))
            or observations.get("external-effect-returned")
            is not (
                scenario
                in {"lose-external-result", "interrupt-after-durable-outcome"}
            )
            or observations.get("mutation-observed-before-loss")
            is not (
                observations.get("live-digest-baseline")
                != observations.get("live-digest-unsettled")
            )
            or (
                cell["required_target_access"] != "read"
                and observations.get("mutation-observed-before-loss")
                is not observations.get("external-effect-returned")
            )
        ):
            raise RuntimeError("effect-boundary ownership facts are invalid")
    elif postcondition == "foreign-resources-unchanged":
        if (
            set(observations)
            != {
                "resource",
                "snapshot-baseline",
                "snapshot-unsettled",
                "snapshot-after",
                "unchanged",
            }
            or not isinstance(observations.get("resource"), dict)
            or not (
                observations.get("snapshot-baseline")
                == observations.get("snapshot-unsettled")
                == observations.get("snapshot-after")
            )
            or observations.get("unchanged") is not True
        ):
            raise RuntimeError("effect-boundary foreign-resource facts are invalid")
    elif postcondition == "dependent-effects-not-executed":
        before = observations.get("timeline-before-settlement")
        after = observations.get("timeline-after-settlement")
        boundary_after = observations.get("boundary-timeline-after-settlement")
        if (
            set(observations)
            != {
                "operation",
                "dependent-operation",
                "dependency-edge",
                "timeline-before-settlement",
                "timeline-after-settlement",
                "boundary-timeline-after-settlement",
                "blocked",
                "settlement-sequence",
                "settlement-position",
            }
            or observations.get("operation") != subject["operation"]
            or observations.get("dependent-operation") != subject["dependent-operation"]
            or observations.get("dependency-edge") != subject["dependency-edge"]
            or before != []
            or not _is_ordered_operation_timeline(
                after, subject["dependent-operation"]["ordinal"]
            )
            or not _is_ordered_boundary_timeline(boundary_after)
            or after[0]["sequence"] <= observations.get("settlement-sequence", -1)
            or boundary_after[0]["transcript-position"]
            <= observations.get("settlement-position", -1)
            or observations.get("blocked") is not True
        ):
            raise RuntimeError("effect-boundary dependency facts are invalid")
    else:
        raise RuntimeError("effect-boundary cohort carries another postcondition")


def _cancellation_oracle_snapshot(
    matrix_spec: dict[str, Any], adapter: str, value: Any
) -> bool:
    """Checks that a live snapshot names the adapter's independent oracle kind."""

    expected = _observation_kind(_adapter_claim(matrix_spec, adapter))
    return provider_evidence.valid_cancellation_snapshot(expected, value)

def _cancellation_foreign_snapshot(
    matrix_spec: dict[str, Any], value: Any
) -> bool:
    """Checks one separately addressed provider sentinel observation."""

    if not isinstance(value, dict) or set(value) != {
        "adapter",
        "resource",
        "observation",
    }:
        return False
    adapter = value.get("adapter")
    return (
        isinstance(adapter, str)
        and isinstance(value.get("resource"), dict)
        and _cancellation_oracle_snapshot(
            matrix_spec, adapter, value.get("observation")
        )
    )

def _validate_cancellation_probe_facts(
    postcondition: str,
    observations: dict[str, Any],
    subject: dict[str, Any],
    cell: dict[str, Any],
    matrix_spec: dict[str, Any],
) -> None:
    """Validates a supported cancellation against independent provider state."""

    operation = subject["operation"]
    resource = operation["target"]["resource"]
    common = {
        "cell": cell["id"],
        "postcondition": postcondition,
    }
    if any(observations.get(field) != value for field, value in common.items()):
        raise RuntimeError("cancellation probe is not bound to its exact matrix cell")

    if postcondition == "durable-attempt-state-classified":
        expected_fields = {
            "cell",
            "postcondition",
            "transaction",
            "operation",
            "switch-process",
            "journal-before-signal",
            "timeline",
            "boundary-timeline",
            "cancellation-result",
            "live-before",
            "live-unsettled",
            "live-after",
        }
        timeline = observations.get("timeline")
        boundaries = observations.get("boundary-timeline")
        kinds = [event.get("kind") for event in timeline or []]
        results = [kind for kind in kinds if kind in CANCELLATION_RESULTS]
        if (
            set(observations) != expected_fields
            or not _matches(LOCAL_KEY, observations.get("transaction"))
            or observations.get("operation") != operation
            or not _is_nonnegative_int(observations.get("switch-process"))
            or observations["switch-process"] == 0
            or not _matches(RAW_DIGEST, observations.get("journal-before-signal"))
            or not _is_ordered_operation_timeline(timeline, operation["ordinal"])
            or kinds[:3]
            != ["operation-admitted", "effect-started", "cancellation-started"]
            or len(results) != 1
            or kinds[-1] != results[0]
            or observations.get("cancellation-result") != results[0]
            or not _is_ordered_boundary_timeline(boundaries)
            or [(event["purpose"], event["boundary"]) for event in boundaries]
            != CANCELLATION_BOUNDARIES
            or not all(
                _cancellation_oracle_snapshot(matrix_spec, cell["adapter"], observations.get(field))
                for field in ("live-before", "live-unsettled", "live-after")
            )
            or observations.get("live-before") != observations.get("live-unsettled")
            or observations.get("live-before") != observations.get("live-after")
        ):
            raise RuntimeError("cancellation journal or provider facts are invalid")
    elif postcondition == "at-most-one-resource-owner":
        expected_fields = {
            "cell",
            "postcondition",
            "resource",
            "owner-before",
            "owner-unsettled",
            "owner-after",
        }
        inventories = [
            observations.get("owner-before"),
            observations.get("owner-unsettled"),
            observations.get("owner-after"),
        ]
        if (
            set(observations) != expected_fields
            or observations.get("resource") != resource
            or not all(_single_owner_inventory(value) for value in inventories)
            or any(
                owner.get("resource") != resource
                for inventory in inventories
                for owner in inventory["identities"]
            )
        ):
            raise RuntimeError("cancellation ownership facts are invalid")
    elif postcondition == "foreign-resources-unchanged":
        expected_fields = {
            "cell",
            "postcondition",
            "foreign-before",
            "foreign-unsettled",
            "foreign-after",
        }
        before = observations.get("foreign-before")
        if (
            set(observations) != expected_fields
            or not _cancellation_foreign_snapshot(matrix_spec, before)
            or before.get("resource") == resource
            or observations.get("foreign-unsettled") != before
            or observations.get("foreign-after") != before
        ):
            raise RuntimeError("cancellation foreign-resource facts are invalid")
    elif postcondition == "dependent-effects-not-executed":
        expected_fields = {
            "cell",
            "postcondition",
            "predecessor-operation",
            "dependent-operation",
            "dependent-timeline-before",
            "dependent-timeline-after",
            "dependent-boundaries",
            "dependent-effect-count",
        }
        if (
            set(observations) != expected_fields
            or observations.get("predecessor-operation") != operation
            or observations.get("dependent-operation")
            != subject["dependent-operation"]
            or observations.get("dependent-timeline-before") != []
            or observations.get("dependent-timeline-after") != []
            or observations.get("dependent-boundaries") != []
            or observations.get("dependent-effect-count") != 0
        ):
            raise RuntimeError("cancellation dependency facts are invalid")
    else:
        raise RuntimeError("cancellation cohort carries another postcondition")

_SUBJECT_VALIDATORS = {
    CANCELLATION_COHORT_SUBJECT_SCHEMA: (
        _validate_cancellation_subject,
        _validate_cancellation_probe_facts,
    ),
    EFFECT_BOUNDARY_COHORT_SUBJECT_SCHEMA: (
        _validate_effect_boundary_subject,
        _validate_effect_boundary_probe_facts,
    ),
}


def accepts_subject(subject: Any) -> bool:
    """Returns whether this module owns the subject's closed schema."""

    return isinstance(subject, dict) and subject.get("schema") in _SUBJECT_VALIDATORS


def validate_subject(
    cell: dict[str, Any],
    subject: Any,
    evidence_bytes: Any,
    matrix_spec: dict[str, Any] | None,
    routes: list[dict[str, Any]],
) -> None:
    """Validates a generic operation subject against its retained evidence."""

    if not accepts_subject(subject):
        raise RuntimeError("operation evidence subject has an unsupported schema")
    validator = _SUBJECT_VALIDATORS[subject["schema"]][0]
    if subject["schema"] == CANCELLATION_COHORT_SUBJECT_SCHEMA:
        validator(cell, subject, evidence_bytes, matrix_spec, routes)
    else:
        validator(cell, subject, evidence_bytes)


def validate_probe(
    postcondition: str,
    observations: dict[str, Any],
    subject: dict[str, Any],
    cell: dict[str, Any],
    matrix_spec: dict[str, Any] | None,
) -> None:
    """Validates one postcondition through its subject's operation semantics."""

    if not accepts_subject(subject):
        raise RuntimeError("operation evidence probe has an unsupported subject")
    validator = _SUBJECT_VALIDATORS[subject["schema"]][1]
    if subject["schema"] == EFFECT_BOUNDARY_COHORT_SUBJECT_SCHEMA:
        validator(postcondition, observations, subject, cell)
    else:
        if matrix_spec is None:
            raise RuntimeError("operation evidence probe lacks its matrix specification")
        validator(postcondition, observations, subject, cell, matrix_spec)
