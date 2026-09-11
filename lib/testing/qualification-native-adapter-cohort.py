"""Builds exact matrix cells from independently retained production probes."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


PROBE_SCHEMA = "aos.release.native-adapter-postcondition-probe/v1"
POSTCONDITION_KINDS = {
    "durable-attempt-state-classified": "journal-timeline",
    "at-most-one-resource-owner": "ownership-inventory",
    "foreign-resources-unchanged": "foreign-resource-snapshot",
    "dependent-effects-not-executed": "dependency-barrier",
    "fresh-receiving-authority": "authority-incarnation",
    "compatible-state-adopted": "state-adoption",
    "exactly-one-resource-owner": "exact-ownership-inventory",
    "transfer-rejected-before-candidate-effect": "transfer-rejection",
    "predecessor-remains-sole-owner": "predecessor-ownership",
    "current-grants-reauthorized": "authority-grants",
    "retained-target-identity-preserved": "target-identity",
    "prerequisite-failure-recorded": "prerequisite-failure",
    "foreign-attempt-rejected-before-mutation": "foreign-attempt-rejection",
}
TOKEN = re.compile(r"[a-z0-9.-]{1,96}").fullmatch
LOCAL_KEY = re.compile(r"[A-Za-z0-9._-]{1,128}").fullmatch
DIGEST = re.compile(r"sha256:[0-9a-f]{64}").fullmatch
RAW_DIGEST = re.compile(r"[0-9a-f]{64}").fullmatch
MAX_PROBE_FACTS = 32
MAX_PROBE_BYTES = 64 * 1024
QUALIFIED_CELL_ID = (
    "managed-configuration/aos.managed-configuration-effects/abi-1/"
    "publish/lose-external-result"
)
COHORT_SUBJECT_SCHEMA = "aos.qualification.host-resource-cohort-subject/v1"
PUBLISH_ORDINAL = 5
DEPENDENT_ORDINAL = 2
FIXTURE_ENVIRONMENT = {
    "authority": "reference",
    "key": "host",
    "stage": "host",
}
MANAGED_CONFIGURATION_INTERFACE = {
    "name": "aos.managed-configuration-effects",
    "abi": 1,
    "descriptor": "sha256:682ee08aadd9d0198b409146a373bf38d901ba530b74180400c9087616a41dab",
}
SYSTEMD_SERVICE_INTERFACE = {
    "name": "aos.systemd-service-effects",
    "abi": 1,
    "descriptor": "sha256:e02cd9535b3f97fbaf41066fd4b6ac8c2aa315f38188fb669815dccd291b4f98",
}
PUBLISH_TARGET = {
    "interface": MANAGED_CONFIGURATION_INTERFACE,
    "resource": {
        "provider": {
            "environment": FIXTURE_ENVIRONMENT,
            "key": "shared-configuration",
        },
        "key": "nginx-secondary-configuration",
    },
    "operations": ["publish"],
    "lifetime": "instance",
}
DEPENDENT_TARGET = {
    "interface": SYSTEMD_SERVICE_INTERFACE,
    "resource": {
        "provider": {
            "environment": FIXTURE_ENVIRONMENT,
            "key": "shared-service",
        },
        "key": "nginx-secondary-service",
    },
    "operations": ["reload"],
    "lifetime": "instance",
}
LOST_RESULT_TIMELINE = [
    "operation-admitted",
    "effect-started",
    "operation-admitted",
    "reconciliation-started",
    "reconciled-completed",
]
LOST_RESULT_BOUNDARY_TIMELINE = [
    ("effect", "effect-intent-durable"),
    ("effect", "effect-returned"),
    ("reconcile", "reconciliation-intent-durable"),
    ("reconcile", "reconciliation-returned"),
    ("reconcile", "reconciliation-outcome-durable"),
]
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


def canonical(value: Any) -> bytes:
    """Encodes one value in the canonical JSON dialect used by evidence."""

    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def sha256(value: Any) -> str:
    """Computes the raw canonical SHA-256 identity of one value."""

    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def build_cells(
    spec: dict[str, Any],
    submissions: dict[str, Any],
    expected_qualified_cells: list[str],
    cohort_subject: dict[str, Any],
    cohort_plan_bundle: bytes,
    subject_digest: str,
    environment_digest: str,
) -> tuple[list[dict[str, Any]], int]:
    """Builds all cell observations and proves every positive claim is expected."""

    if sorted(submissions) != sorted(expected_qualified_cells):
        raise RuntimeError("cohort probe cells differ from its explicit qualification scope")
    if len(set(expected_qualified_cells)) != len(expected_qualified_cells):
        raise RuntimeError("cohort qualification scope repeats a matrix cell")

    specification_cells = {cell["id"]: cell for cell in spec["cells"]}
    if len(specification_cells) != len(spec["cells"]):
        raise RuntimeError("matrix specification repeats a cell identity")
    if any(cell_id not in specification_cells for cell_id in submissions):
        raise RuntimeError("cohort submitted a probe outside the exact matrix surface")
    if expected_qualified_cells != [QUALIFIED_CELL_ID]:
        raise RuntimeError("cohort qualification scope differs from its fixed fixture")
    qualified_cell = specification_cells[QUALIFIED_CELL_ID]
    _validate_cohort_subject(qualified_cell, cohort_subject, cohort_plan_bundle)
    cohort_subject_digest = sha256(cohort_subject)

    observed_cells = []
    postcondition_count = 0
    for cell in spec["cells"]:
        submitted = submissions.get(cell["id"])
        names = cell["postconditions"]
        postcondition_count += len(names)
        if submitted is None:
            postconditions = {
                name: {
                    "passed": False,
                    "detail": "not exercised by this production cohort",
                }
                for name in names
            }
            probes = {}
        else:
            postconditions, probes = _validated_probes(
                names,
                submitted,
                cohort_subject,
                cohort_subject_digest,
                subject_digest,
            )

        observation = {
            "id": cell["id"],
            "cell_digest": sha256(cell),
            "environment_digest": environment_digest,
            "postconditions": postconditions,
        }
        if probes:
            observation["probes"] = probes
            observation["cohort_subject"] = cohort_subject
        observed_cells.append(observation)

    return observed_cells, postcondition_count


def _validated_probes(
    postcondition_names: list[str],
    submitted: dict[str, Any],
    cohort_subject: dict[str, Any],
    cohort_subject_digest: str,
    subject_digest: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if set(submitted) != set(postcondition_names):
        raise RuntimeError("qualified cell lacks an exact postcondition probe set")

    postconditions = {}
    probes = {}
    observation_digests = set()
    for name in postcondition_names:
        record = submitted[name]
        if set(record) != {"kind", "detail", "observations"}:
            raise RuntimeError("postcondition probe has unknown or missing fields")
        expected_kind = POSTCONDITION_KINDS.get(name)
        observations = record["observations"]
        if (
            record["kind"] != expected_kind
            or not isinstance(record["detail"], str)
            or not record["detail"].strip()
            or not isinstance(observations, dict)
            or not 1 <= len(observations) <= MAX_PROBE_FACTS
            or any(
                not isinstance(key, str) or TOKEN(key) is None or value is None
                for key, value in observations.items()
            )
            or len(canonical(observations)) > MAX_PROBE_BYTES
        ):
            raise RuntimeError("postcondition probe is malformed")
        _validate_probe_facts(name, observations, cohort_subject)
        observation_digest = sha256(observations)
        if observation_digest in observation_digests:
            raise RuntimeError("passing postconditions do not have independent probes")
        observation_digests.add(observation_digest)

        postconditions[name] = {"passed": True, "detail": record["detail"]}
        probes[name] = {
            "schema_version": PROBE_SCHEMA,
            "kind": record["kind"],
            "subject_digest": subject_digest,
            "cohort_subject_digest": cohort_subject_digest,
            "observation_digest": observation_digest,
            "observations": observations,
        }

    return postconditions, probes


def _validate_probe_facts(
    postcondition: str,
    observations: dict[str, Any],
    cohort_subject: dict[str, Any],
) -> None:
    """Checks the independent facts used by the first host-resource cohort."""

    if postcondition == "durable-attempt-state-classified":
        operation = observations.get("operation")
        timeline = observations.get("timeline")
        boundary_timeline = observations.get("boundary-timeline")
        expected_fields = {
            "transaction",
            "plan",
            "journal-before-loss",
            "operation",
            "timeline",
            "boundary-timeline",
            "effect-return-position",
            "reconciliation-return-position",
        }
        if (
            set(observations) != expected_fields
            or not _matches(LOCAL_KEY, observations.get("transaction"))
            or not _matches(DIGEST, observations.get("plan"))
            or observations.get("plan") != cohort_subject["plan"]
            or not _matches(RAW_DIGEST, observations.get("journal-before-loss"))
            or operation != cohort_subject["publish-operation"]
            or not _is_exact_timeline(
                timeline, LOST_RESULT_TIMELINE, operation.get("ordinal")
            )
            or not _is_exact_boundary_timeline(
                boundary_timeline, LOST_RESULT_BOUNDARY_TIMELINE
            )
            or observations.get("effect-return-position")
            != boundary_timeline[1]["transcript-position"]
            or observations.get("reconciliation-return-position")
            != boundary_timeline[3]["transcript-position"]
        ):
            raise RuntimeError("journal probe does not prove lost-result reconciliation")
    elif postcondition == "at-most-one-resource-owner":
        if (
            observations.get("matching-markers") != 1
            or observations.get("selected-after-gc") is not True
            or not isinstance(observations.get("resource"), dict)
        ):
            raise RuntimeError("ownership probe does not prove one retained owner")
    elif postcondition == "foreign-resources-unchanged":
        snapshots = [
            observations.get("content-before"),
            observations.get("content-unsettled"),
            observations.get("content-after-gc"),
            observations.get("content-after-recovery"),
        ]
        if (
            snapshots[0] is None
            or any(snapshot != snapshots[0] for snapshot in snapshots[1:])
            or not isinstance(observations.get("resource"), dict)
        ):
            raise RuntimeError("foreign-resource probe changed across the cohort")
    elif postcondition == "dependent-effects-not-executed":
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
            "publish-reconciled-sequence",
            "publish-reconciliation-return-position",
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
            or not _is_nonnegative_int(observations.get("publish-reconciled-sequence"))
            or observations["publish-reconciled-sequence"] >= timeline_after[0]["sequence"]
            or not _is_nonnegative_int(
                observations.get("publish-reconciliation-return-position")
            )
            or observations["publish-reconciliation-return-position"]
            >= boundary_after[0]["transcript-position"]
            or observations.get("dependent-effect-return-position")
            != boundary_after[1]["transcript-position"]
            or not isinstance(before, str)
            or not isinstance(after, str)
            or before == after
            or observations.get("changed-only-after-recovery") is not True
        ):
            raise RuntimeError("dependency probe does not retain the predecessor result")


def _validate_cohort_subject(
    cell: dict[str, Any], subject: Any, plan_bundle_bytes: Any
) -> None:
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
    if (
        subject != expected_subject
        or subject.get("schema") != COHORT_SUBJECT_SCHEMA
        or not _matches(DIGEST, subject.get("plan"))
        or not _matches(DIGEST, subject.get("plan-bundle-digest"))
        or not isinstance(authors, dict)
        or set(authors) != {"publish", "dependent"}
        or cell.get("interface") != MANAGED_CONFIGURATION_INTERFACE
        or cell.get("method") != "publish"
        or not _is_expected_author(authors.get("publish"), "shared-configuration")
        or not _is_expected_author(authors.get("dependent"), "nginx-secondary")
        or not _is_expected_operation(
            subject.get("publish-operation"),
            authors["publish"],
            "publish-nginx-secondary-configuration",
            PUBLISH_ORDINAL,
            MANAGED_CONFIGURATION_INTERFACE,
            "publish",
            PUBLISH_TARGET,
        )
        or not _is_expected_operation(
            subject.get("dependent-operation"),
            authors["dependent"],
            "reload-nginx-secondary-service",
            DEPENDENT_ORDINAL,
            SYSTEMD_SERVICE_INTERFACE,
            "reload",
            DEPENDENT_TARGET,
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
        if transition.get("schema") not in {
            "aos.ability.transition-snapshot/v1",
            "aos.ability.transition-snapshot/v2",
        }:
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


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _matches(pattern: Any, value: Any) -> bool:
    return isinstance(value, str) and pattern(value) is not None


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
