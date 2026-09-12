"""Builds exact matrix cells from independently retained production probes."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


PROBE_SCHEMA = "aos.release.native-adapter-postcondition-probe/v2"
CELL_SUBJECT_SCHEMA = "aos.release.native-adapter-cell-cohort-subject/v1"
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
QUALIFIED_CELL_PREFIX = (
    "managed-configuration/aos.managed-configuration-effects/abi-1/publish/"
)
QUALIFIED_CRASH_SCENARIOS = (
    "interrupt-after-durable-intent",
    "lose-external-result",
    "interrupt-after-durable-outcome",
)
PRIMARY_COHORT_CELL_IDS = [
    *(QUALIFIED_CELL_PREFIX + scenario for scenario in QUALIFIED_CRASH_SCENARIOS),
    (
        "managed-configuration/aos.managed-configuration-effects/abi-1/"
        "publish/reject-foreign-resource-mutation"
    ),
    (
        "systemd-service-legacy/aos.systemd-service-effects/abi-1/"
        "reload/block-dependent-effect"
    ),
]
POSTGRESQL_CELL_IDS = [
    "postgresql/aos.postgresql-effects/abi-1/materialize/adopt-compatible-state",
    "postgresql/aos.postgresql-effects/abi-1/materialize/reject-unsupported-transfer",
    "postgresql/aos.postgresql-effects/abi-1/restart/lose-external-result",
    "postgresql/aos.postgresql-effects/abi-1/restart/activate-retained-target",
]
QUALIFIED_CELL_IDS = [*PRIMARY_COHORT_CELL_IDS, *POSTGRESQL_CELL_IDS]
RUNTIME_AUDIT_SCHEMA = "aos.qualification.native-adapter-runtime-audit/v1"
RUNTIME_SUBJECT_SCHEMA = "aos.qualification.native-adapter-runtime-subject/v1"
RUNTIME_PLAN_SCHEMA = "aos.qualification.native-adapter-runtime-plan/v1"
INTERRUPTION_AUDIT_SCHEMA = "aos.qualification.interruption-audit/v1"
INTERRUPTION_SUBJECT_SCHEMA = "aos.qualification.interruption-subject/v1"
INTERRUPTION_PLAN_SCHEMA = "aos.qualification.interruption-plan/v1"
INTERRUPTION_SCENARIO = "interrupt-before-acquisition"
ROLE_SCENARIOS = {
    f"revoke-{role}-{timing}"
    for role in ["caller", "provider", "enforcement", "assignment"]
    for timing in ["before-acquisition", "after-acquisition", "before-external-effect"]
}
FAILURE_CONTROL_SCENARIOS = {
    "cancel-unsettled-attempt",
    "expire-attempt-deadline",
    "fail-cleanup",
    "fail-release",
}


def _runtime_audit_cell(cell: dict[str, Any]) -> bool:
    """Returns whether the shared runtime can qualify this exact matrix cell."""

    scenario = cell["id"].rsplit("/", 1)[-1]
    if scenario in ROLE_SCENARIOS:
        return True
    if scenario in FAILURE_CONTROL_SCENARIOS - {"cancel-unsettled-attempt"}:
        return True

    return (
        scenario == "cancel-unsettled-attempt"
        and cell.get("recovery", {}).get("cancel") is None
    )


EFFECT_BOUNDARY_SCENARIOS = {
    "interrupt-after-acquisition",
    "interrupt-after-durable-intent",
    "lose-external-result",
    "interrupt-after-durable-outcome",
}
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


def _effect_boundary_attempt_timeline(
    scenario: str, effect_class: str
) -> list[str]:
    """Returns the exact recovery classification for one effect class."""

    if (
        scenario == "interrupt-after-durable-intent"
        and effect_class == "observation"
    ):
        return [
            "operation-admitted",
            "effect-started",
            "operation-admitted",
            "reconciliation-started",
            "reconciled-completed",
        ]
    return EFFECT_BOUNDARY_ATTEMPT_TIMELINES[scenario]
EFFECT_BOUNDARY_ADAPTER_GROUPS = [
    {
        "credential-delivery",
        "host-network-policy",
        "host-storage",
        "managed-configuration",
        "network-endpoint",
        "nginx-validation",
        "systemd-service-legacy",
    },
    {"systemd-manager"},
    {"postgresql"},
    {"kubernetes-object", "systemd-bootstrap"},
    {"image-rollout"},
    {"foreground-process"},
]


def _effect_boundary_cell(cell: dict[str, Any]) -> bool:
    """Returns whether the cell belongs to the provider-effect interruption cohort."""

    return (
        cell["id"].rsplit("/", 1)[-1] in EFFECT_BOUNDARY_SCENARIOS
        and cell["id"] not in PRIMARY_COHORT_CELL_IDS
        and cell["id"] not in POSTGRESQL_CELL_IDS
    )


COHORT_SUBJECT_SCHEMA = "aos.qualification.host-resource-cohort-subject/v1"
POSTGRESQL_COHORT_SUBJECT_SCHEMA = (
    "aos.qualification.postgresql-provider-replacement-cohort-subject/v1"
)
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
CANCELLATION_HANDLER_ENTRY_POINTS = {
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
CANCELLATION_ORACLE_KINDS = {
    "credential-delivery": "filesystem",
    "foreground-process": "foreground-process",
    "host-network-policy": "network",
    "host-storage": "filesystem",
    "managed-configuration": "filesystem",
    "network-endpoint": "network",
    "nginx-validation": "filesystem",
    "postgresql": "postgresql",
    "kubernetes-object": "kubernetes",
    "systemd-bootstrap": "systemd",
    "systemd-manager": "systemd",
    "systemd-service-legacy": "systemd",
    "image-rollout": "image-rollout",
}
POSTGRESQL_REJECTION_EVIDENCE_SCHEMA = (
    "aos.qualification.postgresql-provider-rejection-evidence/v1"
)
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
INTERRUPTED_INTENT_TIMELINE = [
    "operation-admitted",
    "effect-started",
    "operation-admitted",
    "reconciliation-started",
    "reconciled-safe-to-retry",
    "operation-admitted",
    "effect-started",
    "effect-completed",
]
INTERRUPTED_INTENT_BOUNDARY_TIMELINE = [
    ("effect", "effect-intent-durable"),
    ("reconcile", "reconciliation-intent-durable"),
    ("reconcile", "reconciliation-returned"),
    ("reconcile", "reconciliation-outcome-durable"),
    ("effect", "effect-intent-durable"),
    ("effect", "effect-returned"),
    ("effect", "effect-outcome-durable"),
]
DURABLE_OUTCOME_TIMELINE = [
    "operation-admitted",
    "effect-started",
    "effect-completed",
]
DURABLE_OUTCOME_BOUNDARY_TIMELINE = [
    ("effect", "effect-intent-durable"),
    ("effect", "effect-returned"),
    ("effect", "effect-outcome-durable"),
]
EXPECTED_ATTEMPT_TIMELINES = {
    "interrupt-after-durable-intent": INTERRUPTED_INTENT_TIMELINE,
    "lose-external-result": LOST_RESULT_TIMELINE,
    "interrupt-after-durable-outcome": DURABLE_OUTCOME_TIMELINE,
}
EXPECTED_ATTEMPT_BOUNDARIES = {
    "interrupt-after-durable-intent": INTERRUPTED_INTENT_BOUNDARY_TIMELINE,
    "lose-external-result": LOST_RESULT_BOUNDARY_TIMELINE,
    "interrupt-after-durable-outcome": DURABLE_OUTCOME_BOUNDARY_TIMELINE,
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
    cohort_subjects: dict[str, dict[str, Any]],
    cohort_evidence: dict[str, bytes],
    subject_digest: str,
    environment_digest: str,
    runtime_audit: dict[str, Any] | None = None,
    interruption_audit: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Builds all cell observations and proves every positive claim is expected."""

    has_runtime_audit = runtime_audit is not None
    runtime_audit = runtime_audit or {
        "schema": RUNTIME_AUDIT_SCHEMA,
        "matrix_spec_digest": "sha256:" + "0" * 64,
        "cells": {},
    }
    runtime_cells = runtime_audit.get("cells")
    if not isinstance(runtime_cells, dict):
        raise RuntimeError("runtime audit cells are malformed")
    has_interruption_audit = interruption_audit is not None
    interruption_audit = interruption_audit or {
        "schema": INTERRUPTION_AUDIT_SCHEMA,
        "matrix_spec_digest": "sha256:" + "0" * 64,
        "cells": {},
    }
    interruption_cells = interruption_audit.get("cells")
    if not isinstance(interruption_cells, dict):
        raise RuntimeError("interruption audit cells are malformed")
    submitted_cells = set(submissions) | set(runtime_cells) | set(interruption_cells)
    if submitted_cells != set(expected_qualified_cells):
        raise RuntimeError("cohort probe cells differ from its explicit qualification scope")
    if len(set(expected_qualified_cells)) != len(expected_qualified_cells):
        raise RuntimeError("cohort qualification scope repeats a matrix cell")

    specification_cells = {cell["id"]: cell for cell in spec["cells"]}
    if len(specification_cells) != len(spec["cells"]):
        raise RuntimeError("matrix specification repeats a cell identity")
    if any(cell_id not in specification_cells for cell_id in submitted_cells):
        raise RuntimeError("cohort submitted a probe outside the exact matrix surface")
    allowed_cells = QUALIFIED_CELL_IDS
    effect_boundary_cells = [
        cell["id"]
        for adapters in EFFECT_BOUNDARY_ADAPTER_GROUPS
        for cell in spec["cells"]
        if cell["adapter"] in adapters and _effect_boundary_cell(cell)
    ]
    supported_cancellation_cells = [
        cell["id"]
        for cell in spec["cells"]
        if _cell_scenario(cell) == "cancel-unsettled-attempt"
        and cell.get("recovery", {}).get("cancel") is not None
    ]
    if has_runtime_audit:
        runtime_failure_cells = [
            cell["id"]
            for cell in spec["cells"]
            if _runtime_audit_cell(cell)
            and cell["id"].rsplit("/", 1)[-1] in FAILURE_CONTROL_SCENARIOS
        ]
        runtime_role_cells = [
            cell["id"]
            for cell in spec["cells"]
            if cell["id"].rsplit("/", 1)[-1] in ROLE_SCENARIOS
        ]
        allowed_cells = [
            *PRIMARY_COHORT_CELL_IDS,
            *runtime_role_cells,
            *runtime_failure_cells,
            *POSTGRESQL_CELL_IDS,
            *effect_boundary_cells,
            *supported_cancellation_cells,
        ]
    else:
        allowed_cells = [
            *allowed_cells,
            *effect_boundary_cells,
            *supported_cancellation_cells,
        ]

    if has_interruption_audit:
        before_acquisition_cells = [
            cell["id"]
            for cell in spec["cells"]
            if cell["id"].rsplit("/", 1)[-1] == INTERRUPTION_SCENARIO
        ]
        insertion = len(PRIMARY_COHORT_CELL_IDS)
        allowed_cells = [
            *allowed_cells[:insertion],
            *before_acquisition_cells,
            *allowed_cells[insertion:],
        ]
    if (
        not expected_qualified_cells
        or any(cell_id not in allowed_cells for cell_id in expected_qualified_cells)
        or expected_qualified_cells
        != [cell_id for cell_id in allowed_cells if cell_id in expected_qualified_cells]
    ):
        raise RuntimeError("cohort qualification scope differs from its fixed fixture")
    if set(cohort_subjects) != set(submissions):
        raise RuntimeError("cohort subjects differ from its explicit qualification scope")
    if set(cohort_evidence) != set(submissions):
        raise RuntimeError("cohort evidence differs from its explicit qualification scope")
    for cell_id in submissions:
        _validate_cohort_subject(
            specification_cells[cell_id],
            cohort_subjects[cell_id],
            cohort_evidence[cell_id],
            spec,
        )
    if has_runtime_audit:
        _validate_runtime_audit(runtime_audit, spec, specification_cells)
    if has_interruption_audit:
        _validate_interruption_audit(interruption_audit, spec, specification_cells)

    observed_cells = []
    postcondition_count = 0
    probe_digests = set()
    for cell in spec["cells"]:
        submitted = submissions.get(cell["id"])
        runtime_record = runtime_cells.get(cell["id"])
        interruption_record = interruption_cells.get(cell["id"])
        names = cell["postconditions"]
        postcondition_count += len(names)
        if runtime_record is not None:
            if cell["id"].rsplit("/", 1)[-1] in ROLE_SCENARIOS:
                bound_subject, postconditions, probes = _validated_authority_cell(
                    cell, runtime_record, subject_digest, probe_digests
                )
            else:
                bound_subject, postconditions, probes = _validated_failure_control_cell(
                    cell, runtime_record, subject_digest, probe_digests
                )
        elif interruption_record is not None:
            bound_subject, postconditions, probes = _validated_interruption_cell(
                cell,
                interruption_record,
                subject_digest,
                probe_digests,
            )
        elif submitted is None:
            postconditions = {
                name: {
                    "passed": False,
                    "detail": "not exercised by this production cohort",
                }
                for name in names
            }
            probes = {}
        else:
            cohort_subject = cohort_subjects[cell["id"]]
            bound_subject = _bound_cohort_subject(cell, cohort_subject)
            postconditions, probes = _validated_probes(
                cell,
                submitted,
                cohort_subject,
                bound_subject,
                subject_digest,
                probe_digests,
            )

        observation = {
            "id": cell["id"],
            "cell_digest": sha256(cell),
            "environment_digest": environment_digest,
            "postconditions": postconditions,
        }
        if probes:
            observation["probes"] = probes
            observation["cohort_subject"] = bound_subject
        observed_cells.append(observation)

    return observed_cells, postcondition_count


def _validate_interruption_audit(
    audit: dict[str, Any],
    spec: dict[str, Any],
    specification_cells: dict[str, dict[str, Any]],
) -> None:
    """Checks the exact generic before-acquisition interruption cohort."""

    expected = {
        cell_id
        for cell_id in specification_cells
        if cell_id.rsplit("/", 1)[-1] == INTERRUPTION_SCENARIO
    }
    if (
        set(audit) != {"schema", "matrix_spec_digest", "cells"}
        or audit.get("schema") != INTERRUPTION_AUDIT_SCHEMA
        or audit.get("matrix_spec_digest") != sha256(spec)
        or set(audit.get("cells", {})) != expected
    ):
        raise RuntimeError("interruption audit differs from the closed before-acquisition cohort")


def _validated_interruption_cell(
    cell: dict[str, Any],
    record: dict[str, Any],
    subject_digest: str,
    probe_digests: set[str],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Validates one candidate-linked admission interruption and derives probes."""

    if set(record) != {"cell_digest", "subject", "plan_bundle", "evidence"}:
        raise RuntimeError("interruption audit cell is malformed")
    cell_digest = sha256(cell)
    subject = record["subject"]
    plan_bundle = record["plan_bundle"]
    evidence = record["evidence"]
    expected_subject_fields = {
        "schema",
        "cell-id",
        "cell-digest",
        "interface",
        "method",
        "plan",
        "transaction",
        "operation",
        "dependent-operation",
    }
    if (
        record.get("cell_digest") != cell_digest
        or cell["id"].rsplit("/", 1)[-1] != INTERRUPTION_SCENARIO
        or not isinstance(subject, dict)
        or set(subject) != expected_subject_fields
        or subject.get("schema") != INTERRUPTION_SUBJECT_SCHEMA
        or subject.get("cell-id") != cell["id"]
        or subject.get("cell-digest") != cell_digest
        or subject.get("interface") != cell["interface"]
        or subject.get("method") != cell["method"]
        or not _matches(DIGEST, subject.get("plan"))
        or not _matches(LOCAL_KEY, subject.get("transaction"))
        or not _scoped_operation_key(subject.get("operation"))
        or not _scoped_operation_key(subject.get("dependent-operation"))
        or subject.get("operation") == subject.get("dependent-operation")
        or not isinstance(plan_bundle, dict)
        or set(plan_bundle) != {"schema", "digest", "bytes-sha256"}
        or plan_bundle.get("schema") != INTERRUPTION_PLAN_SCHEMA
        or not _matches(DIGEST, plan_bundle.get("digest"))
        or plan_bundle.get("bytes-sha256") != plan_bundle.get("digest")
        or not isinstance(evidence, dict)
        or set(evidence)
        != {
            "scenario",
            "runtime-boundary",
            "declared-recovery-routes",
            "fixture-recovery-routes",
            "boundary-record",
            "journal-at-fault",
            "journal-after-restart",
            "reservation-ledger",
            "adapter-calls",
            "primary-ready-at-restart",
            "dependent-ready-at-restart",
            "foreign-before",
            "foreign-after",
        }
        or evidence.get("scenario") != INTERRUPTION_SCENARIO
        or evidence.get("runtime-boundary") != "BeforeResourceAcquisition"
        or evidence.get("declared-recovery-routes") != cell["recovery"]
        or evidence.get("fixture-recovery-routes")
        != {
            "reconcile": cell["method"] if cell["recovery"]["reconcile"] else None,
            "cancel": None,
        }
        or evidence.get("primary-ready-at-restart") is not True
        or evidence.get("dependent-ready-at-restart") is not False
        or not _matches(DIGEST, evidence.get("foreign-before"))
        or evidence.get("foreign-after") != evidence.get("foreign-before")
    ):
        raise RuntimeError("interruption audit subject or envelope is invalid")

    boundary = evidence["boundary-record"]
    boundary_bytes = boundary.get("bytes") if isinstance(boundary, dict) else None
    expected_boundary = {
        "schema": "aos.qualification.interruption-boundary/v1",
        "scenario": INTERRUPTION_SCENARIO,
        "transaction": subject["transaction"],
        "operation": {
            "plan": subject["plan"],
            "operation": subject["operation"],
        },
        "attempt": 1,
        "purpose": "effect",
        "boundary": "BeforeResourceAcquisition",
    }
    journal_at_fault = evidence["journal-at-fault"]
    journal_after_restart = evidence["journal-after-restart"]
    ledger = evidence["reservation-ledger"]
    adapter_calls = evidence["adapter-calls"]
    expected_events = {"transaction-planned": 1}
    if (
        not isinstance(boundary, dict)
        or set(boundary) != {"digest", "bytes"}
        or not _matches(DIGEST, boundary.get("digest"))
        or boundary.get("digest") != sha256(boundary_bytes)
        or boundary_bytes != expected_boundary
        or not isinstance(journal_at_fault, dict)
        or set(journal_at_fault) != {"digest", "head", "state", "events"}
        or not _matches(DIGEST, journal_at_fault.get("digest"))
        or not _matches(DIGEST, journal_at_fault.get("head"))
        or journal_at_fault.get("state") != "pending"
        or journal_at_fault.get("events") != expected_events
        or not isinstance(journal_after_restart, dict)
        or set(journal_after_restart) != {"digest", "head", "state", "events"}
        or journal_after_restart != journal_at_fault
        or not isinstance(ledger, dict)
        or set(ledger)
        != {"digest", "acquire-calls", "release-calls", "max-owners", "owners"}
        or not _matches(DIGEST, ledger.get("digest"))
        or ledger.get("acquire-calls") != 0
        or ledger.get("release-calls") != 0
        or ledger.get("max-owners") != 0
        or ledger.get("owners") != []
        or adapter_calls != {"total": 0, "dependent": 0}
    ):
        raise RuntimeError("interruption audit does not prove a pre-acquisition halt")

    bound_subject = _bound_cohort_subject(cell, subject)
    cohort_subject_digest = sha256(bound_subject)
    observations = {
        "durable-attempt-state-classified": {
            "cell": cell["id"],
            "transaction": subject["transaction"],
            "plan": subject["plan"],
            "boundary-record": boundary["digest"],
            "runtime-boundary": evidence["runtime-boundary"],
            "journal-at-fault": journal_at_fault["digest"],
            "journal-after-restart": journal_after_restart["digest"],
            "journal-head": journal_at_fault["head"],
            "state": journal_at_fault["state"],
            "primary-ready-at-restart": True,
        },
        "at-most-one-resource-owner": {
            "cell": cell["id"],
            "ledger": ledger["digest"],
            "acquire-calls": 0,
            "release-calls": 0,
            "max-owners": 0,
            "owners": [],
        },
        "foreign-resources-unchanged": {
            "cell": cell["id"],
            "snapshot-before": evidence["foreign-before"],
            "snapshot-after": evidence["foreign-after"],
            "unchanged": True,
        },
        "dependent-effects-not-executed": {
            "cell": cell["id"],
            "operation": subject["operation"],
            "dependent-operation": subject["dependent-operation"],
            "adapter-calls": adapter_calls["total"],
            "dependent-calls": adapter_calls["dependent"],
            "dependent-ready-at-restart": False,
            "blocked": True,
        },
    }
    if set(cell["postconditions"]) != set(observations):
        raise RuntimeError("interruption cell postconditions differ from its evidence contract")

    postconditions = {}
    probes = {}
    for name in cell["postconditions"]:
        facts = observations[name]
        observation_digest = sha256(facts)
        if observation_digest in probe_digests:
            raise RuntimeError("passing matrix postconditions replay a production probe")
        probe_digests.add(observation_digest)
        postconditions[name] = {
            "passed": True,
            "detail": "The candidate runtime halted before acquisition and reopened the unchanged pending journal with dependents still blocked.",
        }
        probes[name] = {
            "schema_version": PROBE_SCHEMA,
            "kind": POSTCONDITION_KINDS[name],
            "cell_id": cell["id"],
            "cell_digest": cell_digest,
            "disposition": "rejected-before-acquisition",
            "subject_digest": subject_digest,
            "cohort_subject_digest": cohort_subject_digest,
            "observation_digest": observation_digest,
            "observations": facts,
        }

    return bound_subject, postconditions, probes


def _validate_runtime_audit(
    audit: dict[str, Any],
    spec: dict[str, Any],
    specification_cells: dict[str, dict[str, Any]],
) -> None:
    """Checks the audit envelope and its exact role-cell coverage."""

    expected = {
        cell_id
        for cell_id in specification_cells
        if _runtime_audit_cell(specification_cells[cell_id])
    }
    if (
        set(audit) != {"schema", "matrix_spec_digest", "cells"}
        or audit.get("schema") != RUNTIME_AUDIT_SCHEMA
        or audit.get("matrix_spec_digest") != sha256(spec)
        or set(audit.get("cells", {})) != expected
    ):
        raise RuntimeError("runtime audit differs from the closed control cohort")


def _validated_authority_cell(
    cell: dict[str, Any],
    record: dict[str, Any],
    subject_digest: str,
    probe_digests: set[str],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Validates one real runtime authority fence result and derives its probes."""

    if set(record) != {"cell_digest", "subject", "plan_bundle", "evidence"}:
        raise RuntimeError("authority audit cell is malformed")
    cell_digest = sha256(cell)
    subject = record["subject"]
    plan_bundle = record["plan_bundle"]
    evidence = record["evidence"]
    scenario = cell["id"].rsplit("/", 1)[-1]
    role_name = scenario.removeprefix("revoke-").split("-before", 1)[0].split("-after", 1)[0]
    expected_role = {
        "caller": "caller-binding-grant",
        "provider": "provider-method-implementation",
        "enforcement": "enforcement-platform-guarantee",
        "assignment": "assignment-incarnation",
    }[role_name]
    if scenario.endswith("before-acquisition"):
        expected_authority_boundary = "before-resource-acquisition"
        expected_runtime_boundary = "BeforeResourceAcquisition"
        expected_acquisitions = 0
    elif scenario.endswith("after-acquisition"):
        expected_authority_boundary = "after-resource-acquisition"
        expected_runtime_boundary = "ResourcesAcquired"
        expected_acquisitions = 1
    else:
        expected_authority_boundary = "final-dispatch"
        expected_runtime_boundary = "FinalDispatch"
        expected_acquisitions = 1

    if (
        record.get("cell_digest") != cell_digest
        or not isinstance(subject, dict)
        or set(subject)
        != {"schema", "cell-id", "cell-digest", "interface", "method", "plan", "transaction"}
        or subject.get("schema") != RUNTIME_SUBJECT_SCHEMA
        or subject.get("cell-id") != cell["id"]
        or subject.get("cell-digest") != cell_digest
        or subject.get("interface") != cell["interface"]
        or subject.get("method") != cell["method"]
        or not _matches(DIGEST, subject.get("plan"))
        or not _matches(LOCAL_KEY, subject.get("transaction"))
        or not isinstance(plan_bundle, dict)
        or set(plan_bundle) != {"schema", "digest", "bytes-sha256"}
        or plan_bundle.get("schema") != RUNTIME_PLAN_SCHEMA
        or not _matches(DIGEST, plan_bundle.get("digest"))
        or plan_bundle.get("bytes-sha256") != plan_bundle.get("digest")
        or not isinstance(evidence, dict)
        or set(evidence)
        != {
            "role",
            "authority-boundary",
            "runtime-boundary",
            "journal",
            "reservation-ledger",
            "dispatch-calls",
            "foreign-before",
            "foreign-after",
        }
        or evidence.get("role") != expected_role
        or evidence.get("authority-boundary") != expected_authority_boundary
        or evidence.get("runtime-boundary") != expected_runtime_boundary
        or evidence.get("dispatch-calls") != 0
        or not _matches(DIGEST, evidence.get("foreign-before"))
        or evidence.get("foreign-after") != evidence.get("foreign-before")
    ):
        raise RuntimeError("authority audit subject or fence evidence is invalid")

    journal = evidence["journal"]
    ledger = evidence["reservation-ledger"]
    if (
        not isinstance(journal, dict)
        or set(journal) != {"digest", "head", "authority-rejections", "effect-outcomes"}
        or not _matches(DIGEST, journal.get("digest"))
        or not _matches(DIGEST, journal.get("head"))
        or journal.get("authority-rejections") != 1
        or journal.get("effect-outcomes") != 0
        or not isinstance(ledger, dict)
        or set(ledger) != {"digest", "acquire-calls", "release-calls", "max-owners", "owners"}
        or not _matches(DIGEST, ledger.get("digest"))
        or ledger.get("acquire-calls") != expected_acquisitions
        or ledger.get("release-calls") != expected_acquisitions
        or ledger.get("max-owners") != expected_acquisitions
        or ledger.get("owners") != 0
    ):
        raise RuntimeError("authority audit durable evidence is invalid")

    bound_subject = _bound_cohort_subject(cell, subject)
    cohort_subject_digest = sha256(bound_subject)
    observations = {
        "durable-attempt-state-classified": {
            "cell": cell["id"],
            "transaction": subject["transaction"],
            "plan": subject["plan"],
            "journal": journal["digest"],
            "authority-role": evidence["role"],
            "authority-boundary": evidence["authority-boundary"],
            "runtime-boundary": evidence["runtime-boundary"],
            "authority-rejections": journal["authority-rejections"],
            "adapter-outcomes": journal["effect-outcomes"],
        },
        "at-most-one-resource-owner": {
            "cell": cell["id"],
            "ledger": ledger["digest"],
            "acquire-calls": ledger["acquire-calls"],
            "release-calls": ledger["release-calls"],
            "max-owners": ledger["max-owners"],
            "owners": ledger["owners"],
        },
        "foreign-resources-unchanged": {
            "cell": cell["id"],
            "snapshot-before": evidence["foreign-before"],
            "snapshot-after": evidence["foreign-after"],
            "unchanged": True,
        },
        "dependent-effects-not-executed": {
            "cell": cell["id"],
            "dispatch-calls": evidence["dispatch-calls"],
            "adapter-outcomes": journal["effect-outcomes"],
            "blocked": True,
        },
    }
    if set(cell["postconditions"]) != set(observations):
        raise RuntimeError("authority cell postconditions differ from its evidence contract")

    postconditions = {}
    probes = {}
    for name in cell["postconditions"]:
        facts = observations[name]
        observation_digest = sha256(facts)
        if observation_digest in probe_digests:
            raise RuntimeError("passing matrix postconditions replay a production probe")
        probe_digests.add(observation_digest)
        postconditions[name] = {
            "passed": True,
            "detail": "The candidate runtime rejected the exact revoked role at its authority fence before adapter dispatch.",
        }
        probes[name] = {
            "schema_version": PROBE_SCHEMA,
            "kind": POSTCONDITION_KINDS[name],
            "cell_id": cell["id"],
            "cell_digest": cell_digest,
            "disposition": "rejected-before-effect",
            "subject_digest": subject_digest,
            "cohort_subject_digest": cohort_subject_digest,
            "observation_digest": observation_digest,
            "observations": facts,
        }
    return bound_subject, postconditions, probes


def _validated_failure_control_cell(
    cell: dict[str, Any],
    record: dict[str, Any],
    subject_digest: str,
    probe_digests: set[str],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Validates one runtime-owned failure control and derives its exact probes."""

    if set(record) != {"cell_digest", "subject", "plan_bundle", "evidence"}:
        raise RuntimeError("runtime control audit cell is malformed")
    cell_digest = sha256(cell)
    subject = record["subject"]
    plan_bundle = record["plan_bundle"]
    evidence = record["evidence"]
    scenario = cell["id"].rsplit("/", 1)[-1]
    if scenario not in FAILURE_CONTROL_SCENARIOS:
        raise RuntimeError("runtime control audit names an unsupported scenario")
    if (
        record.get("cell_digest") != cell_digest
        or not isinstance(subject, dict)
        or set(subject)
        != {
            "schema",
            "cell-id",
            "cell-digest",
            "interface",
            "method",
            "plan",
            "transaction",
        }
        or subject.get("schema") != RUNTIME_SUBJECT_SCHEMA
        or subject.get("cell-id") != cell["id"]
        or subject.get("cell-digest") != cell_digest
        or subject.get("interface") != cell["interface"]
        or subject.get("method") != cell["method"]
        or not _matches(DIGEST, subject.get("plan"))
        or not _matches(LOCAL_KEY, subject.get("transaction"))
        or not isinstance(plan_bundle, dict)
        or set(plan_bundle) != {"schema", "digest", "bytes-sha256"}
        or plan_bundle.get("schema") != RUNTIME_PLAN_SCHEMA
        or not _matches(DIGEST, plan_bundle.get("digest"))
        or plan_bundle.get("bytes-sha256") != plan_bundle.get("digest")
        or not isinstance(evidence, dict)
        or set(evidence)
        != {
            "scenario",
            "classification",
            "recovery-routes",
            "fixture-recovery-routes",
            "journal",
            "reservation-ledger",
            "adapter",
            "clock",
            "foreign-before",
            "foreign-after",
        }
        or evidence.get("scenario") != scenario
        or evidence.get("recovery-routes") != cell["recovery"]
        or evidence.get("fixture-recovery-routes")
        != {
            "reconcile": cell["method"]
            if cell["recovery"]["reconcile"] is not None
            else None,
            "cancel": None,
        }
        or not _matches(DIGEST, evidence.get("foreign-before"))
        or evidence.get("foreign-after") != evidence.get("foreign-before")
    ):
        raise RuntimeError("runtime control subject or retained evidence is invalid")

    journal = evidence["journal"]
    ledger = evidence["reservation-ledger"]
    adapter = evidence["adapter"]
    clock = evidence["clock"]
    if (
        not isinstance(journal, dict)
        or set(journal)
        != {
            "digest",
            "head",
            "cancellation-requested",
            "cancellation-observed",
            "cancellation-interventions",
            "deadline-aborts",
            "dependent-effect-events",
            "dependent-settlements",
        }
        or not _matches(DIGEST, journal.get("digest"))
        or not _matches(DIGEST, journal.get("head"))
        or journal.get("dependent-effect-events") != 0
        or journal.get("dependent-settlements")
        != int(scenario in {"cancel-unsettled-attempt", "fail-release"})
        or not isinstance(ledger, dict)
        or set(ledger)
        != {
            "digest",
            "acquire-calls",
            "release-calls",
            "release-failures",
            "max-owners",
            "owners-at-failure",
            "owners-final",
            "retained-resources",
            "cleanup-errors",
        }
        or not _matches(DIGEST, ledger.get("digest"))
        or ledger.get("acquire-calls") != 1
        or ledger.get("max-owners") != 1
        or ledger.get("owners-at-failure") != 1
        or ledger.get("retained-resources") != 1
        or not isinstance(adapter, dict)
        or set(adapter)
        != {
            "execute-calls",
            "reconcile-calls",
            "cancel-calls",
        }
        or adapter.get("reconcile-calls") != 0
        or not isinstance(clock, dict)
        or set(clock) != {"now-millis", "restart-stable-millis"}
        or clock.get("now-millis") != clock.get("restart-stable-millis")
        or not _is_nonnegative_int(clock.get("now-millis"))
    ):
        raise RuntimeError("runtime control durable journal or ownership evidence is invalid")

    cancel_supported = cell["recovery"]["cancel"] is not None
    if scenario == "cancel-unsettled-attempt":
        if (
            cancel_supported
            or evidence.get("classification") != "cancellation-unsupported-intervention"
            or ledger.get("release-calls") != 0
            or ledger.get("release-failures") != 0
            or ledger.get("owners-final") != 1
            or ledger.get("cleanup-errors") != 0
            or adapter.get("execute-calls") != 0
            or adapter.get("cancel-calls") != 0
            or journal.get("cancellation-requested") != 0
            or journal.get("cancellation-observed") != 0
            or journal.get("cancellation-interventions") != 1
            or journal.get("deadline-aborts") != 0
        ):
            raise RuntimeError("cancellation acknowledgement evidence is invalid")
    elif scenario == "expire-attempt-deadline":
        if (
            evidence.get("classification") != "trusted-clock-deadline-expired"
            or clock.get("now-millis", 0) <= 1
            or ledger.get("release-calls") != 0
            or ledger.get("release-failures") != 0
            or ledger.get("owners-final") != 1
            or ledger.get("cleanup-errors") != 0
            or adapter.get("execute-calls") != 0
            or adapter.get("cancel-calls") != 0
            or any(journal.get(name) != 0 for name in [
                "cancellation-requested",
                "cancellation-observed",
                "cancellation-interventions",
            ])
            or journal.get("deadline-aborts") != 1
        ):
            raise RuntimeError("trusted-clock deadline evidence is invalid")
    elif scenario == "fail-cleanup":
        if (
            evidence.get("classification") != "cleanup-failure-retained-then-released"
            or ledger.get("release-calls") != 2
            or ledger.get("release-failures") != 1
            or ledger.get("owners-final") != 0
            or ledger.get("cleanup-errors") != 1
            or adapter.get("execute-calls") != 0
            or adapter.get("cancel-calls") != 0
            or journal.get("deadline-aborts") != 0
        ):
            raise RuntimeError("cleanup failure evidence is invalid")
    elif (
        evidence.get("classification") != "release-failure-retained-then-released"
        or ledger.get("release-calls") != 2
        or ledger.get("release-failures") != 1
        or ledger.get("owners-final") != 0
        or ledger.get("cleanup-errors") != 0
        or adapter.get("execute-calls") != 1
        or adapter.get("cancel-calls") != 0
        or journal.get("deadline-aborts") != 0
    ):
        raise RuntimeError("release failure evidence is invalid")

    bound_subject = _bound_cohort_subject(cell, subject)
    cohort_subject_digest = sha256(bound_subject)
    observations = {
        "durable-attempt-state-classified": {
            "cell": cell["id"],
            "transaction": subject["transaction"],
            "plan": subject["plan"],
            "journal": journal["digest"],
            "journal-head": journal["head"],
            "scenario": scenario,
            "classification": evidence["classification"],
            "recovery-routes": evidence["recovery-routes"],
            "fixture-recovery-routes": evidence["fixture-recovery-routes"],
        },
        "at-most-one-resource-owner": {
            "cell": cell["id"],
            "ledger": ledger["digest"],
            "max-owners": ledger["max-owners"],
            "owners-at-failure": ledger["owners-at-failure"],
            "owners-final": ledger["owners-final"],
            "retained-resources": ledger["retained-resources"],
            "release-failures": ledger["release-failures"],
        },
        "foreign-resources-unchanged": {
            "cell": cell["id"],
            "snapshot-before": evidence["foreign-before"],
            "snapshot-after": evidence["foreign-after"],
            "unchanged": True,
        },
        "dependent-effects-not-executed": {
            "cell": cell["id"],
            "dependent-effect-events": journal["dependent-effect-events"],
            "dependent-settlements": journal["dependent-settlements"],
            "blocked": True,
        },
    }
    if set(cell["postconditions"]) != set(observations):
        raise RuntimeError("failure-control postconditions differ from its evidence contract")

    postconditions = {}
    probes = {}
    disposition = _expected_disposition(cell)
    for name in cell["postconditions"]:
        facts = observations[name]
        observation_digest = sha256(facts)
        if observation_digest in probe_digests:
            raise RuntimeError("passing matrix postconditions replay a production probe")
        probe_digests.add(observation_digest)
        postconditions[name] = {
            "passed": True,
            "detail": "The candidate runtime retained exact ownership and durably classified the injected failure control.",
        }
        probes[name] = {
            "schema_version": PROBE_SCHEMA,
            "kind": POSTCONDITION_KINDS[name],
            "cell_id": cell["id"],
            "cell_digest": cell_digest,
            "disposition": disposition,
            "subject_digest": subject_digest,
            "cohort_subject_digest": cohort_subject_digest,
            "observation_digest": observation_digest,
            "observations": facts,
        }
    return bound_subject, postconditions, probes


def _validated_probes(
    cell: dict[str, Any],
    submitted: dict[str, Any],
    cohort_subject: dict[str, Any],
    bound_subject: dict[str, Any],
    subject_digest: str,
    cohort_probe_digests: set[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    postcondition_names = cell["postconditions"]
    if set(submitted) != set(postcondition_names):
        raise RuntimeError("qualified cell lacks an exact postcondition probe set")
    if bound_subject != _bound_cohort_subject(cell, cohort_subject):
        raise RuntimeError("cohort subject is bound to another matrix cell")

    cell_digest = sha256(cell)
    cohort_subject_digest = sha256(bound_subject)
    expected_disposition = _expected_disposition(cell)
    postconditions = {}
    probes = {}
    for name in postcondition_names:
        record = submitted[name]
        if set(record) != {"kind", "detail", "disposition", "observations"}:
            raise RuntimeError("postcondition probe has unknown or missing fields")
        expected_kind = POSTCONDITION_KINDS.get(name)
        observations = record["observations"]
        if (
            record["kind"] != expected_kind
            or not isinstance(record["detail"], str)
            or not record["detail"].strip()
            or record["disposition"] != expected_disposition
            or not isinstance(observations, dict)
            or not 1 <= len(observations) <= MAX_PROBE_FACTS
            or any(
                not isinstance(key, str) or TOKEN(key) is None or value is None
                for key, value in observations.items()
            )
            or len(canonical(observations)) > MAX_PROBE_BYTES
        ):
            raise RuntimeError("postcondition probe is malformed")
        _validate_probe_facts(name, observations, cohort_subject, cell)
        observation_digest = sha256(observations)
        if observation_digest in cohort_probe_digests:
            raise RuntimeError("passing matrix postconditions replay a production probe")
        cohort_probe_digests.add(observation_digest)

        postconditions[name] = {"passed": True, "detail": record["detail"]}
        probes[name] = {
            "schema_version": PROBE_SCHEMA,
            "kind": record["kind"],
            "cell_id": cell["id"],
            "cell_digest": cell_digest,
            "disposition": record["disposition"],
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
    cell: dict[str, Any],
) -> None:
    """Checks semantic facts for one exact matrix postcondition."""

    if cohort_subject.get("schema") == CANCELLATION_COHORT_SUBJECT_SCHEMA:
        _validate_cancellation_probe_facts(
            postcondition, observations, cohort_subject, cell
        )
        return
    if cohort_subject.get("schema") == POSTGRESQL_COHORT_SUBJECT_SCHEMA:
        _validate_postgresql_probe_facts(
            postcondition, observations, cohort_subject, cell
        )
        return
    if cohort_subject.get("schema") == EFFECT_BOUNDARY_COHORT_SUBJECT_SCHEMA:
        _validate_effect_boundary_probe_facts(
            postcondition, observations, cohort_subject, cell
        )
        return

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
            return

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
            return

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
            return

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
            return

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
            != subject["authorization-policy-revision"]
            or observations.get("current-planning") != subject["current-planning"]
            or observations.get("desired-planning") != subject["desired-planning"]
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


def _cell_scenario(cell: dict[str, Any]) -> str:
    """Returns the scenario suffix carried by an exact matrix cell."""

    return cell["id"].rsplit("/", 1)[-1]


def _interruption_position(
    scenario: str, boundary_timeline: list[dict[str, Any]]
) -> Any:
    """Selects the exact transcript position where the process was killed."""

    indexes = {
        "interrupt-after-durable-intent": 0,
        "lose-external-result": 1,
        "interrupt-after-durable-outcome": 2,
    }
    try:
        return boundary_timeline[indexes[scenario]]["transcript-position"]
    except (IndexError, KeyError, TypeError) as error:
        raise RuntimeError("matrix crash scenario has no interruption boundary") from error


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


def _expected_disposition(cell: dict[str, Any]) -> str:
    scenario = cell["id"].rsplit("/", 1)[-1]
    if scenario == "cancel-unsettled-attempt":
        if cell.get("recovery", {}).get("cancel") is None:
            return "unsupported-cancellation-retains-ownership"
        return "cancelled-after-reconciliation"
    try:
        return SCENARIO_DISPOSITIONS[scenario]
    except KeyError as error:
        raise RuntimeError("matrix cell has no expected disposition") from error


def _cohort_operation(cohort_subject: dict[str, Any]) -> Any:
    return cohort_subject.get("operation", cohort_subject.get("publish-operation"))


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


def _validate_cohort_subject(
    cell: dict[str, Any],
    subject: Any,
    evidence_bytes: Any,
    matrix_spec: dict[str, Any] | None = None,
) -> None:
    if isinstance(subject, dict) and subject.get("schema") == CANCELLATION_COHORT_SUBJECT_SCHEMA:
        _validate_cancellation_subject(cell, subject, evidence_bytes, matrix_spec)
        return

    if cell.get("adapter") == "postgresql":
        _validate_postgresql_cohort_subject(cell, subject, evidence_bytes)
        return

    if isinstance(subject, dict) and subject.get("schema") == EFFECT_BOUNDARY_COHORT_SUBJECT_SCHEMA:
        _validate_effect_boundary_subject(cell, subject, evidence_bytes)
        return

    _validate_managed_configuration_subject(cell, subject, evidence_bytes)


def _validate_cancellation_subject(
    cell: dict[str, Any],
    subject: Any,
    evidence_bytes: Any,
    matrix_spec: dict[str, Any] | None,
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
            "handler-entry-point",
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
        handler, entry_point = CANCELLATION_HANDLER_ENTRY_POINTS[
            cell["interface"]["name"]
        ]
    except RuntimeError:
        raise
    except (AttributeError, KeyError, TypeError) as error:
        raise RuntimeError("cancellation plan evidence is malformed") from error

    cell_digest = sha256(cell)
    matrix_digest = subject["matrix-spec-digest"]
    if matrix_spec is not None and matrix_digest != sha256(matrix_spec):
        raise RuntimeError("cancellation subject names another matrix specification")
    if (
        _cell_scenario(cell) != "cancel-unsettled-attempt"
        or cell.get("recovery", {}).get("cancel") is None
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
        or operation_document.get("recovery", {}).get("cancel")
        != {"interface": cell["interface"], "method": cell["recovery"]["cancel"]}
        or subject["cancel-route"] != operation_document["recovery"]["cancel"]
        or subject["provider-implementation"] != implementation
        or implementation.get("handler") != handler
        or subject["handler-entry-point"] != entry_point
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
        or policy.get("schema") != "aos.ability.authenticated-policy-set/v3"
        or pin.get("document_sha256")
        != "sha256:" + hashlib.sha256(policy_bytes).hexdigest()
        or pin.get("document_size") != len(policy_bytes)
        or policy.get("native_resource_map", {}).get("schema")
        != "aos.ability.native-resource-map/v3"
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
            scenario, cell["effect_class"]
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
                cell["effect_class"] == "mutation"
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


def _cancellation_oracle_snapshot(adapter: str, value: Any) -> bool:
    """Checks that a live snapshot names the adapter's independent oracle kind."""

    expected = CANCELLATION_ORACLE_KINDS.get(adapter)
    return isinstance(value, dict) and value.get("kind") == expected


def _cancellation_foreign_snapshot(value: Any) -> bool:
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
        and _cancellation_oracle_snapshot(adapter, value.get("observation"))
    )


def _validate_cancellation_probe_facts(
    postcondition: str,
    observations: dict[str, Any],
    subject: dict[str, Any],
    cell: dict[str, Any],
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
                _cancellation_oracle_snapshot(cell["adapter"], observations.get(field))
                for field in ("live-before", "live-unsettled", "live-after")
            )
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
            or not _cancellation_foreign_snapshot(before)
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


def _validate_managed_configuration_subject(
    cell: dict[str, Any], subject: Any, plan_bundle_bytes: Any
) -> None:
    scenario = cell["id"].rsplit("/", 1)[-1]
    expected_interface = (
        SYSTEMD_SERVICE_INTERFACE
        if scenario == "block-dependent-effect"
        else MANAGED_CONFIGURATION_INTERFACE
    )
    expected_method = "reload" if scenario == "block-dependent-effect" else "publish"
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
        or cell.get("interface") != expected_interface
        or cell.get("method") != expected_method
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


def _validate_postgresql_cohort_subject(
    cell: dict[str, Any], subject: Any, evidence_bytes: Any
) -> None:
    if (
        cell.get("interface", {}).get("name") != "aos.postgresql-effects"
        or cell.get("interface", {}).get("abi") != 1
        or cell.get("interface", {}).get("descriptor")
        != "sha256:6a1e7d5fb03d9b91127144a64fb96e4c98f4995e7f4f0de258f79fb61fbb9fd6"
        or cell.get("method") not in {"materialize", "restart"}
    ):
        raise RuntimeError("PostgreSQL cohort is bound to another adapter method")

    scenario = cell["id"].rsplit("/", 1)[-1]
    if scenario == "reject-unsupported-transfer":
        expected = _postgresql_rejection_subject(evidence_bytes)
    else:
        expected = _postgresql_plan_subject(evidence_bytes, cell["method"])
    if subject != expected or subject.get("schema") != POSTGRESQL_COHORT_SUBJECT_SCHEMA:
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


def _postgresql_rejection_subject(evidence_bytes: Any) -> dict[str, Any]:
    evidence = _canonical_evidence(evidence_bytes, "PostgreSQL rejection")
    try:
        if (
            evidence.get("schema") != POSTGRESQL_REJECTION_EVIDENCE_SCHEMA
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
        "schema": POSTGRESQL_COHORT_SUBJECT_SCHEMA,
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
