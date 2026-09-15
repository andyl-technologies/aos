"""Validates generic runtime interruption, authority, and failure evidence."""

from __future__ import annotations

from typing import Any

import native_adapter_evidence as provider_evidence

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


RUNTIME_AUDIT_SCHEMA = "aos.qualification.native-adapter-runtime-audit/v1"

RUNTIME_SUBJECT_SCHEMA = "aos.qualification.native-adapter-runtime-subject/v1"

REPLACEMENT_SUBJECT_SCHEMA = (
    "aos.qualification.native-adapter-incarnation-replacement-subject/v1"
)

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

REPLACEMENT_SCENARIOS = {
    "replace-executor-incarnation",
    "replace-provider-incarnation",
}

PROVIDER_NEGATIVE_AUDIT_SCHEMA = (
    "aos.qualification.native-adapter-provider-negative-audit/v1"
)

PROVIDER_NEGATIVE_SUBJECT_SCHEMA = (
    "aos.qualification.native-adapter-provider-negative-subject/v1"
)

PROVIDER_NEGATIVE_PLAN_SCHEMA = (
    "aos.qualification.native-adapter-provider-negative-plan/v1"
)

PROVIDER_NEGATIVE_SCENARIOS = {
    "block-dependent-effect",
    "reject-foreign-resource-mutation",
}


def _runtime_audit_cell(cell: dict[str, Any]) -> bool:
    """Returns whether the shared runtime can qualify this exact matrix cell."""

    scenario = cell["id"].rsplit("/", 1)[-1]
    return scenario in (
        ROLE_SCENARIOS
        | REPLACEMENT_SCENARIOS
        | (FAILURE_CONTROL_SCENARIOS - {"cancel-unsettled-attempt"})
    )

def validate_interruption_audit(
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

def validate_interruption_cell(
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
            "operation-recovery",
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
        or not isinstance(evidence.get("operation-recovery"), dict)
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
            "detail": (
                "The candidate runtime halted before acquisition and reopened "
                "the unchanged pending journal with dependents still blocked."
            ),
        }
        probes[name] = {
            "schema_version": PROBE_SCHEMA,
            "kind": _postcondition_kind(cell, name),
            "cell_id": cell["id"],
            "cell_digest": cell_digest,
            "disposition": "rejected-before-acquisition",
            "subject_digest": subject_digest,
            "cohort_subject_digest": cohort_subject_digest,
            "observation_digest": observation_digest,
            "observations": facts,
        }

    return bound_subject, postconditions, probes

def validate_runtime_audit(
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

def _provider_negative_cell_ids(
    specification_cells: dict[str, dict[str, Any]],
    directly_observed_cells: set[str],
) -> set[str]:
    """Returns the closed dependency/foreign scope owned by the shared audit."""

    return {
        cell_id
        for cell_id, cell in specification_cells.items()
        if cell_id.rsplit("/", 1)[-1] in PROVIDER_NEGATIVE_SCENARIOS
        and cell_id not in directly_observed_cells
    }

def validate_provider_negative_audit(
    audit: dict[str, Any],
    spec: dict[str, Any],
    specification_cells: dict[str, dict[str, Any]],
    directly_observed_cells: set[str],
) -> None:
    """Checks the provider-flight envelope against the realized matrix scope."""

    expected = _provider_negative_cell_ids(
        specification_cells, directly_observed_cells
    )
    if (
        set(audit) != {"schema", "matrix_spec_digest", "cells"}
        or audit.get("schema") != PROVIDER_NEGATIVE_AUDIT_SCHEMA
        or audit.get("matrix_spec_digest") != sha256(spec)
        or set(audit.get("cells", {})) != expected
        or not expected
    ):
        raise RuntimeError("provider-negative audit differs from its closed matrix cohort")

def validate_provider_negative_cell(
    cell: dict[str, Any],
    record: dict[str, Any],
    subject_digest: str,
    probe_digests: set[str],
    spec: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Validates one provider flight and derives its five exact probes."""

    provider_result = provider_evidence.validate_special_provider_negative_cell(
        cell,
        record,
        subject_digest,
        probe_digests,
        spec,
        {
            "cell-subject-schema": CELL_SUBJECT_SCHEMA,
            "subject-schema": PROVIDER_NEGATIVE_SUBJECT_SCHEMA,
            "plan-schema": PROVIDER_NEGATIVE_PLAN_SCHEMA,
            "probe-schema": PROBE_SCHEMA,
            "postcondition-kinds": cell["postcondition_kinds"],
            "disposition": SCENARIO_DISPOSITIONS[_cell_scenario(cell)],
        },
    )
    if provider_result is not None:
        return provider_result
    if set(record) != {"cell_digest", "subject", "plan_bundle", "evidence"}:
        raise RuntimeError("provider-negative audit cell is malformed")
    cell_digest = sha256(cell)
    if record.get("cell_digest") != cell_digest:
        raise RuntimeError("provider-negative audit cell digest differs")

    subject = record.get("subject")
    plan_bundle = record.get("plan_bundle")
    evidence = record.get("evidence")
    if not all(isinstance(value, dict) for value in [subject, plan_bundle, evidence]):
        raise RuntimeError("provider-negative audit record has malformed documents")

    scenario = _cell_scenario(cell)
    adapter = cell["adapter"]
    adapter_claim = _adapter_claim(spec, adapter)
    expected_oracle = _observer_result_value(adapter_claim, "kind")
    expected_subject = {
        "schema": PROVIDER_NEGATIVE_SUBJECT_SCHEMA,
        "cell-id": cell["id"],
        "cell-digest": cell_digest,
        "adapter": adapter,
        "interface": cell["interface"],
        "method": cell["method"],
        "scenario": scenario,
        "plan": subject.get("plan"),
        "transaction": subject.get("transaction"),
        "flight": subject.get("flight"),
    }
    if (
        subject != expected_subject
        or scenario not in PROVIDER_NEGATIVE_SCENARIOS
        or not _matches(LOCAL_KEY, expected_oracle)
        or not _matches(DIGEST, subject.get("plan"))
        or not _matches(LOCAL_KEY, subject.get("transaction"))
        or not _matches(LOCAL_KEY, subject.get("flight"))
    ):
        raise RuntimeError("provider-negative audit subject differs from its matrix cell")

    required_edge = plan_bundle.get("required-success")
    if (
        set(plan_bundle)
        != {
            "schema",
            "digest",
            "plan",
            "foreign-operation",
            "dependent-operation",
            "required-success",
            "behavioral-witness",
        }
        or plan_bundle.get("schema") != PROVIDER_NEGATIVE_PLAN_SCHEMA
        or not _matches(DIGEST, plan_bundle.get("digest"))
        or plan_bundle.get("plan") != subject["plan"]
        or not isinstance(plan_bundle.get("foreign-operation"), dict)
        or not isinstance(plan_bundle.get("dependent-operation"), dict)
        or required_edge
        != {
            "from": plan_bundle.get("foreign-operation"),
            "to": plan_bundle.get("dependent-operation"),
            "kind": "required-success",
        }
    ):
        raise RuntimeError(
            "provider-negative plan does not retain one exact required-success edge"
        )

    foreign_operation = plan_bundle["foreign-operation"]
    dependent_operation = plan_bundle["dependent-operation"]
    behavioral_witness = plan_bundle["behavioral-witness"]
    if not all(
        _provider_negative_operation(operation)
        for operation in [foreign_operation, dependent_operation]
    ):
        raise RuntimeError("provider-negative plan operations are malformed")
    expected_cell_operation = foreign_operation
    if (
        expected_cell_operation.get("interface") != cell["interface"]
        or expected_cell_operation.get("method") != cell["method"]
    ):
        raise RuntimeError("provider-negative selected operation differs from the exact cell")
    if cell["effect_class"] == "observation":
        if (
            not isinstance(behavioral_witness, dict)
            or behavioral_witness.get("resource") is None
        ):
            raise RuntimeError("observation cell lacks its distinct mutation witness")
    elif behavioral_witness is not None:
        raise RuntimeError("mutation cell unexpectedly carries a behavioral witness")

    if set(evidence) != {
        "provider-route",
        "boundary",
        "journal",
        "ownership",
        "foreign-resource",
        "blocked-successor",
        "blocked-witness",
        "provider-sentinel",
    }:
        raise RuntimeError("provider-negative evidence has unexpected fields")
    provider_route = evidence.get("provider-route")
    journal = evidence.get("journal")
    ownership = evidence.get("ownership")
    foreign = evidence.get("foreign-resource")
    successor = evidence.get("blocked-successor")
    blocked_witness = evidence.get("blocked-witness")
    provider_sentinel = evidence.get("provider-sentinel")
    expected_foreign_timeline = [
        "operation-admitted",
        "effect-started",
        "rejected-before-effect",
    ]
    if not all(
        isinstance(value, dict)
        for value in [provider_route, journal, ownership, foreign, successor]
    ):
        raise RuntimeError("provider-negative evidence has malformed facts")
    if (
        set(provider_route)
        != {
            "adapter",
            "interface",
            "method",
            "candidate-linked",
            "artifact",
            "implementation",
            "handler",
            "entry-point",
        }
        or provider_route.get("adapter") != adapter
        or provider_route.get("interface") != cell["interface"]
        or provider_route.get("method") != cell["method"]
        or provider_route.get("candidate-linked") is not True
        or not _matches(DIGEST, provider_route.get("artifact"))
        or not _matches(LOCAL_KEY, provider_route.get("handler"))
        or not isinstance(provider_route.get("entry-point"), str)
        or not provider_route["entry-point"]
        or provider_route["entry-point"].startswith("/")
        or evidence.get("boundary")
        != "after-durable-intent-before-external-effect"
    ):
        raise RuntimeError("provider-negative evidence does not bind the candidate route")
    if (
        set(journal)
        != {
            "digest",
            "failure-record",
            "foreign-operation",
            "foreign-timeline",
            "dependent-operation",
            "dependent-timeline",
            "behavioral-witness",
            "witness-timeline",
            "classified",
        }
        or not _matches(DIGEST, journal.get("digest"))
        or not _matches(DIGEST, journal.get("failure-record"))
        or journal.get("foreign-operation") != foreign_operation
        or journal.get("dependent-operation") != dependent_operation
        or [event.get("kind") for event in journal.get("foreign-timeline", [])]
        != expected_foreign_timeline
        or any(
            set(event) != {"sequence", "kind", "node-ordinal"}
            for event in journal.get("foreign-timeline", [])
        )
        or journal.get("dependent-timeline") != []
        or journal.get("behavioral-witness") != behavioral_witness
        or journal.get("witness-timeline") != []
        or journal.get("classified") != "foreign-authority-rejected"
    ):
        raise RuntimeError("provider-negative journal does not prove exact blocking")
    if ownership != {
        "foreign-owner-count-before": 1,
        "foreign-owner-count-after": 1,
        "candidate-owner-count": 0,
        "maximum-owner-count": 1,
    }:
        raise RuntimeError("provider-negative ownership is not exclusive")
    successor_claim = _adapter_claim_by_interface(
        spec, dependent_operation.get("interface", {}).get("name")
    )
    for label, oracle, operation, oracle_kind, must_be_live in [
        ("foreign", foreign, foreign_operation, expected_oracle, True),
        (
            "successor",
            successor,
            dependent_operation,
            _observer_result_value(successor_claim, "kind"),
            False,
        ),
    ]:
        if (
            set(oracle)
            != {"kind", "resource", "before", "after", "unchanged", "live"}
            or oracle.get("kind") != oracle_kind
            or oracle.get("resource") != operation.get("resource")
            or not _matches(DIGEST, oracle.get("before"))
            or oracle.get("after") != oracle.get("before")
            or oracle.get("unchanged") is not True
            or not isinstance(oracle.get("live"), bool)
            or (must_be_live and oracle.get("live") is not True)
        ):
            raise RuntimeError(
                f"provider-negative {label} oracle is not exact and live"
            )
    if behavioral_witness is None:
        if blocked_witness is not None:
            raise RuntimeError("mutation cell unexpectedly reports a blocked witness")
    elif (
        not isinstance(blocked_witness, dict)
        or set(blocked_witness)
        != {"kind", "resource", "before", "after", "unchanged", "live"}
        or blocked_witness.get("kind")
        != _observer_result_value(
            _adapter_claim_by_interface(
                spec, behavioral_witness.get("interface", {}).get("name")
            ),
            "kind",
        )
        or blocked_witness.get("resource") != behavioral_witness.get("resource")
        or not _matches(DIGEST, blocked_witness.get("before"))
        or blocked_witness.get("before") != blocked_witness.get("after")
        or blocked_witness.get("unchanged") is not True
        or not isinstance(blocked_witness.get("live"), bool)
    ):
        raise RuntimeError("observation cell does not prove mutation-witness nonexecution")

    if provider_sentinel is not None:
        if (
            not isinstance(provider_sentinel, dict)
            or set(provider_sentinel)
            != {"kind", "resource", "before", "after", "unchanged", "live"}
            or provider_sentinel.get("kind") != expected_oracle
            or not _matches(DIGEST, provider_sentinel.get("before"))
            or provider_sentinel.get("after") != provider_sentinel.get("before")
            or provider_sentinel.get("unchanged") is not True
            or provider_sentinel.get("live") is not True
            or provider_sentinel.get("resource") == foreign_operation.get("resource")
        ):
            raise RuntimeError("provider sentinel is not independent and live")

    bound_subject = {
        "schema": CELL_SUBJECT_SCHEMA,
        "cell": {
            "id": cell["id"],
            "digest": cell_digest,
            "boundary": cell["boundary"],
            "failure": cell["failure"],
            "candidate": cell["candidate"],
            "predecessor": cell["predecessor"],
        },
        "subject": subject,
    }
    cohort_subject_digest = sha256(bound_subject)
    scenario_probe = (
        "prerequisite-failure-recorded"
        if scenario == "block-dependent-effect"
        else "foreign-attempt-rejected-before-mutation"
    )
    foreign_resources = (
        foreign
        if provider_sentinel is None
        else {
            "foreign-target": foreign,
            "provider-sentinel": provider_sentinel,
        }
    )
    observations = {
        "durable-attempt-state-classified": journal,
        "at-most-one-resource-owner": ownership,
        "foreign-resources-unchanged": foreign_resources,
        "dependent-effects-not-executed": successor,
        scenario_probe: {
            "boundary": evidence["boundary"],
            "failure-record": journal["failure-record"],
            "provider-route": provider_route,
            "foreign-operation": foreign_operation,
            "dependent-operation": dependent_operation,
            "dependent-timeline": journal["dependent-timeline"],
            "behavioral-witness": behavioral_witness,
            "witness-timeline": journal["witness-timeline"],
            "blocked-witness": blocked_witness,
        },
    }
    if set(observations) != set(cell["postconditions"]):
        raise RuntimeError("provider-negative evidence differs from cell postconditions")

    postconditions = {}
    probes = {}
    for name in cell["postconditions"]:
        observation = observations[name]
        observation_digest = sha256(
            {
                "schema": PROBE_SCHEMA,
                "cell": cell_digest,
                "postcondition": name,
                "subject": cohort_subject_digest,
                "candidate-subject": subject_digest,
                "observations": observation,
            }
        )
        if observation_digest in probe_digests:
            raise RuntimeError("passing matrix postconditions replay a provider probe")
        probe_digests.add(observation_digest)
        postconditions[name] = {
            "passed": True,
            "detail": "candidate-linked provider flight satisfied exact postcondition",
        }
        probes[name] = {
            "schema": PROBE_SCHEMA,
            "kind": _postcondition_kind(cell, name),
            "disposition": SCENARIO_DISPOSITIONS[scenario],
            "observation_digest": observation_digest,
            "cohort_subject_digest": cohort_subject_digest,
        }

    return bound_subject, postconditions, probes

def _provider_negative_operation(value: Any) -> bool:
    """Checks the exact operation identity retained by provider flights."""

    return (
        isinstance(value, dict)
        and set(value) == {"key", "ordinal", "interface", "method", "resource"}
        and _operation_key(value)
        and _is_nonnegative_int(value.get("ordinal"))
        and isinstance(value.get("interface"), dict)
        and isinstance(value.get("method"), str)
        and isinstance(value.get("resource"), dict)
    )

def validate_authority_cell(
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
            "detail": (
                "The candidate runtime rejected the exact revoked role at its "
                "authority fence before adapter dispatch."
            ),
        }
        probes[name] = {
            "schema_version": PROBE_SCHEMA,
            "kind": _postcondition_kind(cell, name),
            "cell_id": cell["id"],
            "cell_digest": cell_digest,
            "disposition": "rejected-before-effect",
            "subject_digest": subject_digest,
            "cohort_subject_digest": cohort_subject_digest,
            "observation_digest": observation_digest,
            "observations": facts,
        }
    return bound_subject, postconditions, probes

def validate_replacement_cell(
    cell: dict[str, Any],
    record: dict[str, Any],
    subject_digest: str,
    probe_digests: set[str],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Validates an executor or provider incarnation fence and derives its probes."""

    if set(record) != {"cell_digest", "subject", "plan_bundle", "evidence"}:
        raise RuntimeError("incarnation replacement audit cell is malformed")
    cell_digest = sha256(cell)
    subject = record["subject"]
    plan_bundle = record["plan_bundle"]
    evidence = record["evidence"]
    scenario = cell["id"].rsplit("/", 1)[-1]
    if scenario == "replace-executor-incarnation":
        expected_runtime_boundary = "ExecutorSessionReplacement"
        expected_releases = 0
        expected_owners = 1
        expected_rejection_kind = "stale-executor-admission"
        detail = (
            "The candidate runtime rejected an admitted token from the predecessor "
            "executor session before adapter dispatch."
        )
    elif scenario == "replace-provider-incarnation":
        expected_runtime_boundary = "ProviderCatalogReplacement"
        expected_releases = 1
        expected_owners = 0
        expected_rejection_kind = "resource-provider-incarnation-precondition"
        detail = (
            "The candidate runtime rejected the catalog's independently observed "
            "replacement provider incarnation before adapter dispatch."
        )
    else:
        raise RuntimeError("incarnation replacement audit names an unsupported scenario")

    primary = subject.get("primary-operation") if isinstance(subject, dict) else None
    dependent = subject.get("dependent-operation") if isinstance(subject, dict) else None
    edge = subject.get("dependency-edge") if isinstance(subject, dict) else None
    primary_key = primary.get("key") if isinstance(primary, dict) else None
    dependent_key = dependent.get("key") if isinstance(dependent, dict) else None
    expected_edge = {
        "from": {"kind": "operation", "key": primary_key},
        "to": {"kind": "operation", "key": dependent_key},
        "kind": "required-success",
    }
    operations_match = False
    if isinstance(primary, dict) and isinstance(dependent, dict):
        dependent_as_primary = dict(dependent)
        dependent_as_primary["key"] = primary_key
        preconditions = primary.get("preconditions")
        operations_match = (
            primary == dependent_as_primary
            and primary.get("interface") == cell["interface"]
            and primary.get("method") == cell["method"]
            and primary_key != dependent_key
            and isinstance(preconditions, list)
            and len(preconditions) == 1
            and _matches(LOCAL_KEY, preconditions[0].get("expected_incarnation"))
            and edge == expected_edge
        )

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
            "primary-operation",
            "dependent-operation",
            "dependency-edge",
        }
        or subject.get("schema") != REPLACEMENT_SUBJECT_SCHEMA
        or subject.get("cell-id") != cell["id"]
        or subject.get("cell-digest") != cell_digest
        or subject.get("interface") != cell["interface"]
        or subject.get("method") != cell["method"]
        or not operations_match
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
            "rejection",
            "journal",
            "reservation-ledger",
            "dispatch-calls",
            "initial-ready",
            "blocked-dependent",
            "foreign-before",
            "foreign-after",
        }
        or evidence.get("role") is not None
        or evidence.get("authority-boundary") is not None
        or evidence.get("runtime-boundary") != expected_runtime_boundary
        or evidence.get("dispatch-calls") != 0
        or evidence.get("initial-ready") != [primary_key]
        or evidence.get("blocked-dependent") != dependent_key
        or not _matches(DIGEST, evidence.get("foreign-before"))
        or evidence.get("foreign-after") != evidence.get("foreign-before")
    ):
        raise RuntimeError("incarnation replacement subject or fence evidence is invalid")

    journal = evidence["journal"]
    ledger = evidence["reservation-ledger"]
    rejection = evidence["rejection"]
    if (
        not isinstance(journal, dict)
        or set(journal) != {"digest", "head", "authority-rejections", "effect-outcomes"}
        or not _matches(DIGEST, journal.get("digest"))
        or not _matches(DIGEST, journal.get("head"))
        or journal.get("authority-rejections") != 0
        or journal.get("effect-outcomes") != 0
        or not isinstance(ledger, dict)
        or set(ledger) != {"digest", "acquire-calls", "release-calls", "max-owners", "owners"}
        or not _matches(DIGEST, ledger.get("digest"))
        or ledger.get("acquire-calls") != 1
        or ledger.get("release-calls") != expected_releases
        or ledger.get("max-owners") != 1
        or ledger.get("owners") != expected_owners
        or not isinstance(rejection, dict)
        or set(rejection) != {"kind", "digest"}
        or rejection.get("kind") != expected_rejection_kind
        or not _matches(DIGEST, rejection.get("digest"))
    ):
        raise RuntimeError("incarnation replacement durable evidence is invalid")

    bound_subject = _bound_cohort_subject(cell, subject)
    cohort_subject_digest = sha256(bound_subject)
    observations = {
        "durable-attempt-state-classified": {
            "cell": cell["id"],
            "transaction": subject["transaction"],
            "plan": subject["plan"],
            "journal": journal["digest"],
            "runtime-boundary": evidence["runtime-boundary"],
            "rejection-kind": rejection["kind"],
            "rejection-record": rejection["digest"],
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
            "primary-operation": primary,
            "dependent-operation": dependent,
            "dependency-edge": edge,
            "initial-ready": evidence["initial-ready"],
            "blocked-dependent": evidence["blocked-dependent"],
            "dispatch-calls": evidence["dispatch-calls"],
            "adapter-outcomes": journal["effect-outcomes"],
            "blocked": True,
        },
    }
    if set(cell["postconditions"]) != set(observations):
        raise RuntimeError("replacement postconditions differ from its evidence contract")

    postconditions = {}
    probes = {}
    for name in cell["postconditions"]:
        facts = observations[name]
        observation_digest = sha256(facts)
        if observation_digest in probe_digests:
            raise RuntimeError("passing matrix postconditions replay a production probe")
        probe_digests.add(observation_digest)
        postconditions[name] = {"passed": True, "detail": detail}
        probes[name] = {
            "schema_version": PROBE_SCHEMA,
            "kind": _postcondition_kind(cell, name),
            "cell_id": cell["id"],
            "cell_digest": cell_digest,
            "disposition": "rejected-before-effect",
            "subject_digest": subject_digest,
            "cohort_subject_digest": cohort_subject_digest,
            "observation_digest": observation_digest,
            "observations": facts,
        }

    return bound_subject, postconditions, probes

def validate_failure_control_cell(
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
            "operation-recovery",
            "journal",
            "reservation-ledger",
            "adapter",
            "clock",
            "foreign-before",
            "foreign-after",
        }
        or evidence.get("scenario") != scenario
        or not isinstance(evidence.get("operation-recovery"), dict)
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

    cancel_supported = evidence["operation-recovery"].get("cancel") is not None
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
            "operation-recovery": evidence["operation-recovery"],
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
    disposition_subject = (
        {"cancel-route": evidence["operation-recovery"].get("cancel")}
        if scenario == "cancel-unsettled-attempt"
        else None
    )
    disposition = _expected_disposition(cell, disposition_subject)
    for name in cell["postconditions"]:
        facts = observations[name]
        observation_digest = sha256(facts)
        if observation_digest in probe_digests:
            raise RuntimeError("passing matrix postconditions replay a production probe")
        probe_digests.add(observation_digest)
        postconditions[name] = {
            "passed": True,
            "detail": (
                "The candidate runtime retained exact ownership and durably "
                "classified the injected failure control."
            ),
        }
        probes[name] = {
            "schema_version": PROBE_SCHEMA,
            "kind": _postcondition_kind(cell, name),
            "cell_id": cell["id"],
            "cell_digest": cell_digest,
            "disposition": disposition,
            "subject_digest": subject_digest,
            "cohort_subject_digest": cohort_subject_digest,
            "observation_digest": observation_digest,
            "observations": facts,
        }
    return bound_subject, postconditions, probes
