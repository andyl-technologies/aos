"""Binds checked native flights to an exact operation matrix partition.

Only independently validated flights produce passing postconditions. This
aggregator retains immutable cell, subject, environment, and observation
bindings and rejects replay or unsupported evidence kinds.
"""

from __future__ import annotations

from typing import Any

import native_adapter_runtime_evidence as runtime_evidence
from native_adapter_evidence_common import (
    DIGEST, PROBE_SCHEMA, _bound_cohort_subject, _expected_disposition,
    _matches, _postcondition_kind, canonical, sha256, required_operations, selected_terminal_effects,
)

QUALIFICATION_SUBJECT_SCHEMA = "aos.qualification.native-operation-package-subject"
MATRIX_APPLICABILITY_SCHEMA = "aos.qualification.native-operation-matrix-applicability"

def _applicable_specification_cells(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Returns the authoritative applicability partition after reference checks."""

    if spec.get("schema") != "aos.qualification.native-operation-matrix-spec":
        raise RuntimeError("native matrix specification has an unsupported schema")
    required_operations(spec)
    cells = spec.get("cells")
    applicability = spec.get("applicability")
    if not isinstance(cells, list) or not isinstance(applicability, dict):
        raise RuntimeError("matrix applicability is missing")
    if set(applicability) != {"schema", "applicable_cell_ids", "inapplicable_cells"}:
        raise RuntimeError("matrix applicability has unknown fields")
    if applicability.get("schema") != MATRIX_APPLICABILITY_SCHEMA:
        raise RuntimeError("matrix applicability has an unsupported schema")

    cell_by_id = {cell.get("id"): cell for cell in cells if isinstance(cell, dict)}
    applicable_ids = applicability.get("applicable_cell_ids")
    inapplicable = applicability.get("inapplicable_cells")
    if (
        len(cell_by_id) != len(cells)
        or not isinstance(applicable_ids, list)
        or applicable_ids != sorted(set(applicable_ids))
        or not isinstance(inapplicable, list)
    ):
        raise RuntimeError("matrix cell identities or applicability order are malformed")
    inapplicable_ids = [entry.get("cell_id") for entry in inapplicable if isinstance(entry, dict)]
    if (
        len(inapplicable_ids) != len(inapplicable)
        or inapplicable_ids != sorted(set(inapplicable_ids))
        or set(applicable_ids).intersection(inapplicable_ids)
        or set(applicable_ids).union(inapplicable_ids) != set(cell_by_id)
        or any(
            set(entry) != {"cell_id", "reason"}
            or entry.get("reason")
            not in {
                "required-resource-lifetime-unavailable",
                "missing-authenticated-state-format",
                "unsupported-scenario-action",
            }
            for entry in inapplicable
        )
    ):
        raise RuntimeError("matrix applicability is not an exact cell partition")

    exclusions = {entry["cell_id"]: entry["reason"] for entry in inapplicable}
    for cell_id, cell in cell_by_id.items():
        predicate = cell.get("applicability")
        if not isinstance(predicate, dict) or set(predicate) != {"required_actions", "required_resource_lifetimes", "requires_state_format"}:
            raise RuntimeError("native scenario lacks its closed applicability predicate")
        actions = predicate["required_actions"]
        if (not isinstance(actions, list) or any(action not in {"apply", "remove"} for action in actions)
                or actions != sorted(set(actions))):
            raise RuntimeError("native scenario action applicability is malformed")
        supported = not actions or cell["action"] in actions
        if (not supported and exclusions.get(cell_id) != "unsupported-scenario-action") or (supported and exclusions.get(cell_id) == "unsupported-scenario-action"):
            raise RuntimeError("native scenario action partition contradicts its authored predicate")

    return [cell_by_id[cell_id] for cell_id in applicable_ids]



def _qualification_routes(subject: Any, spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Requires the independently evaluated candidate operation surface."""
    if (not isinstance(subject, dict)
            or set(subject) != {"schema", "matrixSpecDigest", "operations"}
            or subject.get("schema") != QUALIFICATION_SUBJECT_SCHEMA
            or subject.get("matrixSpecDigest") != sha256(spec)
            or subject.get("operations") != spec.get("surface", {}).get("adapters")):
        raise RuntimeError("candidate native operation surface differs from its matrix")
    return subject["operations"]


def build_cells(
    spec: dict[str, Any], submissions: dict[str, Any],
    expected_qualified_cells: list[str], cohort_subjects: dict[str, dict[str, Any]],
    cohort_evidence: dict[str, bytes], subject_digest: str, environment_digest: str,
    qualification_subject: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Validates retained flights before emitting any positive matrix claims."""
    if not _matches(DIGEST, subject_digest) or not _matches(DIGEST, environment_digest):
        raise RuntimeError("native qualification subject or environment digest is malformed")
    operations = _qualification_routes(qualification_subject, spec)
    cells = _applicable_specification_cells(spec)
    expected = {cell["id"] for cell in cells}
    if (len(expected_qualified_cells) != len(set(expected_qualified_cells))
            or set(expected_qualified_cells) != expected
            or any(set(values) != expected for values in (submissions, cohort_subjects, cohort_evidence))):
        raise RuntimeError("native flights differ from the exact applicable matrix partition")

    observations = []
    seen_flights = set()
    seen_probes = set()
    count = 0
    for cell in cells:
        subject = cohort_subjects[cell["id"]]
        evidence = cohort_evidence[cell["id"]]
        flight = runtime_evidence.validate_flight(cell, subject, evidence, spec, operations)
        evidence_digest = sha256(flight)
        if evidence_digest in seen_flights:
            raise RuntimeError("native matrix cells replay a retained flight")
        seen_flights.add(evidence_digest)
        submitted = submissions[cell["id"]]
        if submitted != {"disposition": "checked", "evidenceDigest": evidence_digest}:
            raise RuntimeError("native flight submission differs from its exact evidence")
        bound_subject = _bound_cohort_subject(cell, subject)
        postconditions = {}
        probes = {}
        for name in cell["postconditions"]:
            facts = runtime_evidence.probe_facts(name, flight)
            if len(canonical(facts)) > 64 * 1024:
                raise RuntimeError("native semantic probe exceeds the retained evidence limit")
            observation_digest = sha256(facts)
            if observation_digest in seen_probes:
                raise RuntimeError("native postconditions replay an observation")
            seen_probes.add(observation_digest)
            postconditions[name] = {"passed": True, "detail": "Checked native journal and independent substrate facts"}
            probes[name] = {
                "schema_version": PROBE_SCHEMA, "kind": _postcondition_kind(cell, name),
                "cell_id": cell["id"], "cell_digest": sha256(cell),
                "disposition": _expected_disposition(cell, subject),
                "subject_digest": subject_digest, "cohort_subject_digest": sha256(bound_subject),
                "observation_digest": observation_digest, "observations": facts,
            }
            count += 1
        observations.append({
            "id": cell["id"], "cell_digest": sha256(cell),
            "environment_digest": environment_digest, "cohort_subject": bound_subject,
            "postconditions": postconditions, "probes": probes,
        })
    return observations, count


def validate_qualification_spec(spec: Any) -> list[dict[str, Any]]:
    """Checks authored cohort custody and semantic coverage without a graph union."""
    if (not isinstance(spec, dict) or set(spec) != {"schema", "required_operations", "cohorts"}
            or spec.get("schema") != "aos.qualification.native-operation-spec"):
        raise RuntimeError("unsupported native operation qualification specification")
    required = required_operations(spec)
    cohorts = spec["cohorts"]
    if not isinstance(cohorts, list) or not 1 <= len(cohorts) <= 4096:
        raise RuntimeError("native operation specification lacks bounded closed cohorts")
    selected = set()
    ids = []
    for cohort in cohorts:
        if (not isinstance(cohort, dict) or set(cohort) != {"id", "matrix_spec", "selected_evaluation", "adoption_evaluation"}
                or not isinstance(cohort["id"], str) or not cohort["id"]):
            raise RuntimeError("native cohort declaration is malformed")
        ids.append(cohort["id"])
        matrix = cohort["matrix_spec"]
        selected.update((operation["ability"], operation["name"]) for operation in required_operations(matrix))
        _applicable_specification_cells(matrix)
        for evaluation in (cohort["selected_evaluation"], cohort["adoption_evaluation"]):
            if (not isinstance(evaluation, dict) or set(evaluation) != {"role", "locator", "scenario_sources"}
                    or evaluation["role"] not in {"candidate-baseline", "scenario"}
                    or not _immutable_locator(evaluation["locator"])
                    or not isinstance(evaluation["scenario_sources"], list)
                    or len(evaluation["scenario_sources"]) > 4096
                    or not all(_immutable_locator(source) for source in evaluation["scenario_sources"])
                    or len(evaluation["scenario_sources"]) != len(set(evaluation["scenario_sources"]))
                    or (evaluation["role"] == "candidate-baseline" and evaluation["scenario_sources"])
                    or (evaluation["role"] == "scenario" and not evaluation["scenario_sources"])):
                raise RuntimeError("native cohort evaluation custody is malformed")
    if ids != sorted(set(ids)):
        raise RuntimeError("native operation cohorts are duplicated or unordered")
    if any((operation["ability"], operation["name"]) not in selected for operation in required):
        raise RuntimeError("required semantic operation lacks an independently selected cohort")
    return cohorts


def _immutable_locator(value: Any) -> bool:
    return (isinstance(value, str) and len(value) <= 4096 and value.startswith("/nix/store/")
            and len(value) > len("/nix/store/") and "\0" not in value
            and not any(component in {".", ".."} for component in value.split("/")))


def build_cohorts(spec: dict[str, Any], executions: dict[str, dict[str, Any]],
                  subject_digest: str, environment_digest: str) -> tuple[list[dict[str, Any]], int]:
    """Validates full per-cohort evidence with separately authenticated candidate custody.

    The caller authenticates each candidate against the case-selected source
    artifacts before supplying its exact digest and reconstructed subject.
    A digest received from a flight is never substituted for that admission.
    """
    cohorts = validate_qualification_spec(spec)
    if set(executions) != {cohort["id"] for cohort in cohorts}:
        raise RuntimeError("native executions differ from the complete authored cohort population")
    observations = []
    count = 0
    for cohort in cohorts:
        execution = executions[cohort["id"]]
        if (set(execution) != {"submissions", "subjects", "evidence", "qualification_subject", "candidate_digest", "adoption_digest"}
                or not _matches(DIGEST, execution["candidate_digest"])
                or not _matches(DIGEST, execution["adoption_digest"])):
            raise RuntimeError("native cohort lacks its authenticated candidate commitment")
        matrix = cohort["matrix_spec"]
        cells, checked_count = build_cells(
            matrix, execution["submissions"], matrix["applicability"]["applicable_cell_ids"],
            execution["subjects"], execution["evidence"], subject_digest, environment_digest,
            qualification_subject=execution["qualification_subject"],
        )
        observations.append({
            "id": cohort["id"], "matrix_spec": matrix,
            "selected_evaluation": cohort["selected_evaluation"],
            "adoption_evaluation": cohort["adoption_evaluation"],
            "adoption_digest": execution["adoption_digest"],
            "spec_digest": sha256(matrix), "candidate_digest": execution["candidate_digest"],
            "cells": cells,
        })
        count += checked_count
    return observations, count
