"""Routes native qualification evidence to provider-owned validators.

This module owns only the normalized boundary used by the matrix aggregator.
Provider modules recognize their own authenticated subject schemas and parse
provider-specific plans and live observations.
"""

from __future__ import annotations

from typing import Any, Protocol

import postgresql_evidence
import reference_evidence
import rollout_evidence


VALIDATION_RESULT_SCHEMA = "aos.qualification.provider-evidence-validation/v1"
SUBJECT_VALIDATORS = (postgresql_evidence, reference_evidence)
SPECIALIZED_CELL_VALIDATORS = (rollout_evidence,)
SPECIALIZED_SNAPSHOT_VALIDATORS = (rollout_evidence,)


class SubjectValidator(Protocol):
    """Describes the closed interface implemented by provider validators."""

    @staticmethod
    def accepts_subject(subject: Any) -> bool: ...

    @staticmethod
    def validate_subject(
        cell: dict[str, Any],
        subject: Any,
        evidence_bytes: Any,
        matrix_spec: dict[str, Any] | None,
    ) -> None: ...

    @staticmethod
    def validate_probe(
        postcondition: str,
        observations: dict[str, Any],
        subject: dict[str, Any],
        cell: dict[str, Any],
    ) -> None: ...


def _subject_validator(subject: Any) -> SubjectValidator:
    matches = [validator for validator in SUBJECT_VALIDATORS if validator.accepts_subject(subject)]
    if len(matches) != 1:
        raise RuntimeError("provider subject has no unique evidence validator")
    return matches[0]


def validate_subject(
    cell: dict[str, Any],
    subject: Any,
    evidence_bytes: Any,
    matrix_spec: dict[str, Any] | None,
) -> dict[str, Any]:
    """Validates a provider subject and returns its normalized result."""

    validator = _subject_validator(subject)
    validator.validate_subject(cell, subject, evidence_bytes, matrix_spec)
    return _validation_result(cell, "subject")


def validate_probe(
    postcondition: str,
    observations: dict[str, Any],
    cohort_subject: dict[str, Any],
    cell: dict[str, Any],
) -> dict[str, Any]:
    """Validates provider observations and returns their normalized result."""

    validator = _subject_validator(cohort_subject)
    validator.validate_probe(postcondition, observations, cohort_subject, cell)
    return _validation_result(cell, "postcondition", postcondition)


def validate_special_provider_negative_cell(
    cell: dict[str, Any],
    record: dict[str, Any],
    subject_digest: str,
    probe_digests: set[str],
    spec: dict[str, Any],
    policy: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Delegates specialized provider records without inspecting their payload."""

    matches = []
    for validator in SPECIALIZED_CELL_VALIDATORS:
        result = validator.validate_provider_negative_cell(
            cell, record, subject_digest, probe_digests, spec, policy
        )
        if result is not None:
            matches.append(result)
    if len(matches) > 1:
        raise RuntimeError("provider-negative record has ambiguous validators")
    return matches[0] if matches else None


def valid_cancellation_snapshot(expected_kind: str, value: Any) -> bool:
    """Validates a live snapshot through its provider-owned representation."""

    matches = []
    for validator in SPECIALIZED_SNAPSHOT_VALIDATORS:
        result = validator.validate_cancellation_snapshot(expected_kind, value)
        if result is not None:
            matches.append(result)
    if len(matches) > 1:
        return False
    if matches:
        return matches[0]
    return isinstance(value, dict) and value.get("kind") == expected_kind


def _validation_result(
    cell: dict[str, Any], kind: str, postcondition: str | None = None
) -> dict[str, Any]:
    result = {
        "schema": VALIDATION_RESULT_SCHEMA,
        "cell-id": cell["id"],
        "kind": kind,
    }
    if postcondition is not None:
        result["postcondition"] = postcondition
    return result
