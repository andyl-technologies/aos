"""Routes native qualification evidence to provider-owned validators.

This module owns only the normalized boundary used by the matrix aggregator.
Provider modules recognize their own authenticated subject schemas and parse
provider-specific plans and live observations.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Protocol

import native_adapter_operation_evidence
import native_adapter_provider_state_evidence
import reference_evidence
import rollout_evidence


VALIDATION_RESULT_SCHEMA = "aos.qualification.provider-evidence-validation/v1"
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
        routes: list[dict[str, Any]],
    ) -> None: ...

    @staticmethod
    def validate_probe(
        postcondition: str,
        observations: dict[str, Any],
        subject: dict[str, Any],
        cell: dict[str, Any],
        matrix_spec: dict[str, Any] | None,
    ) -> None: ...


class SpecializedCellValidator(Protocol):
    """Describes a validator for one provider-specific audit cell."""

    @staticmethod
    def validate_provider_negative_cell(
        cell: dict[str, Any],
        record: dict[str, Any],
        subject_digest: str,
        probe_digests: set[str],
        spec: dict[str, Any],
        policy: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None: ...


class SnapshotValidator(Protocol):
    """Describes a validator for one provider-owned live snapshot."""

    @staticmethod
    def validate_cancellation_snapshot(
        expected_kind: str, value: Any
    ) -> bool | None: ...


class EvidenceValidatorRegistry:
    """Routes evidence only when one declared validator accepts its subject."""

    def __init__(
        self,
        *,
        subjects: Iterable[SubjectValidator],
        specialized_cells: Iterable[SpecializedCellValidator] = (),
        snapshots: Iterable[SnapshotValidator] = (),
    ) -> None:
        self._subjects = tuple(subjects)
        self._specialized_cells = tuple(specialized_cells)
        self._snapshots = tuple(snapshots)

    def validate_subject(
        self,
        cell: dict[str, Any],
        subject: Any,
        evidence_bytes: Any,
        matrix_spec: dict[str, Any] | None,
        routes: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Validates a subject through its one accepting implementation."""

        validator = self._subject_validator(subject)
        validator.validate_subject(cell, subject, evidence_bytes, matrix_spec, routes)
        return _validation_result(cell, "subject")

    def validate_probe(
        self,
        postcondition: str,
        observations: dict[str, Any],
        cohort_subject: dict[str, Any],
        cell: dict[str, Any],
        matrix_spec: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Validates observations through the subject's implementation."""

        validator = self._subject_validator(cohort_subject)
        validator.validate_probe(
            postcondition, observations, cohort_subject, cell, matrix_spec
        )
        return _validation_result(cell, "postcondition", postcondition)

    def validate_specialized_cell(
        self,
        cell: dict[str, Any],
        record: dict[str, Any],
        subject_digest: str,
        probe_digests: set[str],
        spec: dict[str, Any],
        policy: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
        """Validates a cell through at most one specialized implementation."""

        matches = []
        for validator in self._specialized_cells:
            result = validator.validate_provider_negative_cell(
                cell, record, subject_digest, probe_digests, spec, policy
            )
            if result is not None:
                matches.append(result)
        if len(matches) > 1:
            raise RuntimeError("provider-negative record has ambiguous validators")
        return matches[0] if matches else None

    def valid_snapshot(self, expected_kind: str, value: Any) -> bool:
        """Validates a snapshot through at most one specialized implementation."""

        matches = []
        for validator in self._snapshots:
            result = validator.validate_cancellation_snapshot(expected_kind, value)
            if result is not None:
                matches.append(result)
        if len(matches) > 1:
            return False
        if matches:
            return matches[0]
        return isinstance(value, dict) and value.get("kind") == expected_kind

    def _subject_validator(self, subject: Any) -> SubjectValidator:
        matches = [
            validator
            for validator in self._subjects
            if validator.accepts_subject(subject)
        ]
        if len(matches) != 1:
            raise RuntimeError("provider subject has no unique evidence validator")
        return matches[0]


DEFAULT_REGISTRY = EvidenceValidatorRegistry(
    subjects=(
        native_adapter_operation_evidence,
        native_adapter_provider_state_evidence,
        reference_evidence,
    ),
    specialized_cells=(rollout_evidence,),
    snapshots=(rollout_evidence,),
)


def validate_subject(
    cell: dict[str, Any],
    subject: Any,
    evidence_bytes: Any,
    matrix_spec: dict[str, Any] | None,
    routes: list[dict[str, Any]],
) -> dict[str, Any]:
    """Validates a provider subject and returns its normalized result."""

    return DEFAULT_REGISTRY.validate_subject(
        cell, subject, evidence_bytes, matrix_spec, routes
    )


def validate_probe(
    postcondition: str,
    observations: dict[str, Any],
    cohort_subject: dict[str, Any],
    cell: dict[str, Any],
    matrix_spec: dict[str, Any] | None,
) -> dict[str, Any]:
    """Validates provider observations and returns their normalized result."""

    return DEFAULT_REGISTRY.validate_probe(
        postcondition, observations, cohort_subject, cell, matrix_spec
    )


def validate_special_provider_negative_cell(
    cell: dict[str, Any],
    record: dict[str, Any],
    subject_digest: str,
    probe_digests: set[str],
    spec: dict[str, Any],
    policy: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Delegates specialized provider records without inspecting their payload."""

    return DEFAULT_REGISTRY.validate_specialized_cell(
        cell, record, subject_digest, probe_digests, spec, policy
    )


def valid_cancellation_snapshot(expected_kind: str, value: Any) -> bool:
    """Validates a live snapshot through its provider-owned representation."""

    return DEFAULT_REGISTRY.valid_snapshot(expected_kind, value)


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
